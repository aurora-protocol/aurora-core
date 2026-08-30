package server

import (
	"encoding/binary"
	"fmt"
)

const (
	DefaultPacketExchangePath = "/assets/app.bin"

	maxPacketBatchPackets = 64
	maxPacketBytes        = 65535
	maxPacketBatchBytes   = 2 + maxPacketBatchPackets*(2+4+maxPacketBytes)
	packetFamilyIPv4      = 2
	packetFamilyIPv6      = 30
)

type PacketBatch struct {
	Packets         [][]byte
	ProtocolNumbers []uint16
}

// PacketExchanger synchronously consumes the supplied packet batch and returns caller-owned packets.
type PacketExchanger interface {
	ExchangePacketBatch(PacketBatch) (PacketBatch, error)
}

type LoopbackPacketExchanger struct{}

func (LoopbackPacketExchanger) ExchangePacketBatch(batch PacketBatch) (PacketBatch, error) {
	if err := validatePacketBatch(batch); err != nil {
		return PacketBatch{}, err
	}
	return clonePacketBatch(batch), nil
}

func EncodePacketBatch(batch PacketBatch) ([]byte, error) {
	if err := validatePacketBatch(batch); err != nil {
		return nil, err
	}
	if len(batch.Packets) > maxPacketBatchPackets {
		return nil, fmt.Errorf("server: packet batch has %d packets, max %d", len(batch.Packets), maxPacketBatchPackets)
	}
	size := 2
	for _, packet := range batch.Packets {
		if len(packet) > maxPacketBytes {
			return nil, fmt.Errorf("server: packet length %d exceeds %d", len(packet), maxPacketBytes)
		}
		size += 2 + 4 + len(packet)
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint16(out[:2], uint16(len(batch.Packets)))
	offset := 2
	for i, packet := range batch.Packets {
		binary.BigEndian.PutUint16(out[offset:offset+2], batch.ProtocolNumbers[i])
		offset += 2
		binary.BigEndian.PutUint32(out[offset:offset+4], uint32(len(packet)))
		offset += 4
		copy(out[offset:offset+len(packet)], packet)
		offset += len(packet)
	}
	return out, nil
}

func DecodePacketBatch(data []byte) (PacketBatch, error) {
	if len(data) < 2 {
		return PacketBatch{}, fmt.Errorf("server: packet batch missing count")
	}
	count := int(binary.BigEndian.Uint16(data[:2]))
	if count > maxPacketBatchPackets {
		return PacketBatch{}, fmt.Errorf("server: packet batch has %d packets, max %d", count, maxPacketBatchPackets)
	}
	if err := validatePacketBatchEncoding(data, count); err != nil {
		return PacketBatch{}, err
	}
	batch := PacketBatch{
		Packets:         make([][]byte, 0, count),
		ProtocolNumbers: make([]uint16, 0, count),
	}
	offset := 2
	for i := 0; i < count; i++ {
		protocolNumber := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		packetLength := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		batch.ProtocolNumbers = append(batch.ProtocolNumbers, protocolNumber)
		batch.Packets = append(batch.Packets, append([]byte(nil), data[offset:offset+packetLength]...))
		offset += packetLength
	}
	return batch, nil
}

func validatePacketBatchEncoding(data []byte, count int) error {
	offset := 2
	for i := 0; i < count; i++ {
		if len(data)-offset < 6 {
			return fmt.Errorf("server: packet entry %d is truncated", i)
		}
		protocolNumber := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		packetLength, err := validatePacketBatchPacketLength(binary.BigEndian.Uint32(data[offset : offset+4]))
		if err != nil {
			return err
		}
		offset += 4
		if packetLength == 0 {
			return fmt.Errorf("server: packet entry %d is empty", i)
		}
		if len(data)-offset < packetLength {
			return fmt.Errorf("server: packet entry %d payload is truncated", i)
		}
		packetFamily := packetProtocolNumber(data[offset : offset+packetLength])
		if packetFamily == 0 {
			return fmt.Errorf("server: packet entry %d is not IPv4 or IPv6", i)
		}
		if protocolNumber != packetFamily {
			return fmt.Errorf("server: packet entry %d protocol number %d does not match packet family %d", i, protocolNumber, packetFamily)
		}
		offset += packetLength
	}
	if offset != len(data) {
		return fmt.Errorf("server: trailing packet batch bytes")
	}
	return nil
}

func validatePacketBatchPacketLength(length uint32) (int, error) {
	if length > maxPacketBytes {
		return 0, fmt.Errorf("server: packet length %d exceeds %d", length, maxPacketBytes)
	}
	return int(length), nil
}

func validatePacketBatch(batch PacketBatch) error {
	if len(batch.Packets) != len(batch.ProtocolNumbers) {
		return fmt.Errorf("server: packet and protocol count mismatch")
	}
	if len(batch.Packets) > maxPacketBatchPackets {
		return fmt.Errorf("server: packet batch has %d packets, max %d", len(batch.Packets), maxPacketBatchPackets)
	}
	for i, packet := range batch.Packets {
		if len(packet) == 0 {
			return fmt.Errorf("server: packet entry %d is empty", i)
		}
		if len(packet) > maxPacketBytes {
			return fmt.Errorf("server: packet length %d exceeds %d", len(packet), maxPacketBytes)
		}
		protocolNumber := packetProtocolNumber(packet)
		if protocolNumber == 0 {
			return fmt.Errorf("server: packet entry %d is not IPv4 or IPv6", i)
		}
		if batch.ProtocolNumbers[i] != protocolNumber {
			return fmt.Errorf("server: packet entry %d protocol number %d does not match packet family %d", i, batch.ProtocolNumbers[i], protocolNumber)
		}
	}
	return nil
}

func clonePacketBatch(batch PacketBatch) PacketBatch {
	out := PacketBatch{
		Packets:         make([][]byte, len(batch.Packets)),
		ProtocolNumbers: append([]uint16(nil), batch.ProtocolNumbers...),
	}
	for i, packet := range batch.Packets {
		out.Packets[i] = append([]byte(nil), packet...)
	}
	return out
}

func zeroPacketBatch(batch *PacketBatch) {
	if batch == nil {
		return
	}
	for index := range batch.Packets {
		zeroCarrierPayload(batch.Packets[index])
		batch.Packets[index] = nil
	}
	batch.Packets = nil
	batch.ProtocolNumbers = nil
}
