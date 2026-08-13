package server

import (
	"fmt"
	"io"
	"sync"
)

const (
	defaultDevicePacketMTU          = 1280
	defaultDevicePacketQueuePackets = 64
)

type DevicePacketExchangerOptions struct {
	MTU          int
	QueuePackets int
}

type DevicePacketExchanger struct {
	device   io.ReadWriteCloser
	mtu      int
	outbound chan []byte
	done     chan struct{}
	readDone chan struct{}

	closeOnce sync.Once
	closeErr  error
	writeMu   sync.Mutex
}

func NewDevicePacketExchanger(device io.ReadWriteCloser, opts DevicePacketExchangerOptions) (*DevicePacketExchanger, error) {
	if device == nil {
		return nil, fmt.Errorf("server: packet device is required")
	}
	mtu := opts.MTU
	if mtu == 0 {
		mtu = defaultDevicePacketMTU
	}
	if mtu < 1 || mtu > maxPacketBytes {
		return nil, fmt.Errorf("server: packet device MTU %d outside supported range", mtu)
	}
	queuePackets := opts.QueuePackets
	if queuePackets == 0 {
		queuePackets = defaultDevicePacketQueuePackets
	}
	if queuePackets < 1 || queuePackets > maxPacketBatchPackets {
		return nil, fmt.Errorf("server: packet device queue size %d outside supported range", queuePackets)
	}

	exchanger := &DevicePacketExchanger{
		device:   device,
		mtu:      mtu,
		outbound: make(chan []byte, queuePackets),
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
	}
	go exchanger.readDevice()
	return exchanger, nil
}

func (e *DevicePacketExchanger) ExchangePacketBatch(batch PacketBatch) (PacketBatch, error) {
	if e == nil {
		return PacketBatch{}, fmt.Errorf("server: packet exchanger is nil")
	}
	select {
	case <-e.done:
		return PacketBatch{}, fmt.Errorf("server: packet exchanger is closed")
	default:
	}
	if err := validatePacketBatch(batch); err != nil {
		return PacketBatch{}, err
	}

	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	select {
	case <-e.done:
		return PacketBatch{}, fmt.Errorf("server: packet exchanger is closed")
	default:
	}
	for _, packet := range batch.Packets {
		if len(packet) > e.mtu {
			return PacketBatch{}, fmt.Errorf("server: packet length %d exceeds device MTU %d", len(packet), e.mtu)
		}
		if err := writeFullPacket(e.device, packet); err != nil {
			return PacketBatch{}, fmt.Errorf("server: write packet device: %w", err)
		}
	}

	return e.drainOutbound(), nil
}

func (e *DevicePacketExchanger) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		close(e.done)
		e.closeErr = e.device.Close()
	})
	return e.closeErr
}

func (e *DevicePacketExchanger) readDevice() {
	defer close(e.readDone)
	buffer := make([]byte, e.mtu)
	for {
		n, err := e.device.Read(buffer)
		if n > 0 {
			e.queueOutbound(buffer[:n])
		}
		if err != nil {
			return
		}
		select {
		case <-e.done:
			return
		default:
		}
	}
}

func (e *DevicePacketExchanger) queueOutbound(packet []byte) {
	copied := append([]byte(nil), packet...)
	select {
	case e.outbound <- copied:
		return
	case <-e.done:
		return
	default:
	}
	select {
	case <-e.outbound:
	default:
	}
	select {
	case e.outbound <- copied:
	case <-e.done:
	default:
	}
}

func (e *DevicePacketExchanger) drainOutbound() PacketBatch {
	outbound := PacketBatch{
		Packets:         make([][]byte, 0),
		ProtocolNumbers: make([]uint16, 0),
	}
	for len(outbound.Packets) < maxPacketBatchPackets {
		select {
		case packet := <-e.outbound:
			outbound.Packets = append(outbound.Packets, append([]byte(nil), packet...))
			outbound.ProtocolNumbers = append(outbound.ProtocolNumbers, packetProtocolNumber(packet))
		default:
			return outbound
		}
	}
	return outbound
}

func writeFullPacket(w io.Writer, packet []byte) error {
	for len(packet) > 0 {
		n, err := w.Write(packet)
		if n > 0 {
			packet = packet[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func packetProtocolNumber(packet []byte) uint16 {
	if len(packet) == 0 {
		return 0
	}
	switch packet[0] >> 4 {
	case 4:
		return 2
	case 6:
		return 30
	default:
		return 0
	}
}

var _ PacketExchanger = (*DevicePacketExchanger)(nil)
