package packet

import (
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

type AuroraPacket struct {
	RouteInstanceID uint64
	HopLayer        uint8
	Direction       uint8
	KeyPhase        uint8
	PacketNumber    uint64
	Ciphertext      []byte
	AuthTag         []byte
}

func (p AuroraPacket) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.RouteInstanceID)
	e.WriteUint8(p.HopLayer)
	e.WriteUint8(p.Direction)
	e.WriteUint8(p.KeyPhase)
	e.WriteVarint(p.PacketNumber)
	e.WriteOpaque24(p.Ciphertext)
	e.WriteOpaqueFixed(p.AuthTag, 16)
}

func DecodeAuroraPacket(encoded []byte) (AuroraPacket, error) {
	return decodeAuroraPacket(encoded, false)
}

// DecodeAuroraPacketView returns ciphertext and tag slices borrowed from encoded.
func DecodeAuroraPacketView(encoded []byte) (AuroraPacket, error) {
	return decodeAuroraPacket(encoded, true)
}

func decodeAuroraPacket(encoded []byte, borrowPayload bool) (AuroraPacket, error) {
	r := wire.NewReader(encoded)
	p := AuroraPacket{
		RouteInstanceID: r.ReadVarint(),
		HopLayer:        r.ReadUint8(),
		Direction:       r.ReadUint8(),
		KeyPhase:        r.ReadUint8(),
		PacketNumber:    r.ReadVarint(),
	}
	if borrowPayload {
		p.Ciphertext = r.ReadOpaque24View()
		p.AuthTag = r.ReadOpaqueFixedView(16)
	} else {
		p.Ciphertext = r.ReadOpaque24()
		p.AuthTag = r.ReadOpaqueFixed(16)
	}
	if r.Err() != nil {
		return AuroraPacket{}, r.Err()
	}
	if !r.EOF() {
		return AuroraPacket{}, fmt.Errorf("packet: trailing packet bytes")
	}
	return p, nil
}

type Protector struct {
	Suite           uint64
	RouteInstanceID uint64
	HopLayer        uint8
	Direction       uint8
	KeyPhase        uint8
	Key             []byte
	StaticIV        []byte
	NextPacket      uint64
}

func (p *Protector) Seal(block protocol.FrameBlock) (AuroraPacket, error) {
	if p.Direction > 1 {
		return AuroraPacket{}, fmt.Errorf("packet: reserved packet direction 0x%x", p.Direction)
	}
	if err := protocol.ValidateFrameBlockForDirection(block, p.Direction); err != nil {
		return AuroraPacket{}, err
	}
	plaintext, err := protocol.Encode(block)
	if err != nil {
		return AuroraPacket{}, err
	}
	defer destroyBytes(plaintext)
	packetNumber := p.NextPacket
	aad, err := auroracrypto.PacketAD(p.Suite, p.RouteInstanceID, p.HopLayer, p.Direction, p.KeyPhase, packetNumber)
	if err != nil {
		return AuroraPacket{}, err
	}
	nonce, err := auroracrypto.XORNonce96(p.StaticIV, packetNumber)
	if err != nil {
		return AuroraPacket{}, err
	}
	sealed, err := auroracrypto.SealForSuite(p.Suite, p.Key, nonce, aad, plaintext)
	if err != nil {
		return AuroraPacket{}, err
	}
	if len(sealed) < 16 {
		destroyBytes(sealed)
		return AuroraPacket{}, fmt.Errorf("packet: sealed payload too short")
	}
	p.NextPacket++
	ciphertextLength := len(sealed) - 16
	return AuroraPacket{
		RouteInstanceID: p.RouteInstanceID,
		HopLayer:        p.HopLayer,
		Direction:       p.Direction,
		KeyPhase:        p.KeyPhase,
		PacketNumber:    packetNumber,
		Ciphertext:      sealed[:ciphertextLength:ciphertextLength],
		AuthTag:         sealed[ciphertextLength:],
	}, nil
}

func (p Protector) Open(pkt AuroraPacket) (protocol.FrameBlock, error) {
	if pkt.RouteInstanceID != p.RouteInstanceID || pkt.HopLayer != p.HopLayer || pkt.Direction != p.Direction || pkt.KeyPhase != p.KeyPhase {
		return protocol.FrameBlock{}, fmt.Errorf("packet: packet metadata does not match protector")
	}
	aad, err := auroracrypto.PacketAD(p.Suite, pkt.RouteInstanceID, pkt.HopLayer, pkt.Direction, pkt.KeyPhase, pkt.PacketNumber)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	nonce, err := auroracrypto.XORNonce96(p.StaticIV, pkt.PacketNumber)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	sealed := append(append([]byte(nil), pkt.Ciphertext...), pkt.AuthTag...)
	defer destroyBytes(sealed)
	plaintext, err := auroracrypto.OpenForSuite(p.Suite, p.Key, nonce, aad, sealed)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	defer destroyBytes(plaintext)
	block, err := protocol.DecodeFrameBlock(plaintext)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	if err := protocol.ValidateFrameBlockForDirection(block, pkt.Direction); err != nil {
		destroyFrameBlock(&block)
		return protocol.FrameBlock{}, err
	}
	return block, nil
}
