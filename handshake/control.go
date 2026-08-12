package handshake

import (
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	ControlDirectionClientToHop uint8 = 0x00
	ControlDirectionHopToClient uint8 = 0x01
)

type ControlCapsuleContext struct {
	SelectedVersion                 uint64
	SelectedSuite                   uint64
	RouteInstanceID                 uint64
	HopIndex                        uint8
	HandshakeBindingContext         []byte
	PreludeTranscriptHashForThisHop []byte
	ClientHSKey                     []byte
	ClientHSIV                      []byte
	ServerHSKey                     []byte
	ServerHSIV                      []byte
}

func SealCoverCapsule1(ctx ControlCapsuleContext, plain protocol.CoverCapsule1Plain) ([]byte, error) {
	plain.MsgType = registry.MsgCoverCapsule1
	plain.RouteInstanceID = ctx.RouteInstanceID
	encoded, err := protocol.Encode(plain)
	if err != nil {
		return nil, err
	}
	return sealControl(ctx, registry.MsgCoverCapsule1, ControlDirectionClientToHop, ctx.ClientHSKey, ctx.ClientHSIV, encoded)
}

func OpenCoverCapsule1(ctx ControlCapsuleContext, sealed []byte) (protocol.CoverCapsule1Plain, error) {
	plaintext, err := openControl(ctx, registry.MsgCoverCapsule1, ControlDirectionClientToHop, ctx.ClientHSKey, ctx.ClientHSIV, sealed)
	if err != nil {
		return protocol.CoverCapsule1Plain{}, failure.NewError(failure.BadAEADTag, "handshake: CoverCapsule1 AEAD open failed: %w", err)
	}
	defer zeroBindingBytes(plaintext)
	plain, err := decodeCoverCapsule1Plain(plaintext)
	if err != nil {
		return protocol.CoverCapsule1Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: malformed CoverCapsule1 plaintext: %w", err)
	}
	if plain.MsgType != registry.MsgCoverCapsule1 || plain.RouteInstanceID != ctx.RouteInstanceID {
		return protocol.CoverCapsule1Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: CoverCapsule1 plaintext header mismatch")
	}
	return plain, nil
}

func SealCoverCapsule2(ctx ControlCapsuleContext, plain protocol.CoverCapsule2Plain) ([]byte, error) {
	plain.MsgType = registry.MsgCoverCapsule2
	plain.RouteInstanceID = ctx.RouteInstanceID
	encoded, err := protocol.Encode(plain)
	if err != nil {
		return nil, err
	}
	return sealControl(ctx, registry.MsgCoverCapsule2, ControlDirectionHopToClient, ctx.ServerHSKey, ctx.ServerHSIV, encoded)
}

func OpenCoverCapsule2(ctx ControlCapsuleContext, sealed []byte) (protocol.CoverCapsule2Plain, error) {
	plaintext, err := openControl(ctx, registry.MsgCoverCapsule2, ControlDirectionHopToClient, ctx.ServerHSKey, ctx.ServerHSIV, sealed)
	if err != nil {
		return protocol.CoverCapsule2Plain{}, failure.NewError(failure.BadAEADTag, "handshake: CoverCapsule2 AEAD open failed: %w", err)
	}
	defer zeroBindingBytes(plaintext)
	plain, err := decodeCoverCapsule2Plain(plaintext)
	if err != nil {
		return protocol.CoverCapsule2Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: malformed CoverCapsule2 plaintext: %w", err)
	}
	if plain.MsgType != registry.MsgCoverCapsule2 || plain.RouteInstanceID != ctx.RouteInstanceID {
		return protocol.CoverCapsule2Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: CoverCapsule2 plaintext header mismatch")
	}
	return plain, nil
}

func SealRouteCapsule1(ctx ControlCapsuleContext, plain protocol.RouteCapsule1Plain) ([]byte, error) {
	plain.MsgType = registry.MsgRouteCapsule1
	plain.RouteInstanceID = ctx.RouteInstanceID
	plain.HopIndex = ctx.HopIndex
	encoded, err := protocol.Encode(plain)
	if err != nil {
		return nil, err
	}
	return sealControl(ctx, registry.MsgRouteCapsule1, ControlDirectionClientToHop, ctx.ClientHSKey, ctx.ClientHSIV, encoded)
}

func OpenRouteCapsule1(ctx ControlCapsuleContext, sealed []byte) (protocol.RouteCapsule1Plain, error) {
	plaintext, err := openControl(ctx, registry.MsgRouteCapsule1, ControlDirectionClientToHop, ctx.ClientHSKey, ctx.ClientHSIV, sealed)
	if err != nil {
		return protocol.RouteCapsule1Plain{}, failure.NewError(failure.BadAEADTag, "handshake: RouteCapsule1 AEAD open failed: %w", err)
	}
	defer zeroBindingBytes(plaintext)
	plain, err := decodeRouteCapsule1Plain(plaintext)
	if err != nil {
		return protocol.RouteCapsule1Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: malformed RouteCapsule1 plaintext: %w", err)
	}
	if plain.MsgType != registry.MsgRouteCapsule1 || plain.RouteInstanceID != ctx.RouteInstanceID || plain.HopIndex != ctx.HopIndex {
		return protocol.RouteCapsule1Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: RouteCapsule1 plaintext header mismatch")
	}
	return plain, nil
}

func SealRouteCapsule2(ctx ControlCapsuleContext, plain protocol.RouteCapsule2Plain) ([]byte, error) {
	plain.MsgType = registry.MsgRouteCapsule2
	plain.RouteInstanceID = ctx.RouteInstanceID
	plain.HopIndex = ctx.HopIndex
	encoded, err := protocol.Encode(plain)
	if err != nil {
		return nil, err
	}
	return sealControl(ctx, registry.MsgRouteCapsule2, ControlDirectionHopToClient, ctx.ServerHSKey, ctx.ServerHSIV, encoded)
}

func OpenRouteCapsule2(ctx ControlCapsuleContext, sealed []byte) (protocol.RouteCapsule2Plain, error) {
	plaintext, err := openControl(ctx, registry.MsgRouteCapsule2, ControlDirectionHopToClient, ctx.ServerHSKey, ctx.ServerHSIV, sealed)
	if err != nil {
		return protocol.RouteCapsule2Plain{}, failure.NewError(failure.BadAEADTag, "handshake: RouteCapsule2 AEAD open failed: %w", err)
	}
	defer zeroBindingBytes(plaintext)
	plain, err := decodeRouteCapsule2Plain(plaintext)
	if err != nil {
		return protocol.RouteCapsule2Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: malformed RouteCapsule2 plaintext: %w", err)
	}
	if plain.MsgType != registry.MsgRouteCapsule2 || plain.RouteInstanceID != ctx.RouteInstanceID || plain.HopIndex != ctx.HopIndex {
		return protocol.RouteCapsule2Plain{}, failure.NewError(failure.MalformedCapsule, "handshake: RouteCapsule2 plaintext header mismatch")
	}
	return plain, nil
}

func sealControl(ctx ControlCapsuleContext, msgType uint64, direction uint8, key, iv, plaintext []byte) ([]byte, error) {
	aad, err := controlAAD(ctx, msgType, direction)
	if err != nil {
		return nil, err
	}
	nonce, err := auroracrypto.XORNonce96(iv, 0)
	if err != nil {
		return nil, err
	}
	return auroracrypto.SealForSuite(ctx.SelectedSuite, key, nonce, aad, plaintext)
}

func openControl(ctx ControlCapsuleContext, msgType uint64, direction uint8, key, iv, sealed []byte) ([]byte, error) {
	aad, err := controlAAD(ctx, msgType, direction)
	if err != nil {
		return nil, err
	}
	nonce, err := auroracrypto.XORNonce96(iv, 0)
	if err != nil {
		return nil, err
	}
	return auroracrypto.OpenForSuite(ctx.SelectedSuite, key, nonce, aad, sealed)
}

func controlAAD(ctx ControlCapsuleContext, msgType uint64, direction uint8) ([]byte, error) {
	if ctx.SelectedVersion != registry.Version20 {
		return nil, fmt.Errorf("handshake: unsupported selected version 0x%x", ctx.SelectedVersion)
	}
	return auroracrypto.ControlAAD(auroracrypto.ControlAADInput{
		SelectedVersion:                 ctx.SelectedVersion,
		SelectedSuite:                   ctx.SelectedSuite,
		MsgType:                         msgType,
		RouteInstanceID:                 ctx.RouteInstanceID,
		HopIndex:                        ctx.HopIndex,
		ControlDirection:                direction,
		HandshakeBindingContext:         ctx.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: ctx.PreludeTranscriptHashForThisHop,
	})
}

func decodeCoverCapsule1Plain(encoded []byte) (protocol.CoverCapsule1Plain, error) {
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverCapsule1Plain(r)
	if r.Err() != nil {
		return protocol.CoverCapsule1Plain{}, r.Err()
	}
	if !r.EOF() {
		return protocol.CoverCapsule1Plain{}, fmt.Errorf("handshake: trailing CoverCapsule1 bytes")
	}
	return out, nil
}

func decodeRouteCapsule1Plain(encoded []byte) (protocol.RouteCapsule1Plain, error) {
	r := wire.NewReader(encoded)
	out := protocol.DecodeRouteCapsule1Plain(r)
	if r.Err() != nil {
		return protocol.RouteCapsule1Plain{}, r.Err()
	}
	if !r.EOF() {
		return protocol.RouteCapsule1Plain{}, fmt.Errorf("handshake: trailing RouteCapsule1 bytes")
	}
	return out, nil
}

func decodeRouteCapsule2Plain(encoded []byte) (protocol.RouteCapsule2Plain, error) {
	r := wire.NewReader(encoded)
	out := protocol.DecodeRouteCapsule2Plain(r)
	if r.Err() != nil {
		return protocol.RouteCapsule2Plain{}, r.Err()
	}
	if !r.EOF() {
		return protocol.RouteCapsule2Plain{}, fmt.Errorf("handshake: trailing RouteCapsule2 bytes")
	}
	return out, nil
}

func decodeCoverCapsule2Plain(encoded []byte) (protocol.CoverCapsule2Plain, error) {
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverCapsule2Plain(r)
	if r.Err() != nil {
		return protocol.CoverCapsule2Plain{}, r.Err()
	}
	if !r.EOF() {
		return protocol.CoverCapsule2Plain{}, fmt.Errorf("handshake: trailing CoverCapsule2 bytes")
	}
	return out, nil
}
