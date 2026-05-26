package route

import (
	"bytes"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type HopBindingInput struct {
	RouteInstanceID                uint64
	HopIndex                       uint8
	PreviousHopFullTranscriptHash  []byte
	PreviousHopRelayDescriptorHash []byte
	NextRelayDescriptorHash        []byte
	RoutePreludeWrapContext        []byte
	ClientNonceForThisHop          []byte
}

func PreviousHopFullTranscriptHash(previousHopSelectedSuite uint64, applicationTranscriptHash []byte) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 previous hop full transcript"))
	e.WriteVarint(previousHopSelectedSuite)
	e.WriteOpaque16(applicationTranscriptHash)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func RouteHopBinding(in HopBindingInput) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 route hop binding"))
	e.WriteVarint(in.RouteInstanceID)
	e.WriteUint8(in.HopIndex)
	e.WritePreHash(in.PreviousHopFullTranscriptHash)
	e.WritePreHash(in.PreviousHopRelayDescriptorHash)
	e.WritePreHash(in.NextRelayDescriptorHash)
	e.WritePreHash(in.RoutePreludeWrapContext)
	e.WriteOpaqueFixed(in.ClientNonceForThisHop, 32)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

type EnvelopeInput struct {
	RouteInstanceID                uint64
	HopIndex                       uint8
	PreviousHopRelayDescriptorHash []byte
	NextRelayDescriptorHash        []byte
	HintIssuerID                   []byte
	RelayBucketID                  []byte
	HintEpochID                    uint64
	HintSelector                   []byte
	WrapSuiteID                    uint64
	WrapNonce                      []byte
	HintSecret                     []byte
}

func (e EnvelopeInput) routeWrapInput() auroracrypto.RouteWrapInput {
	return auroracrypto.RouteWrapInput{
		RouteInstanceID:                e.RouteInstanceID,
		HopIndex:                       e.HopIndex,
		PreviousHopRelayDescriptorHash: e.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        e.NextRelayDescriptorHash,
		HintIssuerID:                   e.HintIssuerID,
		RelayBucketID:                  e.RelayBucketID,
		HintEpochID:                    e.HintEpochID,
		HintSelector:                   e.HintSelector,
		WrapSuiteID:                    e.WrapSuiteID,
		WrapNonce:                      e.WrapNonce,
		HintSecret:                     e.HintSecret,
	}
}

type PrivatePrelude struct {
	MsgType                        uint64
	Version                        uint64
	RouteInstanceID                uint64
	HopIndex                       uint8
	PreviousHopRelayDescriptorHash []byte
	NextRelayDescriptorHash        []byte
	RoutePreludeWrapContext        []byte
	PreviousHopFullTranscriptHash  []byte
	ClientNonceForThisHop          []byte
	OfferedSuites                  []uint64
	ClientClassicalEphPub          []byte
	ClientMLKEMEncapsulationKey    []byte
	HintIssuerID                   []byte
	RelayBucketID                  []byte
	HintEpochID                    uint64
	HintSelector                   []byte
	AccessHint                     []byte
	RequestedRouteModeID           uint64
	CoverShapeHintID               uint64
	Padding                        []byte
	Extensions                     []protocol.Extension
}

func (p PrivatePrelude) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.MsgType)
	e.WriteVarint(p.Version)
	e.WriteVarint(p.RouteInstanceID)
	e.WriteUint8(p.HopIndex)
	e.WritePreHash(p.PreviousHopRelayDescriptorHash)
	e.WritePreHash(p.NextRelayDescriptorHash)
	e.WritePreHash(p.RoutePreludeWrapContext)
	e.WritePreHash(p.PreviousHopFullTranscriptHash)
	e.WriteOpaqueFixed(p.ClientNonceForThisHop, 32)
	e.WriteVarintVector(p.OfferedSuites)
	e.WriteOpaque16(p.ClientClassicalEphPub)
	e.WriteOpaque16(p.ClientMLKEMEncapsulationKey)
	e.WriteOpaqueFixed(p.HintIssuerID, 16)
	e.WriteOpaqueFixed(p.RelayBucketID, 16)
	e.WriteUint64(p.HintEpochID)
	e.WriteOpaqueFixed(p.HintSelector, 16)
	e.WriteOpaque16(p.AccessHint)
	e.WriteVarint(p.RequestedRouteModeID)
	e.WriteVarint(p.CoverShapeHintID)
	e.WriteOpaque16(p.Padding)
	protocol.EncodeExtensions(e, p.Extensions)
}

func DecodePrivatePrelude(encoded []byte) (PrivatePrelude, error) {
	r := wire.NewReader(encoded)
	p := PrivatePrelude{
		MsgType:                        r.ReadVarint(),
		Version:                        r.ReadVarint(),
		RouteInstanceID:                r.ReadVarint(),
		HopIndex:                       r.ReadUint8(),
		PreviousHopRelayDescriptorHash: r.ReadPreHash(),
		NextRelayDescriptorHash:        r.ReadPreHash(),
		RoutePreludeWrapContext:        r.ReadPreHash(),
		PreviousHopFullTranscriptHash:  r.ReadPreHash(),
		ClientNonceForThisHop:          r.ReadOpaqueFixed(32),
		OfferedSuites:                  r.ReadVarintVector(),
		ClientClassicalEphPub:          r.ReadOpaque16(),
		ClientMLKEMEncapsulationKey:    r.ReadOpaque16(),
		HintIssuerID:                   r.ReadOpaqueFixed(16),
		RelayBucketID:                  r.ReadOpaqueFixed(16),
		HintEpochID:                    r.ReadUint64(),
		HintSelector:                   r.ReadOpaqueFixed(16),
		AccessHint:                     r.ReadOpaque16(),
		RequestedRouteModeID:           r.ReadVarint(),
		CoverShapeHintID:               r.ReadVarint(),
		Padding:                        r.ReadOpaque16(),
		Extensions:                     protocol.DecodeExtensions(r),
	}
	if r.Err() != nil {
		return PrivatePrelude{}, r.Err()
	}
	if !r.EOF() {
		return PrivatePrelude{}, fmt.Errorf("route: trailing private prelude bytes")
	}
	return p, nil
}

func SealPrivatePrelude(env EnvelopeInput, private PrivatePrelude) (protocol.RoutePreludeEnvelope, error) {
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		return protocol.RoutePreludeEnvelope{}, err
	}
	private.MsgType = registry.MsgRoutePrelude0
	private.Version = registry.Version20
	private.RoutePreludeWrapContext = context
	private.RouteInstanceID = env.RouteInstanceID
	private.HopIndex = env.HopIndex
	private.PreviousHopRelayDescriptorHash = append([]byte(nil), env.PreviousHopRelayDescriptorHash...)
	private.NextRelayDescriptorHash = append([]byte(nil), env.NextRelayDescriptorHash...)
	private.HintIssuerID = append([]byte(nil), env.HintIssuerID...)
	private.RelayBucketID = append([]byte(nil), env.RelayBucketID...)
	private.HintEpochID = env.HintEpochID
	private.HintSelector = append([]byte(nil), env.HintSelector...)
	encoded, err := protocol.Encode(private)
	if err != nil {
		return protocol.RoutePreludeEnvelope{}, err
	}
	_, _, _, _, sealed, err := auroracrypto.SealRoutePrelude(env.routeWrapInput(), encoded)
	if err != nil {
		return protocol.RoutePreludeEnvelope{}, err
	}
	return protocol.RoutePreludeEnvelope{
		RouteInstanceID:                env.RouteInstanceID,
		HopIndex:                       env.HopIndex,
		PreviousHopRelayDescriptorHash: append([]byte(nil), env.PreviousHopRelayDescriptorHash...),
		NextRelayDescriptorHash:        append([]byte(nil), env.NextRelayDescriptorHash...),
		HintIssuerID:                   append([]byte(nil), env.HintIssuerID...),
		RelayBucketID:                  append([]byte(nil), env.RelayBucketID...),
		HintEpochID:                    env.HintEpochID,
		HintSelector:                   append([]byte(nil), env.HintSelector...),
		WrapSuiteID:                    env.WrapSuiteID,
		WrapNonce:                      append([]byte(nil), env.WrapNonce...),
		SealedRoutePrelude0:            sealed,
	}, nil
}

func OpenPrivatePrelude(env EnvelopeInput, envelope protocol.RoutePreludeEnvelope) (PrivatePrelude, error) {
	if err := validateEnvelopeInput(env, envelope); err != nil {
		return PrivatePrelude{}, err
	}
	plaintext, err := auroracrypto.OpenRoutePrelude(env.routeWrapInput(), envelope.SealedRoutePrelude0)
	if err != nil {
		return PrivatePrelude{}, err
	}
	private, err := DecodePrivatePrelude(plaintext)
	if err != nil {
		return PrivatePrelude{}, err
	}
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		return PrivatePrelude{}, err
	}
	if private.RouteInstanceID != env.RouteInstanceID ||
		private.HopIndex != env.HopIndex ||
		!bytes.Equal(private.PreviousHopRelayDescriptorHash, env.PreviousHopRelayDescriptorHash) ||
		!bytes.Equal(private.NextRelayDescriptorHash, env.NextRelayDescriptorHash) ||
		!bytes.Equal(private.HintIssuerID, env.HintIssuerID) ||
		!bytes.Equal(private.RelayBucketID, env.RelayBucketID) ||
		private.HintEpochID != env.HintEpochID ||
		!bytes.Equal(private.HintSelector, env.HintSelector) ||
		!bytes.Equal(private.RoutePreludeWrapContext, context) {
		return PrivatePrelude{}, fmt.Errorf("route: decrypted prelude does not match visible envelope")
	}
	if err := ValidatePrivatePreludeHybridShares(private); err != nil {
		return PrivatePrelude{}, err
	}
	return private, nil
}

func ValidatePrivatePreludeHybridShares(private PrivatePrelude) error {
	for _, suite := range private.OfferedSuites {
		if err := validatePrivatePreludeHybridSharesForSuite(suite, private); err == nil {
			return nil
		}
	}
	return failure.NewError(failure.MalformedHybridShare, "route: malformed client hybrid share")
}

func validatePrivatePreludeHybridSharesForSuite(suite uint64, private PrivatePrelude) error {
	if _, err := auroracrypto.NewECDHPublicKeyForSuite(suite, private.ClientClassicalEphPub); err != nil {
		return err
	}
	return auroracrypto.ValidateMLKEMEncapsulationKeyForSuite(suite, private.ClientMLKEMEncapsulationKey)
}

func validateEnvelopeInput(env EnvelopeInput, envelope protocol.RoutePreludeEnvelope) error {
	if envelope.RouteInstanceID != env.RouteInstanceID ||
		envelope.HopIndex != env.HopIndex ||
		envelope.HintEpochID != env.HintEpochID ||
		envelope.WrapSuiteID != env.WrapSuiteID ||
		!bytes.Equal(envelope.PreviousHopRelayDescriptorHash, env.PreviousHopRelayDescriptorHash) ||
		!bytes.Equal(envelope.NextRelayDescriptorHash, env.NextRelayDescriptorHash) ||
		!bytes.Equal(envelope.HintIssuerID, env.HintIssuerID) ||
		!bytes.Equal(envelope.RelayBucketID, env.RelayBucketID) ||
		!bytes.Equal(envelope.HintSelector, env.HintSelector) ||
		!bytes.Equal(envelope.WrapNonce, env.WrapNonce) {
		return fmt.Errorf("route: visible envelope mismatch")
	}
	return nil
}
