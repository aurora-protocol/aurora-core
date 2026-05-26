package route

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
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
	if err := ValidatePrivatePreludeHeader(private); err != nil {
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

func OpenAndVerifyPrivatePrelude(cache admission.ReplayCache, env EnvelopeInput, envelope protocol.RoutePreludeEnvelope, cred admission.AccessHintCredential, nowUnix uint64) (PrivatePrelude, []byte, error) {
	private, err := OpenPrivatePrelude(env, envelope)
	if err != nil {
		return PrivatePrelude{}, nil, err
	}
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		return PrivatePrelude{}, nil, err
	}
	if err := admission.VerifyAndSpendAccessHintAt(cache, cred, binding, private.ClientNonceForThisHop, private.AccessHint, nowUnix); err != nil {
		return PrivatePrelude{}, nil, fmt.Errorf("route: access hint verification failed: %w", err)
	}
	return private, binding, nil
}

func OpenAndVerifyPrivatePreludeWithWrapNonceCache(accessHintCache admission.ReplayCache, wrapNonceCache *WrapNonceReplayCache, env EnvelopeInput, envelope protocol.RoutePreludeEnvelope, cred admission.AccessHintCredential, nowUnix uint64) (PrivatePrelude, []byte, error) {
	private, err := OpenPrivatePrelude(env, envelope)
	if err != nil {
		return PrivatePrelude{}, nil, err
	}
	if wrapNonceCache == nil {
		return PrivatePrelude{}, nil, fmt.Errorf("route: missing route wrap nonce replay cache")
	}
	if ok, err := wrapNonceCache.InsertIfAbsent(envelope); err != nil {
		return PrivatePrelude{}, nil, err
	} else if !ok {
		return PrivatePrelude{}, nil, fmt.Errorf("route: duplicate route wrap nonce")
	}
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		return PrivatePrelude{}, nil, err
	}
	if err := admission.VerifyAndSpendAccessHintAt(accessHintCache, cred, binding, private.ClientNonceForThisHop, private.AccessHint, nowUnix); err != nil {
		return PrivatePrelude{}, nil, fmt.Errorf("route: access hint verification failed: %w", err)
	}
	return private, binding, nil
}

type WrapNonceReplayCache struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewWrapNonceReplayCache() *WrapNonceReplayCache {
	return &WrapNonceReplayCache{seen: make(map[string]struct{})}
}

func (c *WrapNonceReplayCache) InsertIfAbsent(envelope protocol.RoutePreludeEnvelope) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("route: missing route wrap nonce replay cache")
	}
	key, err := routeWrapNonceReplayKey(envelope)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[string(key)]; ok {
		return false, nil
	}
	c.seen[string(key)] = struct{}{}
	return true, nil
}

func routeWrapNonceReplayKey(envelope protocol.RoutePreludeEnvelope) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 route wrap nonce replay"))
	e.WriteOpaqueFixed(envelope.HintIssuerID, 16)
	e.WriteOpaqueFixed(envelope.RelayBucketID, 16)
	e.WriteUint64(envelope.HintEpochID)
	e.WriteOpaqueFixed(envelope.HintSelector, 16)
	e.WriteOpaqueFixed(envelope.WrapNonce, 16)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

type RoutePreludeVerificationInput struct {
	Suite           uint64
	RouteHopBinding []byte
	Prelude0        PrivatePrelude
	Prelude1        protocol.RoutePrelude1
	Descriptor      protocol.RelayDescriptor
	RequirePQ       bool
	NowUnix         uint64
}

func HopPreludeTranscriptHash(suite uint64, routeHopBinding []byte, p0 PrivatePrelude, p1 protocol.RoutePrelude1) ([]byte, error) {
	encoded0, err := protocol.Encode(p0)
	if err != nil {
		return nil, err
	}
	encoded1, err := protocol.Encode(p1.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.SuiteHash(suite,
		[]byte("aurora v2.0 hop prelude transcript"),
		routeHopBinding,
		encoded0,
		encoded1,
	)
}

func VerifyRoutePrelude1Signatures(in RoutePreludeVerificationInput) ([]byte, error) {
	if err := ValidatePrivatePreludeHeader(in.Prelude0); err != nil {
		return nil, err
	}
	if in.Prelude1.MsgType != registry.MsgRoutePrelude1 {
		return nil, fmt.Errorf("route: malformed route prelude response message type 0x%x", in.Prelude1.MsgType)
	}
	if in.Prelude1.Version != registry.Version20 {
		return nil, fmt.Errorf("route: unsupported route prelude response version 0x%x", in.Prelude1.Version)
	}
	if in.Prelude1.SelectedSuite != in.Suite {
		return nil, fmt.Errorf("route: selected suite mismatch")
	}
	if !containsUint64(in.Prelude0.OfferedSuites, in.Suite) {
		return nil, fmt.Errorf("route: selected suite was not offered")
	}
	if !containsUint64(in.Descriptor.SupportedSuiteIDs, in.Suite) {
		return nil, fmt.Errorf("route: selected suite is not supported by descriptor")
	}
	if err := validateRoutePreludeMetadata(in.Prelude0, in.Prelude1); err != nil {
		return nil, err
	}
	if err := ValidateRoutePreludeHybridShares(in.Suite, in.Prelude0, in.Prelude1); err != nil {
		return nil, err
	}
	expectedBinding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                in.Prelude0.RouteInstanceID,
		HopIndex:                       in.Prelude0.HopIndex,
		PreviousHopFullTranscriptHash:  in.Prelude0.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: in.Prelude0.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        in.Prelude0.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        in.Prelude0.RoutePreludeWrapContext,
		ClientNonceForThisHop:          in.Prelude0.ClientNonceForThisHop,
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(in.RouteHopBinding, expectedBinding) {
		return nil, fmt.Errorf("route: route_hop_binding mismatch")
	}
	if in.Prelude1.NextRelayEpochID != in.Descriptor.EpochID {
		return nil, fmt.Errorf("route: next relay epoch mismatch")
	}
	if in.NowUnix != 0 && (in.NowUnix < in.Descriptor.EpochValidFromUnix || in.NowUnix >= in.Descriptor.EpochValidUntilUnix) {
		return nil, fmt.Errorf("route: next relay epoch outside validity window")
	}
	descriptorHash, err := trust.RelayDescriptorHash(in.Descriptor)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(in.Prelude0.NextRelayDescriptorHash, descriptorHash) || !bytes.Equal(in.Prelude1.NextRelayDescriptorHash, descriptorHash) {
		return nil, fmt.Errorf("route: next relay descriptor hash mismatch")
	}
	transcript, err := HopPreludeTranscriptHash(in.Suite, expectedBinding, in.Prelude0, in.Prelude1)
	if err != nil {
		return nil, err
	}
	if len(in.Prelude1.ServerPreludeSignatureClassical) == 0 {
		return nil, fmt.Errorf("route: missing classical route prelude signature")
	}
	if err := auroracrypto.VerifySignature(in.Descriptor.EpochAuthClassicalKey.SignatureScheme, in.Descriptor.EpochAuthClassicalKey.KeyEncoding, in.Descriptor.EpochAuthClassicalKey.PublicKey, transcript, in.Prelude1.ServerPreludeSignatureClassical); err != nil {
		return nil, err
	}
	if in.RequirePQ || len(in.Prelude1.ServerPreludeSignaturePQ) > 0 {
		if len(in.Prelude1.ServerPreludeSignaturePQ) == 0 {
			return nil, fmt.Errorf("route: missing PQ route prelude signature")
		}
		if err := auroracrypto.VerifySignature(in.Descriptor.EpochAuthPQKey.SignatureScheme, in.Descriptor.EpochAuthPQKey.KeyEncoding, in.Descriptor.EpochAuthPQKey.PublicKey, transcript, in.Prelude1.ServerPreludeSignaturePQ); err != nil {
			return nil, err
		}
	}
	return transcript, nil
}

func validateRoutePreludeMetadata(p0 PrivatePrelude, p1 protocol.RoutePrelude1) error {
	if p1.RouteInstanceID != p0.RouteInstanceID ||
		p1.HopIndex != p0.HopIndex ||
		!bytes.Equal(p1.PreviousHopRelayDescriptorHash, p0.PreviousHopRelayDescriptorHash) ||
		!bytes.Equal(p1.NextRelayDescriptorHash, p0.NextRelayDescriptorHash) {
		return fmt.Errorf("route: route prelude response does not match request")
	}
	if len(p1.ServerNonce) != 32 {
		return fmt.Errorf("route: server nonce length %d, want 32", len(p1.ServerNonce))
	}
	return nil
}

func ValidateRoutePreludeHybridShares(suite uint64, p0 PrivatePrelude, p1 protocol.RoutePrelude1) error {
	if _, err := auroracrypto.NewECDHPublicKeyForSuite(suite, p0.ClientClassicalEphPub); err != nil {
		return failure.NewError(failure.MalformedHybridShare, "route: malformed client classical share")
	}
	if _, err := auroracrypto.NewECDHPublicKeyForSuite(suite, p1.ServerClassicalEphPub); err != nil {
		return failure.NewError(failure.MalformedHybridShare, "route: malformed server classical share")
	}
	if err := auroracrypto.ValidateMLKEMEncapsulationKeyForSuite(suite, p0.ClientMLKEMEncapsulationKey); err != nil {
		return failure.NewError(failure.MalformedHybridShare, "route: malformed client ML-KEM share")
	}
	if err := auroracrypto.ValidateMLKEMCiphertextForSuite(suite, p1.ServerMLKEMCiphertextToClient); err != nil {
		return failure.NewError(failure.MalformedHybridShare, "route: malformed server ML-KEM share")
	}
	return nil
}

func ValidatePrivatePreludeHeader(private PrivatePrelude) error {
	if private.MsgType != registry.MsgRoutePrelude0 {
		return fmt.Errorf("route: malformed private prelude message type 0x%x", private.MsgType)
	}
	if private.Version != registry.Version20 {
		return fmt.Errorf("route: unsupported private prelude version 0x%x", private.Version)
	}
	return nil
}

func containsUint64(values []uint64, needle uint64) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
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
