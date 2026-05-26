package admission

import (
	"crypto/subtle"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

type ContextInput struct {
	SelectedVersion                 uint64
	SelectedSuite                   uint64
	RelayDescriptorHash             []byte
	CoverTemplateHash               []byte
	RouteInstanceID                 uint64
	HopIndex                        uint8
	HandshakeBindingContext         []byte
	PreludeTranscriptHashForThisHop []byte
	PolicyOffer                     protocol.PolicyOffer
	ClientTransportHints            protocol.ClientTransportHints
	RouteHop                        bool
}

func PolicyOfferHash(offer protocol.PolicyOffer) ([]byte, error) {
	encoded, err := protocol.Encode(offer)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 policy offer", encoded), nil
}

func ClientTransportHintsHash(hints protocol.ClientTransportHints) ([]byte, error) {
	if err := hints.ValidatePrototype(); err != nil {
		return nil, err
	}
	encoded, err := protocol.Encode(hints)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 client transport hints", encoded), nil
}

func AdmissionContextHash(in ContextInput) ([]byte, error) {
	policyOfferHash, err := PolicyOfferHash(in.PolicyOffer)
	if err != nil {
		return nil, err
	}
	hints := in.ClientTransportHints
	if in.RouteHop {
		hints = protocol.EmptyClientTransportHints()
	}
	hintsHash, err := ClientTransportHintsHash(hints)
	if err != nil {
		return nil, err
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 admission context"))
	e.WriteVarint(in.SelectedVersion)
	e.WriteVarint(in.SelectedSuite)
	e.WritePreHash(in.RelayDescriptorHash)
	e.WritePreHash(in.CoverTemplateHash)
	e.WriteVarint(in.PolicyOffer.RequestedRouteModeID)
	e.WriteVarint(in.RouteInstanceID)
	e.WriteUint8(in.HopIndex)
	e.WriteOpaque16(in.HandshakeBindingContext)
	e.WriteOpaque16(in.PreludeTranscriptHashForThisHop)
	e.WritePreHash(policyOfferHash)
	e.WritePreHash(hintsHash)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func TokenRedemptionHash(p protocol.AdmissionProof) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 token redemption"))
	e.WriteVarint(p.ProofType)
	e.WriteOpaqueFixed(p.IssuerID, 16)
	e.WriteOpaqueFixed(p.TokenKeyID, 32)
	e.WriteOpaqueFixed(p.RelayBucketID, 16)
	e.WriteOpaqueFixed(p.TokenScopeID, 16)
	e.WriteUint64(p.ExpiryUnix)
	e.WriteOpaqueFixed(p.TokenNonce, 32)
	e.WritePreHash(p.RedemptionContextHash)
	e.WriteOpaque16(p.TokenPublicMetadata)
	e.WriteOpaque16(p.TokenAuthenticator)
	e.WriteOpaque16(p.BindingProof)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func TokenSpentKey(tokenRedemptionHash []byte) ([]byte, error) {
	if len(tokenRedemptionHash) != 48 {
		return nil, fmt.Errorf("admission: token redemption hash length %d, want 48", len(tokenRedemptionHash))
	}
	return auroracrypto.PreHashLabel("aurora v2.0 token spent", tokenRedemptionHash), nil
}

func ReplayContextHash(tokenRedemptionHash []byte, replay protocol.ReplayProof, routeInstanceID uint64, hopIndex uint8, handshakeBindingContext, admissionContextHash []byte) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 replay context"))
	e.WritePreHash(tokenRedemptionHash)
	e.WriteOpaqueFixed(replay.ClientReplayNonce, 32)
	e.WriteUint64(replay.ReplayEpochID)
	e.WriteVarint(routeInstanceID)
	e.WriteUint8(hopIndex)
	e.WriteOpaque16(handshakeBindingContext)
	e.WritePreHash(admissionContextHash)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func BootstrapDedupKey(replayContextHash, replayWindowID []byte) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 bootstrap dedup"))
	e.WritePreHash(replayContextHash)
	e.WriteOpaqueFixed(replayWindowID, 16)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

type ReplayVerificationInput struct {
	AdmissionProof          protocol.AdmissionProof
	ReplayProof             protocol.ReplayProof
	RouteInstanceID         uint64
	HopIndex                uint8
	HandshakeBindingContext []byte
	AdmissionContextHash    []byte
	TokenSpentCache         ReplayCache
	BootstrapDedupCache     ReplayCache
	NowUnix                 uint64
	AllowLabProofs          bool
}

func VerifyAndSpendReplay(in ReplayVerificationInput) (tokenSpentKey, bootstrapDedupKey []byte, err error) {
	if err := in.AdmissionProof.ValidateStructural(in.NowUnix, in.AllowLabProofs); err != nil {
		return nil, nil, err
	}
	if err := in.ReplayProof.ValidateStructural(); err != nil {
		return nil, nil, err
	}
	if in.TokenSpentCache == nil {
		return nil, nil, fmt.Errorf("admission: missing token spent replay cache")
	}
	if in.BootstrapDedupCache == nil {
		return nil, nil, fmt.Errorf("admission: missing bootstrap replay cache")
	}
	tokenRedemptionHash, err := TokenRedemptionHash(in.AdmissionProof)
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(tokenRedemptionHash, in.ReplayProof.TokenRedemptionHash) != 1 {
		return nil, nil, fmt.Errorf("admission: replay token_redemption_hash mismatch")
	}
	tokenSpentKey, err = TokenSpentKey(tokenRedemptionHash)
	if err != nil {
		return nil, nil, err
	}
	replayContextHash, err := ReplayContextHash(tokenRedemptionHash, in.ReplayProof, in.RouteInstanceID, in.HopIndex, in.HandshakeBindingContext, in.AdmissionContextHash)
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(replayContextHash, in.ReplayProof.ReplayContextHash) != 1 {
		return nil, nil, fmt.Errorf("admission: replay_context_hash mismatch")
	}
	bootstrapDedupKey, err = BootstrapDedupKey(replayContextHash, in.ReplayProof.ReplayWindowID)
	if err != nil {
		return nil, nil, err
	}
	inserted, err := in.TokenSpentCache.InsertIfAbsent(tokenSpentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("admission: token spent replay cache failed: %w", err)
	}
	if !inserted {
		return nil, nil, fmt.Errorf("admission: token already spent")
	}
	inserted, err = in.BootstrapDedupCache.InsertIfAbsent(bootstrapDedupKey)
	if err != nil {
		return nil, nil, fmt.Errorf("admission: bootstrap replay cache failed: %w", err)
	}
	if !inserted {
		return nil, nil, fmt.Errorf("admission: bootstrap attempt already seen")
	}
	return tokenSpentKey, bootstrapDedupKey, nil
}
