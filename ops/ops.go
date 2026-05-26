package ops

import (
	"bytes"
	"fmt"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

type ConsensusDraft struct {
	AuthoritySignatureCount int
	PayloadHash             []byte
}

type DirectoryPublisher struct {
	Threshold int
}

func (p DirectoryPublisher) Publish(d ConsensusDraft) error {
	threshold := p.Threshold
	if threshold == 0 {
		threshold = 1
	}
	if d.AuthoritySignatureCount < threshold {
		return fmt.Errorf("ops: consensus lacks signature threshold")
	}
	if len(d.PayloadHash) != 48 {
		return fmt.Errorf("ops: consensus payload hash must be 48 bytes")
	}
	return nil
}

type VerifierService struct {
	AllowedProofTypes     []uint64
	AllowedRelayBucketIDs [][]byte
}

func (s VerifierService) Allows(proofType uint64, relayBucketID []byte) bool {
	if len(s.AllowedProofTypes) == 0 || len(s.AllowedRelayBucketIDs) == 0 {
		return false
	}
	proofOK := false
	for _, allowed := range s.AllowedProofTypes {
		if allowed == proofType {
			proofOK = true
			break
		}
	}
	if !proofOK {
		return false
	}
	for _, allowed := range s.AllowedRelayBucketIDs {
		if bytes.Equal(allowed, relayBucketID) {
			return true
		}
	}
	return false
}

func ValidateServiceAuthKey(serviceAuthKey []byte, authorityKeys [][]byte) error {
	for _, key := range authorityKeys {
		if bytes.Equal(serviceAuthKey, key) {
			return fmt.Errorf("ops: service_auth_key must not reuse authority key material")
		}
	}
	return nil
}

func SelectIssuerVerifierService(services []protocol.IssuerVerifierServiceRecord, proofType uint64, relayBucketID []byte, now uint64, implementedRequestAuthPolicies map[uint64]bool) (protocol.IssuerVerifierServiceRecord, error) {
	var matches []protocol.IssuerVerifierServiceRecord
	for _, service := range services {
		if err := service.Allows(proofType, relayBucketID, now, implementedRequestAuthPolicies[service.RequestAuthPolicyID]); err != nil {
			continue
		}
		matches = append(matches, service)
	}
	if len(matches) != 1 {
		return protocol.IssuerVerifierServiceRecord{}, fmt.Errorf("ops: verifier service selection returned %d matches", len(matches))
	}
	return matches[0], nil
}

type IssuerVerifierRequestInput struct {
	Service                   protocol.IssuerVerifierServiceRecord
	AdmissionProof            protocol.AdmissionProof
	ReplayProof               protocol.ReplayProof
	IssuerMetadataHash        []byte
	RelayDescriptorHash       []byte
	RouteInstanceID           uint64
	HopIndex                  uint8
	ReplayEpochValidUntilUnix uint64
	HandshakeBindingContext   []byte
	AdmissionContextHash      []byte
	ChallengeDigest           []byte
	AuthenticatorInputHash    []byte
	RequestNonce              []byte
	RequestTimeUnix           uint64
	NowUnix                   uint64
	RequestAuthImplemented    bool
}

func BuildIssuerVerifierRequest(in IssuerVerifierRequestInput) (protocol.IssuerVerifierRequest, []byte, error) {
	if err := in.AdmissionProof.ValidateStructural(in.NowUnix, false); err != nil {
		return protocol.IssuerVerifierRequest{}, nil, err
	}
	if err := in.Service.Allows(in.AdmissionProof.ProofType, in.AdmissionProof.RelayBucketID, in.NowUnix, in.RequestAuthImplemented); err != nil {
		return protocol.IssuerVerifierRequest{}, nil, err
	}
	tokenSpentKey, _, err := admission.VerifyAndSpendReplay(admission.ReplayVerificationInput{
		AdmissionProof:          in.AdmissionProof,
		ReplayProof:             in.ReplayProof,
		RouteInstanceID:         in.RouteInstanceID,
		HopIndex:                in.HopIndex,
		HandshakeBindingContext: in.HandshakeBindingContext,
		AdmissionContextHash:    in.AdmissionContextHash,
	})
	if err != nil {
		return protocol.IssuerVerifierRequest{}, nil, err
	}
	req := protocol.IssuerVerifierRequest{
		RequestVersion:            registry.Version20,
		ServiceID:                 append([]byte(nil), in.Service.ServiceID...),
		IssuerID:                  append([]byte(nil), in.AdmissionProof.IssuerID...),
		IssuerMetadataHash:        append([]byte(nil), in.IssuerMetadataHash...),
		RelayDescriptorHash:       append([]byte(nil), in.RelayDescriptorHash...),
		RelayBucketID:             append([]byte(nil), in.AdmissionProof.RelayBucketID...),
		RouteInstanceID:           in.RouteInstanceID,
		HopIndex:                  in.HopIndex,
		ProofType:                 in.AdmissionProof.ProofType,
		TokenKeyID:                append([]byte(nil), in.AdmissionProof.TokenKeyID...),
		TokenNonce:                append([]byte(nil), in.AdmissionProof.TokenNonce...),
		ChallengeDigest:           append([]byte(nil), in.ChallengeDigest...),
		AuthenticatorInputHash:    append([]byte(nil), in.AuthenticatorInputHash...),
		TokenAuthenticator:        append([]byte(nil), in.AdmissionProof.TokenAuthenticator...),
		TokenSpentKey:             tokenSpentKey,
		ReplayEpochID:             in.ReplayProof.ReplayEpochID,
		ReplayEpochValidUntilUnix: in.ReplayEpochValidUntilUnix,
		RequestNonce:              append([]byte(nil), in.RequestNonce...),
		RequestTimeUnix:           in.RequestTimeUnix,
	}
	hash, err := IssuerVerifierRequestHash(req)
	if err != nil {
		return protocol.IssuerVerifierRequest{}, nil, err
	}
	return req, hash, nil
}

func IssuerVerifierRequestHash(req protocol.IssuerVerifierRequest) ([]byte, error) {
	encoded, err := protocol.Encode(req)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 issuer verifier request", encoded), nil
}

func ValidateIssuerVerifierResponse(service protocol.IssuerVerifierServiceRecord, req protocol.IssuerVerifierRequest, resp protocol.IssuerVerifierResponse, now uint64) error {
	if resp.ResponseVersion != registry.Version20 {
		return fmt.Errorf("ops: unsupported verifier response version 0x%x", resp.ResponseVersion)
	}
	if !bytes.Equal(resp.ServiceID, service.ServiceID) || !bytes.Equal(resp.ServiceID, req.ServiceID) {
		return fmt.Errorf("ops: verifier response service mismatch")
	}
	requestHash, err := IssuerVerifierRequestHash(req)
	if err != nil {
		return err
	}
	if !bytes.Equal(resp.RequestHash, requestHash) {
		return fmt.Errorf("ops: verifier response request hash mismatch")
	}
	if resp.Decision != registry.VerifierDecisionAccept {
		return fmt.Errorf("ops: verifier response did not accept token")
	}
	if !bytes.Equal(resp.TokenSpentKey, req.TokenSpentKey) {
		return fmt.Errorf("ops: verifier response token_spent_key mismatch")
	}
	if now > resp.ValidUntilUnix {
		return fmt.Errorf("ops: verifier response expired")
	}
	if resp.ValidUntilUnix > service.ValidUntilUnix || resp.ValidUntilUnix > req.ReplayEpochValidUntilUnix {
		return fmt.Errorf("ops: verifier response outlives service or replay epoch")
	}
	if resp.ValidUntilUnix > req.RequestTimeUnix+300 {
		return fmt.Errorf("ops: verifier response freshness window too long")
	}
	if len(resp.ResponseNonce) != 32 {
		return fmt.Errorf("ops: verifier response nonce must be 32 bytes")
	}
	if len(resp.ServiceSignature) == 0 {
		return fmt.Errorf("ops: verifier response missing service signature")
	}
	return nil
}
