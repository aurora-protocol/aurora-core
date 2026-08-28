package ops

// Adversarial coverage for the pure validation functions in ops/ops.go that the
// existing ops_test.go does not reach. Each case crafts a minimal input (or
// reuses the existing verifierServiceRecord / verifierProofReplay / rb helpers)
// and asserts the error response, with no TLS server or live signature needed
// where the rejection branch fires before the signature check.
//
// Branch routing notes:
//   - ValidateIssuerVerifierResponse checks fields in order (version, service,
//     request hash, decision, token_spent_key, expiry, outlives, freshness,
//     nonce, signature-present, final verify). The five uncovered branches
//     (version/service/expired/outlives/nonce) all fire before the final
//     auroratrust.VerifyIssuerVerifierResponse call, so no valid signature is
//     required — a crafted response with the matching request hash is enough.
//   - BuildIssuerVerifierRequest checks missing replay cache (135-136) and then
//     Service.Allows (141-142) before any replay/field computation, so a nil
//     cache or a non-allowed relay bucket trips those early returns without
//     touching the (precomputed) replay context.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// Dead by design (documented, not contrived) in verifierRequestAuthenticatorFields:
//   - 196-198 (DecodeAuroraTokenMetadataBytes error): ValidateStructural at line
//     138 already decoded proof.TokenPublicMetadata successfully and the bytes are
//     unchanged, so the re-decode at line 195 cannot fail.
//   - 203-205 (RFC9577TokenChallengeDigest error): errors only on proofType >
//     0xffff or an empty issuer name, both already validated by ValidateForProof
//     (run inside ValidateStructural at 138).
//   - 210-212 (RFC9577AuthenticatorInputHash error): errors only on proofType >
//     0xffff, already validated.
//   - 214-215 (switch default fallback): only reachable via a proof type other
//     than ProofVOPRFP384SHA384/ProofBlindRSA2048; only those two types exist in
//     the registry (registry.go:70-71) and production services allow only them.
//     The one genuinely reachable uncovered branch — the challenge-digest value
//     mismatch at line 206 (ValidateForProof checks challenge-digest LENGTH only,
//     not value) — is covered by
//     TestBuildIssuerVerifierRequestRejectsTokenMetadataChallengeMismatch.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

// verifierTokenMetadataWithPerturbedChallengeDigest mirrors
// verifierTokenMetadataForTest (ops_test.go) but embeds a WRONG 32-byte challenge
// digest. ValidateForProof (called by ValidateStructural at line 138 and again at
// line 199) checks the challenge digest's LENGTH only, not its value, so this
// metadata passes structural validation; the value mismatch is first caught at
// line 206 inside verifierRequestAuthenticatorFields. Every other field
// (proof type, token key id, issuer name, issuer metadata hash) is identical to
// the passing fixture, so the rejection is attributable to the challenge digest
// alone (no wrong-branch).
func verifierTokenMetadataWithPerturbedChallengeDigest(t *testing.T, proof protocol.AdmissionProof, issuerMetadataHash, issuerName, originInfo []byte) []byte {
	t.Helper()
	metadataEncoder := wire.NewEncoder()
	metadataEncoder.WriteUint16(uint16(proof.ProofType))
	metadataEncoder.WriteOpaqueFixed(rb(0xee, 32), 32)
	metadataEncoder.WriteOpaqueFixed(proof.TokenKeyID, 32)
	metadataEncoder.WriteOpaque16(issuerName)
	metadataEncoder.WriteOpaque16(originInfo)
	metadataEncoder.WritePreHash(issuerMetadataHash)
	metadata, err := metadataEncoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestBuildIssuerVerifierRequestRejectsTokenMetadataChallengeMismatch(t *testing.T) {
	// The perturbed metadata passes ValidateStructural (issuer metadata hash is
	// self-consistent) and Service.Allows (proof type + bucket still match), so
	// execution reaches verifierRequestAuthenticatorFields, where the recomputed
	// challenge digest (from issuer name + origin info + redemption context)
	// does not equal the embedded one -> line 206. This fires before the replay
	// spend at line 148, so no token is spent.
	service := verifierServiceRecord()
	input := verifierServiceVerificationRequest(t, service)
	input.AdmissionProof.TokenPublicMetadata = verifierTokenMetadataWithPerturbedChallengeDigest(
		t, input.AdmissionProof, rb(0x30, 48), []byte("issuer.example"), []byte("origin.example"))
	if _, _, err := BuildIssuerVerifierRequest(input); err == nil {
		t.Fatal("BuildIssuerVerifierRequest accepted token metadata with a mismatched challenge digest")
	}
}

func TestDirectoryPublisherPublishValidation(t *testing.T) {
	t.Run("zero threshold defaults to one and accepts signed consensus", func(t *testing.T) {
		p := DirectoryPublisher{Threshold: 0}
		if err := p.Publish(ConsensusDraft{AuthoritySignatureCount: 1, PayloadHash: rb(0x01, 48)}); err != nil {
			t.Fatalf("zero-threshold signed consensus rejected: %v", err)
		}
	})
	t.Run("consensus below threshold rejected", func(t *testing.T) {
		p := DirectoryPublisher{Threshold: 3}
		if err := p.Publish(ConsensusDraft{AuthoritySignatureCount: 2, PayloadHash: rb(0x01, 48)}); err == nil {
			t.Fatal("below-threshold consensus accepted")
		}
	})
	t.Run("negative threshold fails closed on unsigned consensus", func(t *testing.T) {
		p := DirectoryPublisher{Threshold: -3}
		if err := p.Publish(ConsensusDraft{AuthoritySignatureCount: 0, PayloadHash: rb(0x01, 48)}); err == nil {
			t.Fatal("negative-threshold publisher accepted an unsigned consensus")
		}
	})
	t.Run("payload hash length must be 48", func(t *testing.T) {
		p := DirectoryPublisher{Threshold: 1}
		if err := p.Publish(ConsensusDraft{AuthoritySignatureCount: 2, PayloadHash: rb(0x01, 47)}); err == nil {
			t.Fatal("consensus with 47-byte payload hash accepted")
		}
	})
}

func TestVerifierServiceAllowsMembership(t *testing.T) {
	t.Run("proof type not in allowlist rejected", func(t *testing.T) {
		s := VerifierService{
			AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
			AllowedRelayBucketIDs: [][]byte{rb(0x01, 16)},
		}
		if s.Allows(registry.ProofBlindRSA2048, rb(0x01, 16)) {
			t.Fatal("verifier service allowed an unlisted proof type")
		}
	})
	t.Run("matching proof type and bucket allowed", func(t *testing.T) {
		bucket := rb(0x01, 16)
		s := VerifierService{
			AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
			AllowedRelayBucketIDs: [][]byte{bucket},
		}
		if !s.Allows(registry.ProofVOPRFP384SHA384, bucket) {
			t.Fatal("verifier service rejected a matching proof type and bucket")
		}
	})
	t.Run("bucket not in allowlist rejected", func(t *testing.T) {
		s := VerifierService{
			AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
			AllowedRelayBucketIDs: [][]byte{rb(0x01, 16)},
		}
		if s.Allows(registry.ProofVOPRFP384SHA384, rb(0x02, 16)) {
			t.Fatal("verifier service allowed an unlisted bucket")
		}
	})
	t.Run("empty bucket allowlist rejected even with proof type", func(t *testing.T) {
		s := VerifierService{
			AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
			AllowedRelayBucketIDs: nil,
		}
		if s.Allows(registry.ProofVOPRFP384SHA384, rb(0x01, 16)) {
			t.Fatal("verifier service with empty bucket allowlist allowed a request")
		}
	})
}

func TestValidateServiceAuthKeyAcceptsNovelKey(t *testing.T) {
	if err := ValidateServiceAuthKey([]byte("novel-service-key"), [][]byte{[]byte("authority-key-1"), []byte("authority-key-2")}); err != nil {
		t.Fatalf("novel service auth key rejected: %v", err)
	}
}

func TestBuildIssuerVerifierRequestRejectsMissingReplayCache(t *testing.T) {
	if _, _, err := BuildIssuerVerifierRequest(IssuerVerifierRequestInput{}); err == nil {
		t.Fatal("BuildIssuerVerifierRequest accepted an input missing local replay caches")
	}
}

func TestBuildIssuerVerifierRequestRejectsServiceNotAllowedBucket(t *testing.T) {
	// A structurally-valid proof whose RelayBucketID is not in the service
	// allowlist passes ValidateStructural but is rejected by Service.Allows at
	// line 141, before any replay or authenticator-field computation.
	service := verifierServiceRecord()
	input := verifierServiceVerificationRequest(t, service)
	input.AdmissionProof.RelayBucketID = rb(0xff, 16)
	if _, _, err := BuildIssuerVerifierRequest(input); err == nil {
		t.Fatal("BuildIssuerVerifierRequest accepted a proof whose bucket the service does not allow")
	}
}

func TestVerifyIssuerVerifierServiceRejectsNilTransport(t *testing.T) {
	if err := VerifyIssuerVerifierService(IssuerVerifierServiceVerificationInput{Transport: nil}); err == nil {
		t.Fatal("VerifyIssuerVerifierService accepted a nil transport")
	}
}

func TestVerifyIssuerVerifierServicePropagatesRequestBuildFailure(t *testing.T) {
	// A non-nil transport with a request whose replay caches are nil makes
	// BuildIssuerVerifierRequest fail at line 135, so VerifyIssuerVerifierService
	// returns that build error at line 124 (before any transport exchange).
	if err := VerifyIssuerVerifierService(IssuerVerifierServiceVerificationInput{
		Request:   IssuerVerifierRequestInput{},
		Transport: outageVerifierTransport{},
	}); err == nil {
		t.Fatal("VerifyIssuerVerifierService accepted a request that failed to build")
	}
}

// validVerifierResponseBase builds a response that passes every
// ValidateIssuerVerifierResponse check up to (but not including) the final
// signature verification, so a single perturbation reaches a specific late
// branch. It is reused by the expired / outlives / nonce subtests.
func validVerifierResponseBase(service protocol.IssuerVerifierServiceRecord, req protocol.IssuerVerifierRequest, requestHash []byte) protocol.IssuerVerifierResponse {
	return protocol.IssuerVerifierResponse{
		ResponseVersion: registry.Version20,
		ServiceID:       append([]byte(nil), service.ServiceID...),
		RequestHash:     append([]byte(nil), requestHash...),
		Decision:        registry.VerifierDecisionAccept,
		TokenSpentKey:   append([]byte(nil), req.TokenSpentKey...),
		ValidUntilUnix:  200,
		ResponseNonce:   rb(0x40, 32),
	}
}

func TestValidateIssuerVerifierResponseRejectsEarlyMalformed(t *testing.T) {
	service := verifierServiceRecord()
	t.Run("unsupported response version", func(t *testing.T) {
		resp := protocol.IssuerVerifierResponse{ResponseVersion: 0}
		if err := ValidateIssuerVerifierResponse(service, protocol.IssuerVerifierRequest{}, resp, 150); err == nil {
			t.Fatal("verifier response with unsupported version accepted")
		}
	})
	t.Run("service id mismatch", func(t *testing.T) {
		resp := protocol.IssuerVerifierResponse{
			ResponseVersion: registry.Version20,
			ServiceID:       []byte("wrong-service-id"),
		}
		if err := ValidateIssuerVerifierResponse(service, protocol.IssuerVerifierRequest{}, resp, 150); err == nil {
			t.Fatal("verifier response with mismatched service id accepted")
		}
	})
}

func TestValidateIssuerVerifierResponseRejectsStaleAndMalformedFields(t *testing.T) {
	service := verifierServiceRecord()
	req, requestHash, err := BuildIssuerVerifierRequest(verifierServiceVerificationRequest(t, service))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("expired", func(t *testing.T) {
		resp := validVerifierResponseBase(service, req, requestHash)
		resp.ValidUntilUnix = 100 // now=150 > 100
		if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
			t.Fatal("expired verifier response accepted")
		}
	})
	t.Run("outlives service window", func(t *testing.T) {
		resp := validVerifierResponseBase(service, req, requestHash)
		resp.ValidUntilUnix = 901 // service.ValidUntilUnix=900
		if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
			t.Fatal("verifier response outliving the service window accepted")
		}
	})
	t.Run("nonce not 32 bytes", func(t *testing.T) {
		resp := validVerifierResponseBase(service, req, requestHash)
		resp.ResponseNonce = rb(0x40, 31)
		if err := ValidateIssuerVerifierResponse(service, req, resp, 150); err == nil {
			t.Fatal("verifier response with 31-byte nonce accepted")
		}
	})
}
