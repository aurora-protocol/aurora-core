package admission

// Adversarial coverage for admission/token_metadata.go (RFC 9577 token challenge /
// authenticator derivation, Blind RSA 2048 verification, issuer-policy enforcement).
//
// The Blind RSA verification error branches are exercised by perturbing a field of
// the valid fixture built by signedBlindRSAProofForTest / blindRSAIssuerMetadataForTest
// (in token_metadata_test.go) so that each earlier check still passes and the target
// branch is the one that fires. Coverage is re-measured per group to confirm the
// intended branch moved (no wrong-branch bugs).
//
// IMPORTANT — dead-by-design branches in VerifyBlindRSA2048 (token_metadata.go):
// VerifyBlindRSA2048 calls proof.ValidateStructural at its top, and
// AdmissionProof.ValidateStructuralWithOptions (protocol/admission.go:114-123) ALREADY
// decodes the embedded token metadata and runs AuroraTokenMetadata.ValidateForProof on
// it, after checking every field length ValidateForProof / RFC9577TokenChallengeDigest /
// RFC9577AuthenticatorInput depend on. Consequently four error branches later in
// VerifyBlindRSA2048 are unreachable once the structural check passes:
//   - DecodeAuroraTokenMetadataBytes err  (the bytes were just decoded successfully)
//   - RFC9577TokenChallengeDigest err     (issuer name non-empty + 48-byte redemption
//                                          hash + in-range proof type all guaranteed)
//   - metadata.ValidateForProof err       (the identical call already ran in structural)
//   - RFC9577AuthenticatorInput err       (TokenNonce/TokenKeyID are 32 bytes, guaranteed)
// They are defensive belt-and-suspenders re-checks, not bugs; left intentionally uncovered.
// The metadata-perturbing subtests below therefore exercise ValidateStructural's
// INTERNAL metadata validation (protocol/admission.go:116-122), not these dead branches.
//
// Helper names are suffixed ForCoverage to avoid collisions with the existing
// token_metadata_test.go helpers.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// overlongOpaqueCoverage is longer than the 16-bit Opaque length limit, used to drive
// WriteOpaque16 encoding errors.
const overlongOpaqueCoverage = 70000

func TestRFC9577RedemptionContextRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 47, 49, 64} {
		if _, err := RFC9577RedemptionContext(rep(0x21, n)); err == nil {
			t.Fatalf("RFC9577RedemptionContext accepted %d-byte hash", n)
		}
	}
}

func TestRFC9577TokenChallengeDigestRejectsMalformed(t *testing.T) {
	t.Run("proof type too large", func(t *testing.T) {
		if _, err := RFC9577TokenChallengeDigest(0x10000, []byte("issuer.example"), []byte("origin.example"), rep(0x22, 48)); err == nil {
			t.Fatal("RFC9577TokenChallengeDigest accepted an out-of-range proof type")
		}
	})
	t.Run("empty issuer name", func(t *testing.T) {
		if _, err := RFC9577TokenChallengeDigest(registry.ProofBlindRSA2048, []byte{}, []byte("origin.example"), rep(0x22, 48)); err == nil {
			t.Fatal("RFC9577TokenChallengeDigest accepted an empty issuer name")
		}
	})
	t.Run("bad redemption context hash", func(t *testing.T) {
		if _, err := RFC9577TokenChallengeDigest(registry.ProofBlindRSA2048, []byte("issuer.example"), []byte("origin.example"), rep(0x22, 47)); err == nil {
			t.Fatal("RFC9577TokenChallengeDigest accepted a short redemption context hash")
		}
	})
	t.Run("overlong issuer name", func(t *testing.T) {
		if _, err := RFC9577TokenChallengeDigest(registry.ProofBlindRSA2048, bytes.Repeat([]byte("x"), overlongOpaqueCoverage), []byte("origin.example"), rep(0x22, 48)); err == nil {
			t.Fatal("RFC9577TokenChallengeDigest accepted an overlong issuer name")
		}
	})
}

func TestRFC9577AuthenticatorInputRejectsWrongNonceLength(t *testing.T) {
	proof := protocol.AdmissionProof{
		ProofType:             registry.ProofBlindRSA2048,
		TokenNonce:            rep(0x23, 31), // want 32
		TokenKeyID:            rep(0x24, 32),
		RedemptionContextHash: rep(0x25, 48),
	}
	if _, err := RFC9577AuthenticatorInput(proof, rep(0x26, 32)); err == nil {
		t.Fatal("RFC9577AuthenticatorInput accepted a short token nonce")
	}
}

func TestContainsVarintReturnsFalseWhenMissing(t *testing.T) {
	if containsVarint([]uint64{1, 2, 3}, 99) {
		t.Fatal("containsVarint reported a missing value as present")
	}
}

// marshalBlindRSASPKIWithBody wraps an arbitrary key body in an RSASSA-PSS SPKI, so
// malformed bodies can drive the second asn1.Unmarshal error and trailing-body paths.
func marshalBlindRSASPKIWithBody(t *testing.T, body []byte) []byte {
	t.Helper()
	out, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
		},
		SubjectPublicKey: asn1.BitString{Bytes: body, BitLength: len(body) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseBlindRSA2048PublicKeyRejectsMalformed(t *testing.T) {
	t.Run("bad DER", func(t *testing.T) {
		if _, err := parseBlindRSA2048PublicKey([]byte("not-a-valid-spki")); err == nil {
			t.Fatal("parseBlindRSA2048PublicKey accepted garbage DER")
		}
	})
	t.Run("bad key body", func(t *testing.T) {
		keyDER := marshalBlindRSASPKIWithBody(t, []byte{0xff, 0xff})
		if _, err := parseBlindRSA2048PublicKey(keyDER); err == nil {
			t.Fatal("parseBlindRSA2048PublicKey accepted a malformed key body")
		}
	})
	t.Run("trailing key body bytes", func(t *testing.T) {
		// A valid {N, E} body plus a trailing byte leaves rest != 0 in the second Unmarshal.
		validBody, err := asn1.Marshal(struct {
			N *big.Int
			E int
		}{N: big.NewInt(12345), E: 65537})
		if err != nil {
			t.Fatal(err)
		}
		keyDER := marshalBlindRSASPKIWithBody(t, append(validBody, 0x00))
		if _, err := parseBlindRSA2048PublicKey(keyDER); err == nil {
			t.Fatal("parseBlindRSA2048PublicKey accepted trailing key body bytes")
		}
	})
	t.Run("wrong key size", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
		if _, err := parseBlindRSA2048PublicKey(keyDER); err == nil {
			t.Fatal("parseBlindRSA2048PublicKey accepted a non-2048-bit key")
		}
	})
	t.Run("bad exponent", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv.PublicKey.E = 2 // even
		keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
		if _, err := parseBlindRSA2048PublicKey(keyDER); err == nil {
			t.Fatal("parseBlindRSA2048PublicKey accepted an even public exponent")
		}
	})
}

func TestRequireBindingPolicyAllowsProofAdversarial(t *testing.T) {
	proof := protocol.AdmissionProof{ProofType: registry.ProofBlindRSA2048}
	t.Run("non-matching proof type is skipped", func(t *testing.T) {
		// A policy for a different proof type is skipped; with no matching policy the
		// function returns nil (no binding requirement applies).
		policies := []protocol.AuxiliaryBindingPolicy{{ProofType: registry.ProofVOPRFP384SHA384, BindingProofRequired: true}}
		if err := requireBindingPolicyAllowsProof(protocol.IssuerMetadata{AuxiliaryBindingPolicies: policies}, proof); err != nil {
			t.Fatalf("requireBindingPolicyAllowsProof rejected a proof with no applicable policy: %v", err)
		}
	})
	t.Run("missing required binding proof", func(t *testing.T) {
		policies := []protocol.AuxiliaryBindingPolicy{{ProofType: registry.ProofBlindRSA2048, BindingProofRequired: true, MaxBindingProofLen: 32}}
		if err := requireBindingPolicyAllowsProof(protocol.IssuerMetadata{AuxiliaryBindingPolicies: policies}, proof); err == nil {
			t.Fatal("requireBindingPolicyAllowsProof accepted a missing required binding proof")
		}
	})
	t.Run("overlong binding proof", func(t *testing.T) {
		overlong := protocol.AdmissionProof{ProofType: registry.ProofBlindRSA2048, BindingProof: bytes.Repeat([]byte{0x01}, 33)}
		policies := []protocol.AuxiliaryBindingPolicy{{ProofType: registry.ProofBlindRSA2048, BindingProofRequired: true, MaxBindingProofLen: 32}}
		if err := requireBindingPolicyAllowsProof(protocol.IssuerMetadata{AuxiliaryBindingPolicies: policies}, overlong); err == nil {
			t.Fatal("requireBindingPolicyAllowsProof accepted an overlong binding proof")
		}
	})
}

func TestOriginAllowedByScopeAdversarial(t *testing.T) {
	policies := []protocol.OriginInfoPolicy{{
		PolicyID:             7,
		OriginInfo:           []byte("origin.example"),
		AllowEmptyOriginInfo: false,
		ValidFromUnix:        10,
		ValidUntilUnix:       200,
	}}
	t.Run("policy id not allowed", func(t *testing.T) {
		if originAllowedByScope(policies, []uint64{99}, []byte("origin.example"), 100) {
			t.Fatal("originAllowedByScope allowed a policy id not in the allowed set")
		}
	})
	t.Run("policy outside time window", func(t *testing.T) {
		if originAllowedByScope(policies, []uint64{7}, []byte("origin.example"), 999) {
			t.Fatal("originAllowedByScope allowed a policy outside its time window")
		}
	})
	t.Run("empty origin with allow flag", func(t *testing.T) {
		emptyPolicies := []protocol.OriginInfoPolicy{{
			PolicyID:             7,
			OriginInfo:           []byte("origin.example"),
			AllowEmptyOriginInfo: true,
			ValidFromUnix:        10,
			ValidUntilUnix:       200,
		}}
		if !originAllowedByScope(emptyPolicies, []uint64{7}, []byte{}, 100) {
			t.Fatal("originAllowedByScope rejected an empty origin with AllowEmptyOriginInfo set")
		}
	})
}

func TestRequireOriginAllowedRejectsExpiredMatchingScope(t *testing.T) {
	// A scope that matches the proof's relay bucket and token scope but is outside its
	// validity window at `now` is skipped, leaving no authorized scope.
	metadata := protocol.IssuerMetadata{
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         rep(0x32, 16),
			TokenScopeID:          rep(0x33, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:          10,
			ValidUntilUnix:         50, // expired at now=100
		}},
	}
	proof := protocol.AdmissionProof{RelayBucketID: rep(0x32, 16), TokenScopeID: rep(0x33, 16)}
	if err := requireOriginAllowed(metadata, proof, []byte("origin.example"), 100); err == nil {
		t.Fatal("requireOriginAllowed authorized a proof against an expired matching scope")
	}
}

// validBlindRSATokenMetadataForCoverage builds the AuroraTokenMetadata that
// signedBlindRSAProofForTest embeds in the proof, so perturbed copies stay consistent
// with the proof's issuer/origin/key-id.
func validBlindRSATokenMetadataForCoverage(t *testing.T, proof protocol.AdmissionProof) protocol.AuroraTokenMetadata {
	t.Helper()
	challengeDigest, err := RFC9577TokenChallengeDigest(proof.ProofType, []byte("issuer.example"), []byte("origin.example"), proof.RedemptionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest:  challengeDigest,
		RFC9577TokenKeyID:        append([]byte(nil), proof.TokenKeyID...),
		IssuerName:               []byte("issuer.example"),
		OriginInfo:               []byte("origin.example"),
		IssuerMetadataHash:       rep(0x36, 48),
	}
}

// blindRSAProofWithMetadataForCoverage replaces a proof's public metadata with an
// encoded AuroraTokenMetadata, keeping the fixture's 256-byte authenticator and
// matching key id so earlier VerifyBlindRSA2048 checks still pass.
func blindRSAProofWithMetadataForCoverage(t *testing.T, base protocol.AdmissionProof, tm protocol.AuroraTokenMetadata) protocol.AdmissionProof {
	t.Helper()
	p := base
	var err error
	p.TokenPublicMetadata, err = protocol.Encode(tm)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyBlindRSA2048RejectsMalformed(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
	base := signedBlindRSAProofForTest(t, priv, keyDER)

	t.Run("invalid proof structure", func(t *testing.T) {
		proof := base
		proof.IssuerID = nil // must be 16 bytes
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted an invalid proof structure")
		}
	})
	t.Run("invalid verification key", func(t *testing.T) {
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: []byte("garbage-key")}).VerifyBlindRSA2048(base); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted a garbage verification key")
		}
	})
	t.Run("token key id mismatch", func(t *testing.T) {
		// proof.TokenKeyID must DISAGREE with sha256(keyDER) to fire the key-id check,
		// but the embedded metadata's RFC9577TokenKeyID must AGREE with proof.TokenKeyID
		// so that ValidateStructural's internal ValidateForProof passes first. The
		// mismatch is then caught by VerifyBlindRSA2048's own key-id-vs-key-hash check.
		proof := base
		proof.TokenKeyID = rep(0xff, 32) // != sha256(keyDER)
		tm := validBlindRSATokenMetadataForCoverage(t, proof)
		proof = blindRSAProofWithMetadataForCoverage(t, proof, tm)
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted a mismatched token key id")
		}
	})
	t.Run("authenticator length", func(t *testing.T) {
		proof := base
		proof.TokenAuthenticator = []byte("too-short") // want 256
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted a short authenticator")
		}
	})
	t.Run("undecodable token metadata", func(t *testing.T) {
		proof := base
		proof.TokenPublicMetadata = []byte("not-valid-metadata")
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted undecodable token metadata")
		}
	})
	t.Run("empty issuer name in metadata", func(t *testing.T) {
		tm := validBlindRSATokenMetadataForCoverage(t, base)
		tm.IssuerName = nil
		proof := blindRSAProofWithMetadataForCoverage(t, base, tm)
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted an empty issuer name in token metadata")
		}
	})
	t.Run("token key id mismatch in metadata", func(t *testing.T) {
		tm := validBlindRSATokenMetadataForCoverage(t, base)
		tm.RFC9577TokenKeyID = rep(0x00, 32) // differs from proof.TokenKeyID
		proof := blindRSAProofWithMetadataForCoverage(t, base, tm)
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted a token key id mismatch in metadata")
		}
	})
	t.Run("challenge digest mismatch", func(t *testing.T) {
		tm := validBlindRSATokenMetadataForCoverage(t, base)
		tm.RFC9577ChallengeDigest = rep(0xff, 32) // wrong digest
		proof := blindRSAProofWithMetadataForCoverage(t, base, tm)
		if err := (BlindRSA2048Verifier{TokenVerificationKeyDER: keyDER}).VerifyBlindRSA2048(proof); err == nil {
			t.Fatal("VerifyBlindRSA2048 accepted a mismatched challenge digest")
		}
	})
}

func TestVerifyBlindRSA2048WithIssuerMetadataRejectsMalformed(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
	proof := signedBlindRSAProofForTest(t, priv, keyDER)
	metadata := blindRSAIssuerMetadataForTest(proof, keyDER)

	t.Run("wrong proof type", func(t *testing.T) {
		p := proof
		p.ProofType = registry.ProofVOPRFP384SHA384
		if err := VerifyBlindRSA2048WithIssuerMetadata(p, metadata, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted a wrong proof type")
		}
	})
	t.Run("invalid metadata structure", func(t *testing.T) {
		m := metadata
		m.ValidUntilUnix = 50 // now=100 >= 50 -> outside validity interval
		if err := VerifyBlindRSA2048WithIssuerMetadata(proof, m, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted invalid metadata structure")
		}
	})
	t.Run("issuer id mismatch", func(t *testing.T) {
		m := metadata
		m.IssuerID = rep(0xfe, 16) // differs from proof.IssuerID
		if err := VerifyBlindRSA2048WithIssuerMetadata(proof, m, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted an issuer id mismatch")
		}
	})
	t.Run("unsupported proof type", func(t *testing.T) {
		m := metadata
		m.SupportedProofTypes = []uint64{registry.ProofVOPRFP384SHA384} // does not contain Blind RSA
		if err := VerifyBlindRSA2048WithIssuerMetadata(proof, m, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted an unsupported proof type")
		}
	})
	t.Run("overlong issuer name", func(t *testing.T) {
		m := metadata
		m.IssuerName = bytes.Repeat([]byte("x"), overlongOpaqueCoverage) // WriteOpaque16 fails in IssuerMetadataHash
		if err := VerifyBlindRSA2048WithIssuerMetadata(proof, m, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted an overlong issuer name")
		}
	})
	t.Run("undecodable token metadata", func(t *testing.T) {
		bound := bindProofToIssuerMetadataForTest(t, proof, metadata)
		bound.TokenPublicMetadata = []byte("not-valid-metadata")
		if err := VerifyBlindRSA2048WithIssuerMetadata(bound, metadata, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted undecodable token metadata")
		}
	})
	t.Run("stale issuer metadata hash", func(t *testing.T) {
		// The un-bound proof carries a placeholder IssuerMetadataHash that does not match
		// the real metadata hash, so ValidateForProof fails.
		if err := VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted a stale issuer metadata hash")
		}
	})
	t.Run("issuer name mismatch", func(t *testing.T) {
		m := metadata
		m.IssuerName = []byte("other.example") // differs from the proof's embedded issuer name
		bound := bindProofToIssuerMetadataForTest(t, proof, m)
		if err := VerifyBlindRSA2048WithIssuerMetadata(bound, m, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted an issuer name mismatch")
		}
	})
	t.Run("missing required binding proof", func(t *testing.T) {
		m := metadata
		m.AuxiliaryBindingPolicies = []protocol.AuxiliaryBindingPolicy{{
			ProofType:           registry.ProofBlindRSA2048,
			BindingProofRequired: true,
			MaxBindingProofLen:   32,
		}}
		bound := bindProofToIssuerMetadataForTest(t, proof, m)
		if err := VerifyBlindRSA2048WithIssuerMetadata(bound, m, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted a missing required binding proof")
		}
	})
	t.Run("expired token key", func(t *testing.T) {
		m := metadata
		m.TokenKeyMappings[0].ValidUntilUnix = 50 // expired at now=100
		bound := bindProofToIssuerMetadataForTest(t, proof, m)
		if err := VerifyBlindRSA2048WithIssuerMetadata(bound, m, 100); err == nil {
			t.Fatal("VerifyBlindRSA2048WithIssuerMetadata accepted an expired token key")
		}
	})
}