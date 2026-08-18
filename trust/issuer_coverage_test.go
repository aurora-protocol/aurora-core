package trust

// Adversarial coverage for trust/issuer.go. The existing issuer_test.go covers
// the happy paths and several rejection cases; this file targets the remaining
// reachable error branches.
//
// Two branches are dead-by-design and intentionally left uncovered:
//
//   - IssuerMetadataSignatureInput e.Bytes() error (lines 34-36): the signature
//     input encoder writes the same fixed-length IssuerID/MetadataSigningKeyID
//     fields that the preceding successful IssuerMetadataHash already encoded,
//     plus a 48-byte PreHash and two varints. If IssuerMetadataHash succeeded,
//     none of those writes can fail, so e.Bytes() cannot return an error here.
//     There is no independently-controlled input on this path (unlike
//     DirectoryConsensusSignatureInput, where the entry's AuthorityID is a
//     separate argument).
//
//   - IssuerVerifierRequestHash wire.EncodeWithCapacity error (lines 108-110):
//     EncodedLen returns known=true only after verifying every fixed field
//     length, the TokenAuthenticator opaque16 bound, and all varint lengths.
//     Those are exactly the writes EncodeTo performs, so a known encoded length
//     guarantees a successful encode -- the error branch is unreachable.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// validIssuerMetadata returns a structurally-valid IssuerMetadata (ECDSA P-256,
// no verifier services, no extensions) that passes ValidateStructural for any
// now in [100,300). Used as the base for adversarial mutants.
func validIssuerMetadata() protocol.IssuerMetadata {
	return protocol.IssuerMetadata{
		MetadataVersion:      registry.Version20,
		IssuerID:             rb(0x20, 16),
		ValidFromUnix:        100,
		ValidUntilUnix:       300,
		IssuerName:           []byte("issuer.example"),
		SupportedProofTypes:  []uint64{registry.ProofBlindRSA2048},
		MetadataSigningKeyID: rb(0x21, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
}

func mustGenerateECDSAP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// --- IssuerMetadata hash + signature input ---

func TestIssuerMetadataHashRejectsMalformedMetadata(t *testing.T) {
	m := validIssuerMetadata()
	m.IssuerID = rb(0x20, 15) // WriteOpaqueFixed(IssuerID,16) wants 16
	if _, err := IssuerMetadataHash(m); err == nil {
		t.Fatal("malformed issuer metadata accepted by IssuerMetadataHash")
	}
}

func TestIssuerMetadataSignatureInputRejectsMalformedMetadata(t *testing.T) {
	m := validIssuerMetadata()
	m.IssuerID = rb(0x20, 15)
	if _, err := IssuerMetadataSignatureInput(m); err == nil {
		t.Fatal("malformed issuer metadata accepted by IssuerMetadataSignatureInput")
	}
}

// --- VerifyIssuerMetadataSignature propagation ---

func TestVerifyIssuerMetadataSignaturePropagatesServiceAuthKeySeparationFailure(t *testing.T) {
	priv := mustGenerateECDSAP256(t)
	reusedKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       mustECDSAPublicKeyBytes(t, &priv.PublicKey),
	}
	m := validIssuerMetadata()
	m.VerifierServices = []protocol.IssuerVerifierServiceRecord{{
		ServiceID:             rb(0x10, 16),
		ServiceKind:           registry.VerifierServiceKindVOPRF,
		ServiceProtocolID:     registry.IssuerVerifierVOPRFMTLS13,
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{rb(0x11, 16)},
		RequestAuthPolicyID:   1,
		ValidFromUnix:         100,
		ValidUntilUnix:        300,
		ServiceStatus:         registry.IssuerStatusActive,
		ServiceAuthKey:        reusedKey,
	}}
	keys := []protocol.AuthorityKeyRecord{{
		AuthorityID:    rb(0x22, 16),
		AuthorityKeyID: m.MetadataSigningKeyID,
		PublicKey:      reusedKey,
		ValidFromUnix:  90,
		ValidUntilUnix: 400,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}}
	// ValidateStructural passes (the service is structurally valid), then the
	// separation check rejects the reuse of authority key material.
	if err := VerifyIssuerMetadataSignature(m, keys, 200); err == nil {
		t.Fatal("issuer verifier service reusing authority key accepted")
	}
}

func TestVerifyIssuerMetadataSignaturePropagatesSignatureInputFailure(t *testing.T) {
	// ValidateStructural does not bound IssuerName to the WriteOpaque16 limit,
	// so a hand-constructed metadata with an overlong name passes structural
	// validation but fails to encode. VerifyIssuerMetadataSignature reaches the
	// signature-input call (structural + separation + key lookup all pass), then
	// IssuerMetadataSignatureInput fails because IssuerMetadataHash cannot encode
	// the overlong IssuerName. This documents the structural-validation gap.
	priv := mustGenerateECDSAP256(t)
	m := validIssuerMetadata()
	m.IssuerName = bytes.Repeat([]byte("x"), 70000) // exceeds WriteOpaque16 (65535)
	signingKey := authorityKeyForECDSA(
		t, rb(0x22, 16), m.MetadataSigningKeyID, priv,
		registry.AuthorityActive, registry.UsageMaySignIssuerMetadata)
	signingKey.ValidUntilUnix = 400 // valid at now=200 so key lookup succeeds
	keys := []protocol.AuthorityKeyRecord{signingKey}
	if err := VerifyIssuerMetadataSignature(m, keys, 200); err == nil {
		t.Fatal("overlong issuer name accepted by VerifyIssuerMetadataSignature")
	}
}

// --- LocateAuthorityKeyByID ---

func TestLocateAuthorityKeyByIDAdversarial(t *testing.T) {
	priv := mustGenerateECDSAP256(t)
	key := authorityKeyForECDSA(t, rb(0x22, 16), rb(0x21, 16), priv,
		registry.AuthorityActive, registry.UsageMaySignIssuerMetadata)
	key.PublicKey.SignatureScheme = registry.SigEd25519Lab // KeyID matches, scheme differs

	if _, err := LocateAuthorityKeyByID(
		[]protocol.AuthorityKeyRecord{key}, rb(0x21, 16),
		registry.SigECDSAP256SHA384DER, registry.KeyP256SEC1Uncompressed,
		200, registry.UsageMaySignIssuerMetadata); err == nil {
		t.Fatal("scheme-mismatched authority key accepted by LocateAuthorityKeyByID")
	}
}

// --- ValidateIssuerServiceAuthKeySeparation ---

func TestValidateIssuerServiceAuthKeySeparationAdversarial(t *testing.T) {
	// Incompatible service auth key: Ed25519 scheme with a 31-byte public key
	// fails ValidateCompatibility.
	m := validIssuerMetadata()
	m.VerifierServices = []protocol.IssuerVerifierServiceRecord{{
		ServiceID:         rb(0x10, 16),
		ServiceKind:       registry.VerifierServiceKindVOPRF,
		ServiceProtocolID: registry.IssuerVerifierVOPRFMTLS13,
		AllowedProofTypes: []uint64{registry.ProofVOPRFP384SHA384},
		ValidFromUnix:     100,
		ValidUntilUnix:    300,
		ServiceStatus:     registry.IssuerStatusActive,
		ServiceAuthKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigEd25519Lab,
			KeyEncoding:     registry.KeyEd25519RawPublic,
			PublicKey:       rb(0x33, 31), // Ed25519 wants 32
		},
	}}
	if err := ValidateIssuerServiceAuthKeySeparation(m, nil, 200); err == nil {
		t.Fatal("incompatible verifier service auth key accepted")
	}

	// Expired authority key is skipped (Validate(now,0) fails -> continue), but a
	// second valid key that reuses the service auth key material is still caught.
	priv := mustGenerateECDSAP256(t)
	serviceAuthKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       mustECDSAPublicKeyBytes(t, &priv.PublicKey),
	}
	m2 := validIssuerMetadata()
	m2.VerifierServices = []protocol.IssuerVerifierServiceRecord{{
		ServiceID:             rb(0x10, 16),
		ServiceKind:           registry.VerifierServiceKindVOPRF,
		ServiceProtocolID:     registry.IssuerVerifierVOPRFMTLS13,
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{rb(0x11, 16)},
		RequestAuthPolicyID:   1,
		ValidFromUnix:         100,
		ValidUntilUnix:        300,
		ServiceStatus:         registry.IssuerStatusActive,
		ServiceAuthKey:        serviceAuthKey,
	}}
	// authorityKeyForECDSA sets ValidUntilUnix=30, so this key is already
	// expired at now=200 -> Validate(now,0) fails -> the continue branch runs.
	expired := authorityKeyForECDSA(t, rb(0x22, 16), rb(0x21, 16), priv,
		registry.AuthorityActive, registry.UsageMaySignIssuerMetadata)
	reusing := expired
	reusing.AuthorityID = rb(0x23, 16)
	reusing.PublicKey = serviceAuthKey
	reusing.ValidUntilUnix = 400 // valid at now=200 -> reaches the reuse check
	if err := ValidateIssuerServiceAuthKeySeparation(m2,
		[]protocol.AuthorityKeyRecord{expired, reusing}, 200); err == nil {
		t.Fatal("authority key reuse across an expired peer accepted")
	}
}

// --- AuthenticatorInputHash ---

func TestAuthenticatorInputHash(t *testing.T) {
	input := []byte("authenticator input")
	got := AuthenticatorInputHash(input)
	want := auroracrypto.PreHashLabel("aurora v2.0 authenticator input", input)
	if !bytes.Equal(got, want) {
		t.Fatalf("AuthenticatorInputHash = %x, want %x", got, want)
	}
	if len(got) != 48 {
		t.Fatalf("AuthenticatorInputHash length = %d, want 48", len(got))
	}
}

// --- IssuerVerifierRequestHash ---

func TestIssuerVerifierRequestHashRejectsMalformedRequest(t *testing.T) {
	_, req, _ := issuerVerifierRequestFixture(t)
	req.IssuerID = rb(0x12, 15) // EncodedLen wants 16
	if _, err := IssuerVerifierRequestHash(req); err == nil {
		t.Fatal("malformed issuer verifier request accepted")
	}
}

// --- IssuerVerifierResponseSignatureInput ---

func TestIssuerVerifierResponseSignatureInputAdversarial(t *testing.T) {
	_, _, resp := issuerVerifierRequestFixture(t)

	// Wrong-length request hash argument.
	if _, err := IssuerVerifierResponseSignatureInput(rb(0x99, 47), resp); err == nil {
		t.Fatal("wrong-length request hash accepted")
	}

	// Valid 48-byte request hash but a malformed response body: ServiceID is the
	// wrong length, so protocol.Encode(r.Unsigned()) fails.
	malformed := resp
	malformed.ServiceID = rb(0x10, 15)
	if _, err := IssuerVerifierResponseSignatureInput(rb(0x99, 48), malformed); err == nil {
		t.Fatal("malformed issuer verifier response accepted")
	}
}

// --- ValidateIssuerVerifierResponseFreshness ---

func TestValidateIssuerVerifierResponseFreshnessAdversarial(t *testing.T) {
	service, req, resp := issuerVerifierRequestFixture(t)

	// Unsupported response version.
	bad := resp
	bad.ResponseVersion = 0
	if err := ValidateIssuerVerifierResponseFreshness(req, service, bad, 220, 300); err == nil {
		t.Fatal("unsupported verifier response version accepted")
	}

	// Service id mismatch.
	bad = resp
	bad.ServiceID = rb(0xee, 16)
	if err := ValidateIssuerVerifierResponseFreshness(req, service, bad, 220, 300); err == nil {
		t.Fatal("mismatched verifier service id accepted")
	}

	// Request hash computation failure: a malformed req (IssuerID wrong length)
	// still has a matching ServiceID, so the service-id check passes and the
	// failure surfaces from IssuerVerifierRequestHash.
	malformedReq := req
	malformedReq.IssuerID = rb(0x12, 15)
	if err := ValidateIssuerVerifierResponseFreshness(malformedReq, service, resp, 220, 300); err == nil {
		t.Fatal("malformed verifier request accepted by freshness check")
	}

	// Request hash mismatch: resp.RequestHash no longer matches the computed hash.
	bad = resp
	bad.RequestHash = rb(0xee, 48)
	if err := ValidateIssuerVerifierResponseFreshness(req, service, bad, 220, 300); err == nil {
		t.Fatal("mismatched verifier request hash accepted")
	}

	// Response expired: now exceeds resp.ValidUntilUnix.
	if err := ValidateIssuerVerifierResponseFreshness(req, service, resp, 300, 300); err == nil {
		t.Fatal("expired verifier response accepted")
	}
}

func TestValidateIssuerVerifierResponseFreshnessLatestAndDefaultWindow(t *testing.T) {
	service, req, resp := issuerVerifierRequestFixture(t)

	// latest collapses to service.ValidUntilUnix when it is earlier than the
	// replay-epoch bound; the response stays within it, so the check passes.
	shortService := service
	shortService.ValidUntilUnix = 500 // < req.ReplayEpochValidUntilUnix (900)
	if err := ValidateIssuerVerifierResponseFreshness(req, shortService, resp, 220, 300); err != nil {
		t.Fatalf("valid response within shortened service window rejected: %v", err)
	}

	// Response exceeds the latest (service/replay) validity bound.
	overlong := resp
	overlong.ValidUntilUnix = 950 // > latest (900)
	if err := ValidateIssuerVerifierResponseFreshness(req, service, overlong, 220, 300); err == nil {
		t.Fatal("verifier response exceeding service/replay validity accepted")
	}

	// maxFreshnessSeconds == 0 defaults to 300; a response within that window is
	// accepted and the default branch is exercised.
	if err := ValidateIssuerVerifierResponseFreshness(req, service, resp, 220, 0); err != nil {
		t.Fatalf("valid response with default freshness window rejected: %v", err)
	}
}

// --- VerifyIssuerVerifierResponse ---

func TestVerifyIssuerVerifierResponseAdversarial(t *testing.T) {
	service, req, resp := issuerVerifierRequestFixture(t)

	// Freshness failure propagation.
	badVersion := resp
	badVersion.ResponseVersion = 0
	if err := VerifyIssuerVerifierResponse(req, service, badVersion, 220, 300); err == nil {
		t.Fatal("freshness failure propagated through VerifyIssuerVerifierResponse")
	}

	// Signature-input failure propagation: freshness passes (ResponseNonce is
	// not checked by freshness) but the response body fails to encode because
	// ResponseNonce is the wrong length.
	badNonce := resp
	badNonce.ResponseNonce = rb(0x1c, 31) // WriteOpaqueFixed(ResponseNonce,32) wants 32
	if err := VerifyIssuerVerifierResponse(req, service, badNonce, 220, 300); err == nil {
		t.Fatal("signature-input failure propagated through VerifyIssuerVerifierResponse")
	}
}
