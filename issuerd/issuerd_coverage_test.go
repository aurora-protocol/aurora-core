package issuerd

// Adversarial coverage for the pure validation/utility functions in issuerd
// (service.go, production_service.go, http.go) that the existing
// service_test.go / http_test.go / production_service_test.go do not reach.
// Every case crafts a minimal input (or reuses the existing fill /
// mustIssuerMetadataHash helpers) and asserts the boolean/error response, with
// no live TLS server, signature, or harness service required where the
// rejection branch fires before any of that.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// Dead by design (documented, not contrived):
//   - certificateECDSAKeyMatchesRecord:706-707 (pk.Bytes error) and 711-712
//     (x509.MarshalPKIXPublicKey error): both encoders only fail on a malformed
//     *ecdsa.PublicKey, but the function only reaches them after confirming
//     cert.PublicKey is a non-nil *ecdsa.PublicKey whose Curve matches the
//     expected curve (697-699). A valid ECDSA public key's Bytes()/
//     MarshalPKIXPublicKey cannot error, so these returns are unreachable.
//   - marshalRSAPSSPublicKey:818-820 and the second Marshal's error path:
//     asn1.Marshal of a plain {N *big.Int, E int} then a SPKI-shaped struct
//     cannot fail for the real *rsa.PublicKey the harness passes (callers only
//     invoke it with rsa.GenerateKey output). Documented, not contrived.
//   - cloneRSAPrivateKey:96-98 (ParsePKCS1PrivateKey error) and 99-101
//     (cloned.Validate error): x509.MarshalPKCS1PrivateKey of a valid key
//     always round-trips through ParsePKCS1PrivateKey and Validate, so both
//     error returns are unreachable for the real keys the issuer uses.
//   - cloneIssuerMetadata:112-114 (reader.Err or !EOF after round-trip):
//     Encode produces a canonical byte stream that DecodeIssuerMetadata
//     consumes to exactly EOF for any metadata that Encode accepts, so the
//     post-decode integrity check never trips. (The Encode-error branch at
//     107-109 IS reachable via a malformed metadata and is covered below.)
//   - hasUsableTokenKey:667-668 (currentUnix()==0): ServiceOptions exposes no
//     clock override, and NewHarnessService backfills validity windows around
//     the supplied now, so a zero clock cannot be produced without breaking
//     harness construction; left to the harness/production tests.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

// validIssuerVerifierRequestForCoverage returns an IssuerVerifierRequest that
// passes every validateIssuerVerifierRequestShape check, so a single-field
// perturbation reaches one specific error branch. Field lengths follow
// expectedVerifierRequestFieldLength (service.go:654-663).
func validIssuerVerifierRequestForCoverage() protocol.IssuerVerifierRequest {
	return protocol.IssuerVerifierRequest{
		RequestVersion:            registry.Version20,
		ServiceID:                 fill(0x10, 16),
		IssuerID:                  fill(0x11, 16),
		IssuerMetadataHash:        fill(0x12, 48),
		RelayDescriptorHash:       fill(0x13, 48),
		RelayBucketID:             fill(0x14, 16),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ProofType:                 registry.ProofVOPRFP384SHA384,
		TokenKeyID:                fill(0x15, 32),
		TokenNonce:                fill(0x16, 32),
		ChallengeDigest:           fill(0x17, 32),
		AuthenticatorInputHash:    fill(0x18, 48),
		TokenAuthenticator:        []byte("private-voprf-authenticator"),
		TokenSpentKey:             fill(0x19, 48),
		ReplayEpochID:             11,
		ReplayEpochValidUntilUnix: 400,
		RequestNonce:              fill(0x1a, 32),
		RequestTimeUnix:           200,
	}
}

func TestValidateIssuerVerifierRequestShapeRejectsEachMalformedField(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(req *protocol.IssuerVerifierRequest)
	}{
		{"unsupported version", func(r *protocol.IssuerVerifierRequest) { r.RequestVersion = 0 }},
		{"service id wrong length", func(r *protocol.IssuerVerifierRequest) { r.ServiceID = fill(0x10, 15) }},
		{"issuer id wrong length", func(r *protocol.IssuerVerifierRequest) { r.IssuerID = fill(0x11, 17) }},
		{"relay bucket id wrong length", func(r *protocol.IssuerVerifierRequest) { r.RelayBucketID = fill(0x14, 8) }},
		{"token nonce wrong length", func(r *protocol.IssuerVerifierRequest) { r.TokenNonce = fill(0x16, 31) }},
		{"challenge digest wrong length", func(r *protocol.IssuerVerifierRequest) { r.ChallengeDigest = fill(0x17, 33) }},
		{"request nonce wrong length", func(r *protocol.IssuerVerifierRequest) { r.RequestNonce = fill(0x1a, 16) }},
		{"token key id wrong length", func(r *protocol.IssuerVerifierRequest) { r.TokenKeyID = fill(0x15, 30) }},
		{"authenticator input hash wrong length", func(r *protocol.IssuerVerifierRequest) { r.AuthenticatorInputHash = fill(0x18, 47) }},
		{"issuer metadata hash wrong length", func(r *protocol.IssuerVerifierRequest) { r.IssuerMetadataHash = fill(0x12, 49) }},
		{"relay descriptor hash wrong length", func(r *protocol.IssuerVerifierRequest) { r.RelayDescriptorHash = fill(0x13, 16) }},
		{"token spent key wrong length", func(r *protocol.IssuerVerifierRequest) { r.TokenSpentKey = fill(0x19, 32) }},
		{"non-VOPRF proof type", func(r *protocol.IssuerVerifierRequest) { r.ProofType = registry.ProofBlindRSA2048 }},
		{"empty token authenticator", func(r *protocol.IssuerVerifierRequest) { r.TokenAuthenticator = nil }},
		{"zero replay epoch expiry", func(r *protocol.IssuerVerifierRequest) { r.ReplayEpochValidUntilUnix = 0 }},
		{"zero request time", func(r *protocol.IssuerVerifierRequest) { r.RequestTimeUnix = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validIssuerVerifierRequestForCoverage()
			tc.mutate(&req)
			if err := validateIssuerVerifierRequestShape(req); err == nil {
				t.Fatalf("validateIssuerVerifierRequestShape accepted %s", tc.name)
			}
		})
	}
}

func TestValidateIssuerVerifierRequestShapeAcceptsWellFormed(t *testing.T) {
	if err := validateIssuerVerifierRequestShape(validIssuerVerifierRequestForCoverage()); err != nil {
		t.Fatalf("well-formed verifier request rejected: %v", err)
	}
}

func TestValidateProductionBlindRSAMetadataRejectsInvalidLayouts(t *testing.T) {
	t.Run("advertises verifier services", func(t *testing.T) {
		// SupportedProofTypes is the single-Blind-RSA happy layout, so the only
		// failing check is the non-empty VerifierServices at line 135.
		metadata := protocol.IssuerMetadata{
			SupportedProofTypes: []uint64{registry.ProofBlindRSA2048},
			VerifierServices:    []protocol.IssuerVerifierServiceRecord{{ServiceID: fill(0x01, 16)}},
		}
		if err := validateProductionBlindRSAMetadata(metadata); err == nil {
			t.Fatal("validateProductionBlindRSAMetadata accepted metadata advertising verifier services")
		}
	})
	t.Run("empty supported proof types", func(t *testing.T) {
		// len(SupportedProofTypes) != 1 -> line 138; the loop finds no VOPRF ->
		// line 144 ("must support only Blind RSA").
		metadata := protocol.IssuerMetadata{SupportedProofTypes: nil}
		if err := validateProductionBlindRSAMetadata(metadata); err == nil {
			t.Fatal("validateProductionBlindRSAMetadata accepted metadata with no supported proof types")
		}
	})
	t.Run("advertises VOPRF", func(t *testing.T) {
		// [VOPRF] has len 1 but [0] != BlindRSA -> line 138; the loop finds VOPRF
		// -> line 141.
		metadata := protocol.IssuerMetadata{SupportedProofTypes: []uint64{registry.ProofVOPRFP384SHA384}}
		if err := validateProductionBlindRSAMetadata(metadata); err == nil {
			t.Fatal("validateProductionBlindRSAMetadata accepted metadata advertising VOPRF")
		}
	})
	t.Run("token key mapping with unsupported proof type", func(t *testing.T) {
		// SupportedProofTypes == [BlindRSA] (line 138 false), but a token key
		// mapping carries VOPRF -> line 147 -> 148.
		metadata := protocol.IssuerMetadata{
			SupportedProofTypes: []uint64{registry.ProofBlindRSA2048},
			TokenKeyMappings:    []protocol.IssuerTokenKeyRecord{{ProofType: registry.ProofVOPRFP384SHA384}},
		}
		if err := validateProductionBlindRSAMetadata(metadata); err == nil {
			t.Fatal("validateProductionBlindRSAMetadata accepted a non-Blind-RSA token key mapping")
		}
	})
}

func TestValidateProductionBlindRSAMetadataAcceptsBlindRSAOnly(t *testing.T) {
	metadata := protocol.IssuerMetadata{
		SupportedProofTypes: []uint64{registry.ProofBlindRSA2048},
		TokenKeyMappings:    []protocol.IssuerTokenKeyRecord{{ProofType: registry.ProofBlindRSA2048}},
	}
	if err := validateProductionBlindRSAMetadata(metadata); err != nil {
		t.Fatalf("Blind-RSA-only metadata rejected: %v", err)
	}
}

// selfSignedECDSACertForCoverage generates and parses a self-signed ECDSA
// certificate on the given curve, returning the parsed *x509.Certificate so
// its .PublicKey is a concrete *ecdsa.PublicKey for the key-matching functions.
func selfSignedECDSACertForCoverage(t *testing.T, curve elliptic.Curve) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "coverage"},
		NotBefore:     time.Unix(0, 0),
		NotAfter:      time.Unix(1<<32, 0),
		KeyUsage:      x509.KeyUsageDigitalSignature,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCertificateMatchesPublicKeyRecord(t *testing.T) {
	p256Cert := selfSignedECDSACertForCoverage(t, elliptic.P256())
	p384Cert := selfSignedECDSACertForCoverage(t, elliptic.P384())
	p256PK := p256Cert.PublicKey.(*ecdsa.PublicKey)
	p384PK := p384Cert.PublicKey.(*ecdsa.PublicKey)
	p256SEC1, err := p256PK.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	p256SPKI, err := x509.MarshalPKIXPublicKey(p256PK)
	if err != nil {
		t.Fatal(err)
	}
	p384SEC1, err := p384PK.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		cert   *x509.Certificate
		scheme uint64
		record protocol.PublicKeyRecord
		want   bool
	}{
		{
			name:   "P256 SHA256 DER via SEC1",
			cert:   p256Cert,
			scheme: registry.SigECDSAP256SHA256DER,
			record: protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA256DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: p256SEC1},
			want:   true,
		},
		{
			name:   "P256 SHA384 DER via SPKI",
			cert:   p256Cert,
			scheme: registry.SigECDSAP256SHA384DER,
			record: protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA384DER, KeyEncoding: registry.KeyP256SPKI, PublicKey: p256SPKI},
			want:   true,
		},
		{
			name:   "P384 SHA384 DER via SEC1",
			cert:   p384Cert,
			scheme: registry.SigECDSAP384SHA384DER,
			record: protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP384SHA384DER, KeyEncoding: registry.KeyP384SEC1Uncompressed, PublicKey: p384SEC1},
			want:   true,
		},
		{
			name:   "unsupported signature scheme",
			cert:   p256Cert,
			scheme: 0x9999,
			record: protocol.PublicKeyRecord{SignatureScheme: 0x9999, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: p256SEC1},
			want:   false,
		},
		{
			name:   "wrong curve for scheme",
			cert:   p256Cert,
			scheme: registry.SigECDSAP384SHA384DER,
			record: protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP384SHA384DER, KeyEncoding: registry.KeyP384SEC1Uncompressed, PublicKey: p384SEC1},
			want:   false,
		},
		{
			name:   "mismatched public key bytes",
			cert:   p256Cert,
			scheme: registry.SigECDSAP256SHA256DER,
			record: protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA256DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: fill(0xff, len(p256SEC1))},
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := certificateMatchesPublicKeyRecord(tc.cert, tc.record)
			if got != tc.want {
				t.Fatalf("certificateMatchesPublicKeyRecord(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestCertificateECDSAKeyMatchesRecordRejectsNilAndUnknownEncoding(t *testing.T) {
	p256Cert := selfSignedECDSACertForCoverage(t, elliptic.P256())
	p256PK := p256Cert.PublicKey.(*ecdsa.PublicKey)
	sec1, err := p256PK.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("nil certificate", func(t *testing.T) {
		if certificateECDSAKeyMatchesRecord(nil, elliptic.P256(), registry.KeyP256SEC1Uncompressed, registry.KeyP256SPKI, protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA256DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: sec1,
		}) {
			t.Fatal("certificateECDSAKeyMatchesRecord accepted a nil certificate")
		}
	})
	t.Run("unknown key encoding", func(t *testing.T) {
		if certificateECDSAKeyMatchesRecord(p256Cert, elliptic.P256(), registry.KeyP256SEC1Uncompressed, registry.KeyP256SPKI, protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA256DER, KeyEncoding: 0x9999, PublicKey: sec1,
		}) {
			t.Fatal("certificateECDSAKeyMatchesRecord accepted an unknown key encoding")
		}
	})
	t.Run("wrong curve", func(t *testing.T) {
		// P256 cert evaluated against the P384 curve -> pk.Curve != curve.
		if certificateECDSAKeyMatchesRecord(p256Cert, elliptic.P384(), registry.KeyP384SEC1Uncompressed, registry.KeyP384SPKI, protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP384SHA384DER, KeyEncoding: registry.KeyP384SEC1Uncompressed, PublicKey: sec1,
		}) {
			t.Fatal("certificateECDSAKeyMatchesRecord accepted a certificate on the wrong curve")
		}
	})
}

// encodeTokenMetadataForCoverage serializes an AuroraTokenMetadata via the same
// wire encoder the production decoder reads, so tokenMetadataMatchesIssuerMetadata
// can decode it cleanly.
func encodeTokenMetadataForCoverage(t *testing.T, m protocol.AuroraTokenMetadata) []byte {
	t.Helper()
	e := wire.NewEncoder()
	m.EncodeTo(e)
	encoded, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestTokenMetadataMatchesIssuerMetadata(t *testing.T) {
	harness, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	metadata := harness.PublishIssuerMetadata()
	metadataHash := mustIssuerMetadataHash(t, metadata)

	t.Run("matching metadata hash", func(t *testing.T) {
		encoded := encodeTokenMetadataForCoverage(t, protocol.AuroraTokenMetadata{
			RFC9577TokenType:       uint16(registry.ProofVOPRFP384SHA384),
			RFC9577ChallengeDigest: fill(0x01, 32),
			RFC9577TokenKeyID:       fill(0x02, 32),
			IssuerName:              []byte("issuer.example"),
			OriginInfo:              []byte("origin.example"),
			IssuerMetadataHash:       metadataHash,
		})
		proof := protocol.AdmissionProof{TokenPublicMetadata: encoded}
		if !tokenMetadataMatchesIssuerMetadata(proof, metadata) {
			t.Fatal("tokenMetadataMatchesIssuerMetadata rejected a matching metadata hash")
		}
	})
	t.Run("mismatched metadata hash", func(t *testing.T) {
		encoded := encodeTokenMetadataForCoverage(t, protocol.AuroraTokenMetadata{
			RFC9577TokenType:       uint16(registry.ProofVOPRFP384SHA384),
			RFC9577ChallengeDigest: fill(0x01, 32),
			RFC9577TokenKeyID:       fill(0x02, 32),
			IssuerName:              []byte("issuer.example"),
			OriginInfo:              []byte("origin.example"),
			IssuerMetadataHash:       fill(0xee, 48),
		})
		proof := protocol.AdmissionProof{TokenPublicMetadata: encoded}
		if tokenMetadataMatchesIssuerMetadata(proof, metadata) {
			t.Fatal("tokenMetadataMatchesIssuerMetadata accepted a mismatched metadata hash")
		}
	})
	t.Run("undecodable token metadata", func(t *testing.T) {
		// A single byte cannot satisfy ReadUint16 -> DecodeAuroraTokenMetadataBytes
		// errors -> line 782-783.
		proof := protocol.AdmissionProof{TokenPublicMetadata: []byte{0xff}}
		if tokenMetadataMatchesIssuerMetadata(proof, metadata) {
			t.Fatal("tokenMetadataMatchesIssuerMetadata accepted undecodable token metadata")
		}
	})
	t.Run("issuer metadata hash computation fails", func(t *testing.T) {
		// Token metadata decodes cleanly, but a malformed IssuerMetadata (IssuerID
		// not 16 bytes) makes auroratrust.IssuerMetadataHash error -> line 786-787.
		encoded := encodeTokenMetadataForCoverage(t, protocol.AuroraTokenMetadata{
			RFC9577TokenType:       uint16(registry.ProofVOPRFP384SHA384),
			RFC9577ChallengeDigest: fill(0x01, 32),
			RFC9577TokenKeyID:       fill(0x02, 32),
			IssuerName:              []byte("issuer.example"),
			OriginInfo:              []byte("origin.example"),
			IssuerMetadataHash:       metadataHash,
		})
		proof := protocol.AdmissionProof{TokenPublicMetadata: encoded}
		malformed := protocol.IssuerMetadata{IssuerID: []byte("too-short")}
		if tokenMetadataMatchesIssuerMetadata(proof, malformed) {
			t.Fatal("tokenMetadataMatchesIssuerMetadata accepted a metadata whose hash fails to compute")
		}
	})
}

func TestSelectProductionIssuanceScopeRejectsInvalidSelection(t *testing.T) {
	bucket := fill(0x81, 16)
	inWindow := func(from, until uint64) protocol.RelayBucketScope {
		return protocol.RelayBucketScope{
			RelayBucketID:         bucket,
			TokenScopeID:          fill(0x82, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:         from,
			ValidUntilUnix:        until,
		}
	}
	t.Run("relay bucket id not 16 bytes", func(t *testing.T) {
		metadata := protocol.IssuerMetadata{RelayBucketScopes: []protocol.RelayBucketScope{inWindow(100, 900)}}
		if _, _, err := selectProductionIssuanceScope(metadata, fill(0x81, 15), 7, 200); err == nil {
			t.Fatal("selectProductionIssuanceScope accepted a 15-byte relay bucket id")
		}
	})
	t.Run("zero origin info policy id", func(t *testing.T) {
		metadata := protocol.IssuerMetadata{RelayBucketScopes: []protocol.RelayBucketScope{inWindow(100, 900)}}
		if _, _, err := selectProductionIssuanceScope(metadata, bucket, 0, 200); err == nil {
			t.Fatal("selectProductionIssuanceScope accepted a zero origin-info policy id")
		}
	})
	t.Run("no matching scope", func(t *testing.T) {
		// The only scope is for a different bucket -> zero matches -> line 194-195.
		other := protocol.IssuerMetadata{RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         fill(0x99, 16),
			TokenScopeID:          fill(0x82, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:          100,
			ValidUntilUnix:         900,
		}}}
		if _, _, err := selectProductionIssuanceScope(other, bucket, 7, 200); err == nil {
			t.Fatal("selectProductionIssuanceScope accepted a request with no matching scope")
		}
	})
	t.Run("scope out of validity window", func(t *testing.T) {
		// Bucket matches but now is outside the scope window -> continue -> zero
		// matches -> line 194-195 (exercises the out-of-window continue).
		metadata := protocol.IssuerMetadata{RelayBucketScopes: []protocol.RelayBucketScope{inWindow(300, 900)}}
		if _, _, err := selectProductionIssuanceScope(metadata, bucket, 7, 200); err == nil {
			t.Fatal("selectProductionIssuanceScope accepted an out-of-window scope")
		}
	})
	t.Run("origin info policy out of validity window", func(t *testing.T) {
		// Exactly one matching scope, but the only origin-info policy for id 7 is
		// outside the window -> policies empty -> line 204-205.
		metadata := protocol.IssuerMetadata{
			RelayBucketScopes:  []protocol.RelayBucketScope{inWindow(100, 900)},
			OriginInfoPolicies: []protocol.OriginInfoPolicy{{PolicyID: 7, OriginInfo: []byte("origin.example"), ValidFromUnix: 300, ValidUntilUnix: 900}},
		}
		if _, _, err := selectProductionIssuanceScope(metadata, bucket, 7, 200); err == nil {
			t.Fatal("selectProductionIssuanceScope accepted a scope whose origin-info policy is out of window")
		}
	})
	t.Run("origin info policy id absent", func(t *testing.T) {
		// One matching scope, but no origin-info policy carries id 7 -> policies
		// empty -> line 204-205 (exercises the policy-id-miss path).
		metadata := protocol.IssuerMetadata{
			RelayBucketScopes:  []protocol.RelayBucketScope{inWindow(100, 900)},
			OriginInfoPolicies: []protocol.OriginInfoPolicy{{PolicyID: 99, OriginInfo: []byte("other"), ValidFromUnix: 100, ValidUntilUnix: 900}},
		}
		if _, _, err := selectProductionIssuanceScope(metadata, bucket, 7, 200); err == nil {
			t.Fatal("selectProductionIssuanceScope accepted a scope with no matching origin-info policy id")
		}
	})
}

func TestSelectProductionIssuanceScopeAcceptsUniqueMatch(t *testing.T) {
	bucket := fill(0x81, 16)
	metadata := protocol.IssuerMetadata{
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         bucket,
			TokenScopeID:          fill(0x82, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:         100,
			ValidUntilUnix:        900,
		}},
		OriginInfoPolicies: []protocol.OriginInfoPolicy{{
			PolicyID:      7,
			OriginInfo:    []byte("origin.example"),
			ValidFromUnix: 100,
			ValidUntilUnix: 900,
		}},
	}
	scope, originInfo, err := selectProductionIssuanceScope(metadata, bucket, 7, 200)
	if err != nil {
		t.Fatalf("unique matching scope rejected: %v", err)
	}
	if !bytes.Equal(scope.RelayBucketID, bucket) {
		t.Fatalf("returned scope relay bucket id = %x, want %x", scope.RelayBucketID, bucket)
	}
	if string(originInfo) != "origin.example" {
		t.Fatalf("returned origin info = %q, want %q", originInfo, "origin.example")
	}
}

func TestDecodeHexFixedRejectsMalformed(t *testing.T) {
	t.Run("invalid hex", func(t *testing.T) {
		if _, err := decodeHexFixed("zz", 1); err == nil {
			t.Fatal("decodeHexFixed accepted non-hex characters")
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		if _, err := decodeHexFixed("0102", 1); err == nil {
			t.Fatal("decodeHexFixed accepted a 2-byte value for a 1-byte field")
		}
	})
}

func TestDecodeHexFixedAcceptsValid(t *testing.T) {
	t.Run("exact length", func(t *testing.T) {
		decoded, err := decodeHexFixed("0102", 2)
		if err != nil {
			t.Fatalf("decodeHexFixed(0102,2) returned err: %v", err)
		}
		if want := []byte{0x01, 0x02}; !bytes.Equal(decoded, want) {
			t.Fatalf("decodeHexFixed(0102,2) = %x, want %x", decoded, want)
		}
	})
	t.Run("empty for zero length", func(t *testing.T) {
		if _, err := decodeHexFixed("", 0); err != nil {
			t.Fatalf("decodeHexFixed(\"\",0) returned err: %v", err)
		}
	})
}

func TestLogLineHasRedactions(t *testing.T) {
	allMarkers := "[redacted:admission-proof:] x [redacted:token-authenticator:] y [redacted:hint-secret:] z [redacted:capsule-plaintext:]"
	t.Run("all markers present", func(t *testing.T) {
		if !logLineHasRedactions(allMarkers) {
			t.Fatal("logLineHasRedactions rejected a line containing every redaction marker")
		}
	})
	t.Run("missing one marker", func(t *testing.T) {
		missing := "[redacted:admission-proof:] x [redacted:token-authenticator:] y [redacted:hint-secret:]"
		if logLineHasRedactions(missing) {
			t.Fatal("logLineHasRedactions accepted a line missing a redaction marker")
		}
	})
	t.Run("empty line", func(t *testing.T) {
		if logLineHasRedactions("") {
			t.Fatal("logLineHasRedactions accepted an empty line")
		}
	})
}

func TestContainsUint64(t *testing.T) {
	values := []uint64{1, 2, 3}
	if !containsUint64(values, 2) {
		t.Fatal("containsUint64 failed to find a present value")
	}
	if containsUint64(values, 99) {
		t.Fatal("containsUint64 found an absent value")
	}
	if containsUint64(nil, 1) {
		t.Fatal("containsUint64 found a value in a nil slice")
	}
}

func TestCloneIssuerMetadataRejectsMalformedMetadata(t *testing.T) {
	// IssuerID is not 16 bytes, so protocol.Encode(metadata.Unsigned()) errors
	// at WriteOpaqueFixed -> line 107-109. This is the reachable Encode-error
	// branch; the post-decode EOF check (112-114) is dead by design (see header).
	if _, err := cloneIssuerMetadata(protocol.IssuerMetadata{IssuerID: []byte("too-short")}); err == nil {
		t.Fatal("cloneIssuerMetadata accepted a metadata whose encoding fails")
	}
}

func TestCloneIssuerMetadataRoundTripsValidMetadata(t *testing.T) {
	harness, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := cloneIssuerMetadata(harness.PublishIssuerMetadata())
	if err != nil {
		t.Fatalf("cloneIssuerMetadata rejected valid harness metadata: %v", err)
	}
	if cloned.IssuerID == nil {
		t.Fatal("cloneIssuerMetadata returned a metadata with a nil IssuerID")
	}
}