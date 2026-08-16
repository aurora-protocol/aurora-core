package ops

// Adversarial coverage for the certificate-to-service-auth-key matching
// helpers in verifier_transport.go:
//   - certificatePublicKeyMatchesRecord (line 226, ~16.7% before): the scheme
//     dispatch (ECDSA P256 / P384, Ed25519, default) and the Ed25519 sub-branches
//     (wrong encoding, not-an-Ed25519-public-key, mismatch, happy).
//   - certificateECDSAKeyMatchesRecord (line 249, ~61.1% before): the not-ECDSA,
//     curve-mismatch, unknown-encoding, and sec1-mismatch rejection branches
//     plus the P384 SPKI happy path.
//
// The existing mTLS integration tests (ops_test.go) reach these helpers only
// through a real TLS handshake with a P256 certificate and the SEC1 encoding,
// so every rejection branch and the P384/Ed25519 dispatch arms stay uncovered.
//
// Both helpers are pure: they read only cert.PublicKey (and the record fields),
// so a crafted &x509.Certificate{PublicKey: ...} with an in-memory key suffices
// — no valid signed certificate or TLS fixture is required.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// Dead-by-design (documented, not tested):
//   - pk.Bytes() error branch (line 262): (*ecdsa.PublicKey).Bytes() returns a
//     non-nil error only for curves the stdlib does not support; P256 and P384
//     are always supported, so with the crafted certificates used here the call
//     cannot fail.
//   - x509.MarshalPKIXPublicKey error branch (line 267): marshalling a valid
//     *ecdsa.PublicKey never fails.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestCertificatePublicKeyMatchesRecordDispatchesByScheme(t *testing.T) {
	t.Run("ecdsa p256 sec1 happy", func(t *testing.T) {
		cert := ecdsaCertificateForCoverage(t, elliptic.P256())
		pub := cert.PublicKey.(*ecdsa.PublicKey)
		encoded, err := pub.Bytes()
		if err != nil {
			t.Fatalf("p256 public key bytes: %v", err)
		}
		record := protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA256DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       encoded,
		}
		if err := certificatePublicKeyMatchesRecord(cert, record); err != nil {
			t.Fatalf("p256 sec1 happy: %v", err)
		}
	})
	t.Run("ecdsa p384 spki happy", func(t *testing.T) {
		cert := ecdsaCertificateForCoverage(t, elliptic.P384())
		encoded, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			t.Fatalf("p384 spki marshal: %v", err)
		}
		record := protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP384SHA384DER,
			KeyEncoding:     registry.KeyP384SPKI,
			PublicKey:       encoded,
		}
		if err := certificatePublicKeyMatchesRecord(cert, record); err != nil {
			t.Fatalf("p384 spki happy: %v", err)
		}
	})
	t.Run("ed25519 happy", func(t *testing.T) {
		cert := ed25519CertificateForCoverage(t)
		pub := cert.PublicKey.(ed25519.PublicKey)
		record := protocol.PublicKeyRecord{
			SignatureScheme: registry.SigEd25519Lab,
			KeyEncoding:     registry.KeyEd25519RawPublic,
			PublicKey:       []byte(pub),
		}
		if err := certificatePublicKeyMatchesRecord(cert, record); err != nil {
			t.Fatalf("ed25519 happy: %v", err)
		}
	})
	t.Run("unsupported scheme", func(t *testing.T) {
		cert := ecdsaCertificateForCoverage(t, elliptic.P256())
		record := protocol.PublicKeyRecord{SignatureScheme: 0x0000}
		err := certificatePublicKeyMatchesRecord(cert, record)
		if err == nil || !strings.Contains(err.Error(), "unsupported verifier service signature scheme") {
			t.Fatalf("unsupported scheme err = %v, want substring", err)
		}
	})
}

func TestCertificateECDSAKeyMatchesRecordRejectsEachInvalidCondition(t *testing.T) {
	cases := []struct {
		name       string
		cert       *x509.Certificate
		record     protocol.PublicKeyRecord
		wantSubstr string
	}{
		{
			"not ecdsa public key",
			ed25519CertificateForCoverage(t),
			protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA256DER, KeyEncoding: registry.KeyP256SEC1Uncompressed},
			"certificate public key is not ECDSA",
		},
		{
			"curve mismatch",
			ecdsaCertificateForCoverage(t, elliptic.P256()),
			protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP384SHA384DER, KeyEncoding: registry.KeyP384SEC1Uncompressed},
			"certificate ECDSA curve mismatch",
		},
		{
			"unknown key encoding",
			ecdsaCertificateForCoverage(t, elliptic.P256()),
			protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA256DER, KeyEncoding: 0x9999},
			"ECDSA service key encoding",
		},
		{
			"sec1 mismatch",
			ecdsaCertificateForCoverage(t, elliptic.P256()),
			protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA256DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: []byte("wrong")},
			"does not equal service_auth_key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := certificatePublicKeyMatchesRecord(tc.cert, tc.record)
			if err == nil {
				t.Fatalf("certificatePublicKeyMatchesRecord accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("%s err = %q, want substring %q", tc.name, err, tc.wantSubstr)
			}
		})
	}
}

func TestCertificatePublicKeyMatchesRecordEd25519RejectionBranches(t *testing.T) {
	t.Run("wrong key encoding", func(t *testing.T) {
		cert := ed25519CertificateForCoverage(t)
		record := protocol.PublicKeyRecord{SignatureScheme: registry.SigEd25519Lab, KeyEncoding: registry.KeyP256SEC1Uncompressed}
		err := certificatePublicKeyMatchesRecord(cert, record)
		if err == nil || !strings.Contains(err.Error(), "Ed25519 lab service key encoding") {
			t.Fatalf("wrong encoding err = %v", err)
		}
	})
	t.Run("not ed25519 public key", func(t *testing.T) {
		cert := ecdsaCertificateForCoverage(t, elliptic.P256())
		record := protocol.PublicKeyRecord{SignatureScheme: registry.SigEd25519Lab, KeyEncoding: registry.KeyEd25519RawPublic}
		err := certificatePublicKeyMatchesRecord(cert, record)
		if err == nil || !strings.Contains(err.Error(), "certificate public key is not Ed25519") {
			t.Fatalf("not ed25519 err = %v", err)
		}
	})
	t.Run("public key mismatch", func(t *testing.T) {
		cert := ed25519CertificateForCoverage(t)
		record := protocol.PublicKeyRecord{SignatureScheme: registry.SigEd25519Lab, KeyEncoding: registry.KeyEd25519RawPublic, PublicKey: []byte("wrong")}
		err := certificatePublicKeyMatchesRecord(cert, record)
		if err == nil || !strings.Contains(err.Error(), "does not equal service_auth_key") {
			t.Fatalf("mismatch err = %v", err)
		}
	})
}

// ecdsaCertificateForCoverage returns a minimal x509.Certificate whose
// PublicKey is a freshly generated ECDSA key on the given curve. The
// certificate-key helpers read only cert.PublicKey, so no signing is needed.
func ecdsaCertificateForCoverage(t *testing.T, curve elliptic.Curve) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	return &x509.Certificate{PublicKey: &key.PublicKey}
}

// ed25519CertificateForCoverage returns a minimal x509.Certificate whose
// PublicKey is a freshly generated Ed25519 public key.
func ed25519CertificateForCoverage(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate: %v", err)
	}
	return &x509.Certificate{PublicKey: pub}
}
