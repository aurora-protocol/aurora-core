package auroracrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// TestVerifySignatureEd25519Lab covers the entire Ed25519 lab verification path
// (previously 0%): a valid signature verifies, and each failure mode is
// exercised -- wrong key encoding, wrong public-key length, tampered message,
// and tampered signature.
func TestVerifySignatureEd25519Lab(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	messageDigest := repeated(0xc1, 48)
	sig := ed25519.Sign(priv, messageDigest)

	if err := VerifySignature(registry.SigEd25519Lab, registry.KeyEd25519RawPublic, pub, messageDigest, sig); err != nil {
		t.Fatalf("valid Ed25519 signature rejected: %v", err)
	}
	// Wrong key encoding.
	if err := VerifySignature(registry.SigEd25519Lab, registry.KeyP256SEC1Uncompressed, pub, messageDigest, sig); err == nil {
		t.Fatal("Ed25519 signature accepted with wrong key encoding")
	}
	// Wrong public-key length.
	if err := VerifySignature(registry.SigEd25519Lab, registry.KeyEd25519RawPublic, pub[:ed25519.PublicKeySize-1], messageDigest, sig); err == nil {
		t.Fatal("Ed25519 signature accepted with truncated public key")
	}
	// Tampered message.
	if err := VerifySignature(registry.SigEd25519Lab, registry.KeyEd25519RawPublic, pub, repeated(0xc2, 48), sig); err == nil {
		t.Fatal("Ed25519 signature accepted with tampered message")
	}
	// Tampered signature.
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xff
	if err := VerifySignature(registry.SigEd25519Lab, registry.KeyEd25519RawPublic, pub, messageDigest, badSig); err == nil {
		t.Fatal("Ed25519 signature accepted with tampered signature")
	}
}

// TestVerifySignatureRejectsUnsupportedScheme covers the default branch: an
// unknown signature scheme is rejected regardless of inputs.
func TestVerifySignatureRejectsUnsupportedScheme(t *testing.T) {
	if err := VerifySignature(0xdead, registry.KeyEd25519RawPublic, repeated(0x01, 32), repeated(0x02, 48), repeated(0x03, 64)); err == nil {
		t.Fatal("unsupported signature scheme accepted")
	}
}

// TestVerifySignatureECDSACrossEncoding covers the ECDSA cross-encoding success
// paths: P-256 verified via SPKI and P-384 verified via SEC1 (previously only
// P-256/SEC1 and P-384/SPKI were exercised).
func TestVerifySignatureECDSACrossEncoding(t *testing.T) {
	// P-256 + SPKI.
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256spki, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest256 := repeated(0xa1, 48)
	sig256, err := ecdsa.SignASN1(rand.Reader, p256, digest256)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SPKI, p256spki, digest256, sig256); err != nil {
		t.Fatalf("valid P-256 SPKI signature rejected: %v", err)
	}

	// P-384 + SEC1.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384sec1 := mustECDSAPublicKeyBytes(t, &p384.PublicKey)
	digest384 := repeated(0xa2, 48)
	sig384, err := ecdsa.SignASN1(rand.Reader, p384, digest384)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(registry.SigECDSAP384SHA384DER, registry.KeyP384SEC1Uncompressed, p384sec1, digest384, sig384); err != nil {
		t.Fatalf("valid P-384 SEC1 signature rejected: %v", err)
	}
	// Tampered digest under P-384 -> verify-false branch.
	if err := VerifySignature(registry.SigECDSAP384SHA384DER, registry.KeyP384SEC1Uncompressed, p384sec1, repeated(0xa3, 48), sig384); err == nil {
		t.Fatal("tampered P-384 digest accepted")
	}
}

// TestDecodeECDSAPublicKeySPKIAdversarial covers the two SPKI rejection branches
// of decodeECDSAPublicKey: a non-ECDSA SPKI key ("is not ECDSA") and an ECDSA
// key on the wrong curve ("curve mismatch").
func TestDecodeECDSAPublicKeySPKIAdversarial(t *testing.T) {
	// Non-ECDSA (RSA) SPKI key -> "is not ECDSA".
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSPKI, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SPKI, rsaSPKI, repeated(0xb1, 48), repeated(0xb2, 64)); err == nil {
		t.Fatal("RSA SPKI key accepted for ECDSA verification")
	}

	// ECDSA P-256 key presented to a P-384 scheme -> "curve mismatch".
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256spki, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(registry.SigECDSAP384SHA384DER, registry.KeyP384SPKI, p256spki, repeated(0xb3, 48), repeated(0xb4, 64)); err == nil {
		t.Fatal("P-256 SPKI key accepted for P-384 verification (curve mismatch)")
	}
}

// TestDecodeECDSAPublicKeyMalformedBytes covers the two parse-error branches of
// decodeECDSAPublicKey that the well-formed-key tests cannot reach: a malformed
// SEC1 uncompressed point (ParseUncompressedPublicKey error) and malformed SPKI
// DER (x509.ParsePKIXPublicKey error). The valid-key and wrong-type tests both
// parse successfully and never exercise these error returns.
func TestDecodeECDSAPublicKeyMalformedBytes(t *testing.T) {
	// Malformed SEC1: wrong length for a P-256 uncompressed point (want 65 bytes).
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SEC1Uncompressed, repeated(0x04, 32), repeated(0xb5, 48), repeated(0xb6, 64)); err == nil {
		t.Fatal("malformed SEC1 public key accepted")
	}
	// Malformed SPKI: random bytes are not valid DER.
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SPKI, repeated(0x09, 32), repeated(0xb7, 48), repeated(0xb8, 64)); err == nil {
		t.Fatal("malformed SPKI public key accepted")
	}
}

// TestVerifySignatureMLDSAAdversarial covers the remaining ML-DSA failure
// branches: a malformed ML-DSA-65 public key (UnmarshalBinary error), a
// tampered ML-DSA-87 message, and an ML-DSA-87 signature with the wrong
// (ML-DSA-65) key encoding.
func TestVerifySignatureMLDSAAdversarial(t *testing.T) {
	// ML-DSA-65 valid key, then a malformed (truncated) key.
	var seed65 [mldsa65.SeedSize]byte
	for i := range seed65 {
		seed65[i] = byte(i + 1)
	}
	pk65, _ := mldsa65.NewKeyFromSeed(&seed65)
	goodBytes := pk65.Bytes()
	if err := VerifySignature(registry.SigMLDSA65, registry.KeyMLDSA65RawPublic, goodBytes[:len(goodBytes)-1], repeated(0xd1, 48), repeated(0xd2, mldsa65.SignatureSize)); err == nil {
		t.Fatal("malformed ML-DSA-65 public key accepted")
	}

	// ML-DSA-87 tampered message.
	var seed87 [mldsa87.SeedSize]byte
	for i := range seed87 {
		seed87[i] = byte(0xa0 + i)
	}
	pk87, sk87 := mldsa87.NewKeyFromSeed(&seed87)
	message := repeated(0xd3, 64)
	sig87 := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk87, message, nil, false, sig87); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(registry.SigMLDSA87, registry.KeyMLDSA87RawPublic, pk87.Bytes(), repeated(0xd4, 64), sig87); err == nil {
		t.Fatal("tampered ML-DSA-87 message accepted")
	}

	// ML-DSA-87 with the wrong (ML-DSA-65) key encoding.
	if err := VerifySignature(registry.SigMLDSA87, registry.KeyMLDSA65RawPublic, pk87.Bytes(), message, sig87); err == nil {
		t.Fatal("ML-DSA-87 signature accepted with ML-DSA-65 key encoding")
	}
}