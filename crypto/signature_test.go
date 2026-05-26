package auroracrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestVerifySignatureAcceptsECDSAP256SEC1DER(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	messageDigest := repeated(0x61, 48)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, messageDigest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SEC1Uncompressed, publicKey, messageDigest, sig); err != nil {
		t.Fatalf("valid ECDSA P-256 signature rejected: %v", err)
	}
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SEC1Uncompressed, publicKey, repeated(0x62, 48), sig); err == nil {
		t.Fatalf("tampered digest accepted")
	}
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP384SEC1Uncompressed, publicKey, messageDigest, sig); err == nil {
		t.Fatalf("mismatched SEC1 key encoding accepted")
	}
}

func TestVerifySignatureAcceptsECDSAP384SPKIDER(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	messageDigest := repeated(0x71, 48)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, messageDigest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(registry.SigECDSAP384SHA384DER, registry.KeyP384SPKI, publicKey, messageDigest, sig); err != nil {
		t.Fatalf("valid ECDSA P-384 signature rejected: %v", err)
	}
	if err := VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP384SPKI, publicKey, messageDigest, sig); err == nil {
		t.Fatalf("mismatched signature scheme/key encoding accepted")
	}
}

func TestVerifySignatureAcceptsMLDSA65RawPublic(t *testing.T) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	publicKey, privateKey := mldsa65.NewKeyFromSeed(&seed)
	message := repeated(0x81, 48)
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(privateKey, message, nil, false, signature); err != nil {
		t.Fatal(err)
	}

	if err := VerifySignature(registry.SigMLDSA65, registry.KeyMLDSA65RawPublic, publicKey.Bytes(), message, signature); err != nil {
		t.Fatalf("valid ML-DSA-65 signature rejected: %v", err)
	}
	if err := VerifySignature(registry.SigMLDSA65, registry.KeyMLDSA65RawPublic, publicKey.Bytes(), repeated(0x82, 48), signature); err == nil {
		t.Fatalf("tampered ML-DSA-65 message accepted")
	}
	if err := VerifySignature(registry.SigMLDSA65, registry.KeyMLDSA87RawPublic, publicKey.Bytes(), message, signature); err == nil {
		t.Fatalf("ML-DSA-65 signature accepted with ML-DSA-87 key encoding")
	}
}

func TestVerifySignatureAcceptsMLDSA87RawPublic(t *testing.T) {
	var seed [mldsa87.SeedSize]byte
	for i := range seed {
		seed[i] = byte(0xa0 + i)
	}
	publicKey, privateKey := mldsa87.NewKeyFromSeed(&seed)
	message := repeated(0x91, 64)
	signature := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(privateKey, message, nil, false, signature); err != nil {
		t.Fatal(err)
	}

	if err := VerifySignature(registry.SigMLDSA87, registry.KeyMLDSA87RawPublic, publicKey.Bytes(), message, signature); err != nil {
		t.Fatalf("valid ML-DSA-87 signature rejected: %v", err)
	}
	if err := VerifySignature(registry.SigMLDSA87, registry.KeyMLDSA87RawPublic, publicKey.Bytes()[:len(publicKey.Bytes())-1], message, signature); err == nil {
		t.Fatalf("truncated ML-DSA-87 public key accepted")
	}
}
