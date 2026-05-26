package auroracrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
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
