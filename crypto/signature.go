package auroracrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
)

func VerifySignature(signatureScheme, keyEncoding uint64, publicKey, messageDigest, signature []byte) error {
	switch signatureScheme {
	case registry.SigECDSAP256SHA256DER, registry.SigECDSAP256SHA384DER:
		pk, err := decodeECDSAPublicKey(keyEncoding, elliptic.P256(), registry.KeyP256SEC1Uncompressed, registry.KeyP256SPKI, publicKey)
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(pk, messageDigest, signature) {
			return fmt.Errorf("crypto: ECDSA P-256 signature verification failed")
		}
		return nil
	case registry.SigECDSAP384SHA384DER:
		pk, err := decodeECDSAPublicKey(keyEncoding, elliptic.P384(), registry.KeyP384SEC1Uncompressed, registry.KeyP384SPKI, publicKey)
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(pk, messageDigest, signature) {
			return fmt.Errorf("crypto: ECDSA P-384 signature verification failed")
		}
		return nil
	case registry.SigEd25519Lab:
		if keyEncoding != registry.KeyEd25519RawPublic {
			return fmt.Errorf("crypto: Ed25519 lab signature incompatible with key encoding 0x%x", keyEncoding)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("crypto: Ed25519 public key length %d, want %d", len(publicKey), ed25519.PublicKeySize)
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), messageDigest, signature) {
			return fmt.Errorf("crypto: Ed25519 signature verification failed")
		}
		return nil
	case registry.SigMLDSA65, registry.SigMLDSA87:
		return VerifyMLDSAUnsupported()
	default:
		return fmt.Errorf("crypto: unsupported signature scheme 0x%x", signatureScheme)
	}
}

func decodeECDSAPublicKey(keyEncoding uint64, curve elliptic.Curve, sec1Encoding, spkiEncoding uint64, encoded []byte) (*ecdsa.PublicKey, error) {
	switch keyEncoding {
	case sec1Encoding:
		x, y := elliptic.Unmarshal(curve, encoded)
		if x == nil || y == nil {
			return nil, fmt.Errorf("crypto: invalid ECDSA SEC1 public key")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case spkiEncoding:
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		if err != nil {
			return nil, err
		}
		pk, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("crypto: SPKI public key is not ECDSA")
		}
		if pk.Curve != curve {
			return nil, fmt.Errorf("crypto: ECDSA public key curve mismatch")
		}
		return pk, nil
	default:
		return nil, fmt.Errorf("crypto: ECDSA signature incompatible with key encoding 0x%x", keyEncoding)
	}
}
