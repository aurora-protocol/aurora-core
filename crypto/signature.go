package auroracrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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
	case registry.SigMLDSA65:
		return verifyMLDSA65(keyEncoding, publicKey, messageDigest, signature)
	case registry.SigMLDSA87:
		return verifyMLDSA87(keyEncoding, publicKey, messageDigest, signature)
	default:
		return fmt.Errorf("crypto: unsupported signature scheme 0x%x", signatureScheme)
	}
}

func verifyMLDSA65(keyEncoding uint64, publicKey, message, signature []byte) error {
	if keyEncoding != registry.KeyMLDSA65RawPublic {
		return fmt.Errorf("crypto: ML-DSA-65 signature incompatible with key encoding 0x%x", keyEncoding)
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return fmt.Errorf("crypto: invalid ML-DSA-65 public key: %w", err)
	}
	if !mldsa65.Verify(&pk, message, nil, signature) {
		return fmt.Errorf("crypto: ML-DSA-65 signature verification failed")
	}
	return nil
}

func verifyMLDSA87(keyEncoding uint64, publicKey, message, signature []byte) error {
	if keyEncoding != registry.KeyMLDSA87RawPublic {
		return fmt.Errorf("crypto: ML-DSA-87 signature incompatible with key encoding 0x%x", keyEncoding)
	}
	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return fmt.Errorf("crypto: invalid ML-DSA-87 public key: %w", err)
	}
	if !mldsa87.Verify(&pk, message, nil, signature) {
		return fmt.Errorf("crypto: ML-DSA-87 signature verification failed")
	}
	return nil
}

func decodeECDSAPublicKey(keyEncoding uint64, curve elliptic.Curve, sec1Encoding, spkiEncoding uint64, encoded []byte) (*ecdsa.PublicKey, error) {
	switch keyEncoding {
	case sec1Encoding:
		pk, err := ecdsa.ParseUncompressedPublicKey(curve, encoded)
		if err != nil {
			return nil, fmt.Errorf("crypto: invalid ECDSA SEC1 public key: %w", err)
		}
		return pk, nil
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
