package auroracrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
)

const (
	ECDHCurveX25519 = "x25519"
	ECDHCurveP256   = "p256"
	ECDHCurveP384   = "p384"
)

type ECDHPrivateKey struct {
	suite     uint64
	curveName string
	key       *ecdh.PrivateKey
}

func GenerateECDHForSuite(suite uint64) (*ECDHPrivateKey, error) {
	curve, name, err := ecdhCurveForSuite(suite)
	if err != nil {
		return nil, err
	}
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDHPrivateKey{suite: suite, curveName: name, key: key}, nil
}

func NewECDHPrivateKeyForSuite(suite uint64, privateKey []byte) (*ECDHPrivateKey, error) {
	curve, name, err := ecdhCurveForSuite(suite)
	if err != nil {
		return nil, err
	}
	key, err := curve.NewPrivateKey(append([]byte(nil), privateKey...))
	if err != nil {
		return nil, err
	}
	return &ECDHPrivateKey{suite: suite, curveName: name, key: key}, nil
}

func NewECDHPublicKeyForSuite(suite uint64, publicKey []byte) (*ecdh.PublicKey, error) {
	curve, _, err := ecdhCurveForSuite(suite)
	if err != nil {
		return nil, err
	}
	return curve.NewPublicKey(append([]byte(nil), publicKey...))
}

func ECDHCurveNameForSuite(suite uint64) (string, error) {
	_, name, err := ecdhCurveForSuite(suite)
	return name, err
}

func (k *ECDHPrivateKey) Suite() uint64 {
	if k == nil {
		return 0
	}
	return k.suite
}

func (k *ECDHPrivateKey) CurveName() string {
	if k == nil {
		return ""
	}
	return k.curveName
}

func (k *ECDHPrivateKey) PrivateKeyBytes() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	return append([]byte(nil), k.key.Bytes()...)
}

func (k *ECDHPrivateKey) PublicKeyBytes() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	return append([]byte(nil), k.key.PublicKey().Bytes()...)
}

func (k *ECDHPrivateKey) SharedSecret(peerPublicKey []byte) ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("crypto: missing ECDH private key")
	}
	peer, err := k.key.Curve().NewPublicKey(append([]byte(nil), peerPublicKey...))
	if err != nil {
		return nil, err
	}
	secret, err := k.key.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), secret...), nil
}

func ecdhCurveForSuite(suite uint64) (ecdh.Curve, string, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768ChaCha20:
		return ecdh.X25519(), ECDHCurveX25519, nil
	case registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768P256ChaCha20:
		return ecdh.P256(), ECDHCurveP256, nil
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		return ecdh.P384(), ECDHCurveP384, nil
	default:
		return nil, "", fmt.Errorf("crypto: unsupported ECDH suite 0x%x", suite)
	}
}
