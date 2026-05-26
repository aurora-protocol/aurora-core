package auroracrypto

import (
	"crypto/mlkem"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
)

type MLKEM768DecapsulationKey struct {
	key *mlkem.DecapsulationKey768
}

func GenerateMLKEM768() (*MLKEM768DecapsulationKey, error) {
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &MLKEM768DecapsulationKey{key: k}, nil
}

func NewMLKEM768DecapsulationKey(seed []byte) (*MLKEM768DecapsulationKey, error) {
	k, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &MLKEM768DecapsulationKey{key: k}, nil
}

func (k *MLKEM768DecapsulationKey) EncapsulationKeyBytes() []byte {
	return k.key.EncapsulationKey().Bytes()
}

func (k *MLKEM768DecapsulationKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	return k.key.Decapsulate(ciphertext)
}

func EncapsulateMLKEM768(encapsulationKey []byte) (sharedKey, ciphertext []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, nil, err
	}
	sharedKey, ciphertext = ek.Encapsulate()
	return sharedKey, ciphertext, nil
}

type MLKEM1024DecapsulationKey struct {
	key *mlkem.DecapsulationKey1024
}

func GenerateMLKEM1024() (*MLKEM1024DecapsulationKey, error) {
	k, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return &MLKEM1024DecapsulationKey{key: k}, nil
}

func NewMLKEM1024DecapsulationKey(seed []byte) (*MLKEM1024DecapsulationKey, error) {
	k, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, err
	}
	return &MLKEM1024DecapsulationKey{key: k}, nil
}

func (k *MLKEM1024DecapsulationKey) EncapsulationKeyBytes() []byte {
	return k.key.EncapsulationKey().Bytes()
}

func (k *MLKEM1024DecapsulationKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	return k.key.Decapsulate(ciphertext)
}

func EncapsulateMLKEM1024(encapsulationKey []byte) (sharedKey, ciphertext []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
	if err != nil {
		return nil, nil, err
	}
	sharedKey, ciphertext = ek.Encapsulate()
	return sharedKey, ciphertext, nil
}

func ValidateMLKEMEncapsulationKeyForSuite(suite uint64, encapsulationKey []byte) error {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20:
		_, err := mlkem.NewEncapsulationKey768(encapsulationKey)
		return err
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		_, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
		return err
	default:
		return fmt.Errorf("crypto: unsupported ML-KEM suite 0x%x", suite)
	}
}

func ValidateMLKEMCiphertextForSuite(suite uint64, ciphertext []byte) error {
	want, err := MLKEMCiphertextSizeForSuite(suite)
	if err != nil {
		return err
	}
	if len(ciphertext) != want {
		return fmt.Errorf("crypto: ML-KEM ciphertext length %d, want %d", len(ciphertext), want)
	}
	return nil
}

func MLKEMCiphertextSizeForSuite(suite uint64) (int, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20:
		return mlkem.CiphertextSize768, nil
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		return mlkem.CiphertextSize1024, nil
	default:
		return 0, fmt.Errorf("crypto: unsupported ML-KEM suite 0x%x", suite)
	}
}

func VerifyMLDSAUnsupported() error {
	return fmt.Errorf("crypto: ML-DSA verification is not implemented by the Go standard library in this prototype")
}
