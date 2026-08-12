package auroracrypto

import (
	"crypto/mlkem"
	"fmt"
	"sync"

	"github.com/aurora-protocol/aurora-core/registry"
)

type MLKEMDecapsulationKey interface {
	EncapsulationKeyBytes() []byte
	Decapsulate([]byte) ([]byte, error)
	Destroy()
}

type MLKEM768DecapsulationKey struct {
	mu  sync.Mutex
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
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil
	}
	return append([]byte(nil), k.key.EncapsulationKey().Bytes()...)
}

func (k *MLKEM768DecapsulationKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("crypto: missing ML-KEM-768 decapsulation key")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil, fmt.Errorf("crypto: ML-KEM-768 decapsulation key destroyed")
	}
	shared, err := k.key.Decapsulate(append([]byte(nil), ciphertext...))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), shared...), nil
}

func (k *MLKEM768DecapsulationKey) Destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	k.key = nil
	k.mu.Unlock()
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
	mu  sync.Mutex
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
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil
	}
	return append([]byte(nil), k.key.EncapsulationKey().Bytes()...)
}

func (k *MLKEM1024DecapsulationKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("crypto: missing ML-KEM-1024 decapsulation key")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil, fmt.Errorf("crypto: ML-KEM-1024 decapsulation key destroyed")
	}
	shared, err := k.key.Decapsulate(append([]byte(nil), ciphertext...))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), shared...), nil
}

func (k *MLKEM1024DecapsulationKey) Destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	k.key = nil
	k.mu.Unlock()
}

func EncapsulateMLKEM1024(encapsulationKey []byte) (sharedKey, ciphertext []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
	if err != nil {
		return nil, nil, err
	}
	sharedKey, ciphertext = ek.Encapsulate()
	return sharedKey, ciphertext, nil
}

func GenerateMLKEMForSuite(suite uint64) (MLKEMDecapsulationKey, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM,
		registry.SuiteHybrid768P256AESGCM,
		registry.SuiteHybrid768ChaCha20,
		registry.SuiteHybrid768P256ChaCha20:
		return GenerateMLKEM768()
	case registry.SuiteHybrid1024AESGCM,
		registry.SuiteHybrid1024ChaCha20:
		return GenerateMLKEM1024()
	default:
		return nil, fmt.Errorf("crypto: unsupported ML-KEM suite 0x%x", suite)
	}
}

func EncapsulateMLKEMForSuite(suite uint64, encapsulationKey []byte) (sharedKey, ciphertext []byte, err error) {
	key := append([]byte(nil), encapsulationKey...)
	switch suite {
	case registry.SuiteHybrid768AESGCM,
		registry.SuiteHybrid768P256AESGCM,
		registry.SuiteHybrid768ChaCha20,
		registry.SuiteHybrid768P256ChaCha20:
		sharedKey, ciphertext, err = EncapsulateMLKEM768(key)
	case registry.SuiteHybrid1024AESGCM,
		registry.SuiteHybrid1024ChaCha20:
		sharedKey, ciphertext, err = EncapsulateMLKEM1024(key)
	default:
		return nil, nil, fmt.Errorf("crypto: unsupported ML-KEM suite 0x%x", suite)
	}
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), sharedKey...), append([]byte(nil), ciphertext...), nil
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
