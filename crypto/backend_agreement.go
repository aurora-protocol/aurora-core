package auroracrypto

import (
	"bytes"
	stdmlkem "crypto/mlkem"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	stdlibMLKEMBackend = "crypto/mlkem"
	circlMLKEMBackend  = "github.com/cloudflare/circl/kem/mlkem"
)

type BackendAgreementResult struct {
	Scheme                 string
	StandardLibraryBackend string
	CrossCheckBackend      string
	PublicKeyBytes         int
	CiphertextBytes        int
	SharedSecretBytes      int
	Passed                 bool
}

func CheckMLKEMBackendAgreement() ([]BackendAgreementResult, error) {
	mlkem768Result, err := checkMLKEM768BackendAgreement()
	if err != nil {
		return nil, err
	}
	mlkem1024Result, err := checkMLKEM1024BackendAgreement()
	if err != nil {
		return nil, err
	}
	return []BackendAgreementResult{mlkem768Result, mlkem1024Result}, nil
}

func checkMLKEM768BackendAgreement() (BackendAgreementResult, error) {
	keySeed := backendAgreementBytes(0x78, mlkem768.KeySeedSize)
	encapsulationSeed := backendAgreementBytes(0xe7, mlkem768.EncapsulationSeedSize)

	stdlibPrivate, err := stdmlkem.NewDecapsulationKey768(keySeed)
	if err != nil {
		return BackendAgreementResult{}, err
	}
	circlPublic, circlPrivate := mlkem768.NewKeyFromSeed(keySeed)

	stdlibPublic := stdlibPrivate.EncapsulationKey().Bytes()
	circlPublicBytes := make([]byte, mlkem768.PublicKeySize)
	circlPublic.Pack(circlPublicBytes)
	if !bytes.Equal(stdlibPublic, circlPublicBytes) {
		return BackendAgreementResult{}, fmt.Errorf("crypto: ML-KEM-768 backend public keys differ")
	}

	ciphertext := make([]byte, mlkem768.CiphertextSize)
	circlShared := make([]byte, mlkem768.SharedKeySize)
	circlPublic.EncapsulateTo(ciphertext, circlShared, encapsulationSeed)
	stdlibShared, err := stdlibPrivate.Decapsulate(ciphertext)
	if err != nil {
		return BackendAgreementResult{}, err
	}
	if !bytes.Equal(stdlibShared, circlShared) {
		return BackendAgreementResult{}, fmt.Errorf("crypto: ML-KEM-768 backend shared secrets differ")
	}
	circlDecapsulated := make([]byte, mlkem768.SharedKeySize)
	circlPrivate.DecapsulateTo(circlDecapsulated, ciphertext)
	if !bytes.Equal(circlDecapsulated, stdlibShared) {
		return BackendAgreementResult{}, fmt.Errorf("crypto: ML-KEM-768 CIRCL decapsulation disagrees with stdlib")
	}

	return BackendAgreementResult{
		Scheme:                 "ML-KEM-768",
		StandardLibraryBackend: stdlibMLKEMBackend,
		CrossCheckBackend:      circlMLKEMBackend,
		PublicKeyBytes:         len(stdlibPublic),
		CiphertextBytes:        len(ciphertext),
		SharedSecretBytes:      len(stdlibShared),
		Passed:                 true,
	}, nil
}

func checkMLKEM1024BackendAgreement() (BackendAgreementResult, error) {
	keySeed := backendAgreementBytes(0x24, mlkem1024.KeySeedSize)
	encapsulationSeed := backendAgreementBytes(0xe1, mlkem1024.EncapsulationSeedSize)

	stdlibPrivate, err := stdmlkem.NewDecapsulationKey1024(keySeed)
	if err != nil {
		return BackendAgreementResult{}, err
	}
	circlPublic, circlPrivate := mlkem1024.NewKeyFromSeed(keySeed)

	stdlibPublic := stdlibPrivate.EncapsulationKey().Bytes()
	circlPublicBytes := make([]byte, mlkem1024.PublicKeySize)
	circlPublic.Pack(circlPublicBytes)
	if !bytes.Equal(stdlibPublic, circlPublicBytes) {
		return BackendAgreementResult{}, fmt.Errorf("crypto: ML-KEM-1024 backend public keys differ")
	}

	ciphertext := make([]byte, mlkem1024.CiphertextSize)
	circlShared := make([]byte, mlkem1024.SharedKeySize)
	circlPublic.EncapsulateTo(ciphertext, circlShared, encapsulationSeed)
	stdlibShared, err := stdlibPrivate.Decapsulate(ciphertext)
	if err != nil {
		return BackendAgreementResult{}, err
	}
	if !bytes.Equal(stdlibShared, circlShared) {
		return BackendAgreementResult{}, fmt.Errorf("crypto: ML-KEM-1024 backend shared secrets differ")
	}
	circlDecapsulated := make([]byte, mlkem1024.SharedKeySize)
	circlPrivate.DecapsulateTo(circlDecapsulated, ciphertext)
	if !bytes.Equal(circlDecapsulated, stdlibShared) {
		return BackendAgreementResult{}, fmt.Errorf("crypto: ML-KEM-1024 CIRCL decapsulation disagrees with stdlib")
	}

	return BackendAgreementResult{
		Scheme:                 "ML-KEM-1024",
		StandardLibraryBackend: stdlibMLKEMBackend,
		CrossCheckBackend:      circlMLKEMBackend,
		PublicKeyBytes:         len(stdlibPublic),
		CiphertextBytes:        len(ciphertext),
		SharedSecretBytes:      len(stdlibShared),
		Passed:                 true,
	}, nil
}

func backendAgreementBytes(seed byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed ^ byte(i*31)
	}
	return out
}
