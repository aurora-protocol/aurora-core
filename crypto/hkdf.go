package auroracrypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func HKDFExtractSHA384(secret, salt []byte) ([]byte, error) {
	return hkdf.Extract(sha512.New384, secret, salt)
}

func HKDFExtractSHA256(secret, salt []byte) ([]byte, error) {
	return hkdf.Extract(sha256.New, secret, salt)
}

func HKDFExtractForSuite(suite uint64, secret, salt []byte) ([]byte, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20:
		return HKDFExtractSHA384(secret, salt)
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		return hkdf.Extract(sha512.New, secret, salt)
	case registry.SuiteLabClassical:
		return HKDFExtractSHA256(secret, salt)
	default:
		return nil, fmt.Errorf("crypto: unsupported suite 0x%x", suite)
	}
}

func HKDFExpandLabelSHA384(secret []byte, label string, context []byte, length int) ([]byte, error) {
	return hkdfExpandLabel(sha512.New384, secret, label, context, length)
}

func HKDFExpandLabelSHA256(secret []byte, label string, context []byte, length int) ([]byte, error) {
	return hkdfExpandLabel(sha256.New, secret, label, context, length)
}

func HKDFExpandLabelForSuite(suite uint64, secret []byte, label string, context []byte, length int) ([]byte, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20:
		return HKDFExpandLabelSHA384(secret, label, context, length)
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		return hkdfExpandLabel(sha512.New, secret, label, context, length)
	case registry.SuiteLabClassical:
		return HKDFExpandLabelSHA256(secret, label, context, length)
	default:
		return nil, fmt.Errorf("crypto: unsupported suite 0x%x", suite)
	}
}

func hkdfExpandLabel[H interface {
	Reset()
	Size() int
	BlockSize() int
	Write([]byte) (int, error)
	Sum([]byte) []byte
}](hash func() H, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := []byte("aurora " + label)
	if len(fullLabel) > 255 {
		return nil, fmt.Errorf("crypto: HKDF label too long")
	}
	if len(context) > 255 {
		return nil, fmt.Errorf("crypto: HKDF context too long")
	}
	e := wire.NewEncoder()
	e.WriteUint16(uint16(length))
	e.WriteOpaque8(fullLabel)
	e.WriteOpaque8(context)
	info, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return hkdf.Expand(hash, secret, string(info), length)
}
