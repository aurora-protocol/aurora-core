package auroracrypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
)

func PreHash(parts ...[]byte) []byte {
	h := sha512.New384()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func PreHashLabel(label string, parts ...[]byte) []byte {
	all := make([][]byte, 0, len(parts)+1)
	all = append(all, []byte(label))
	all = append(all, parts...)
	return PreHash(all...)
}

func Truncate128(b []byte) []byte {
	if len(b) < 16 {
		out := make([]byte, 16)
		copy(out, b)
		return out
	}
	out := make([]byte, 16)
	copy(out, b[:16])
	return out
}

func SHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func SuiteHash(suite uint64, parts ...[]byte) ([]byte, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20:
		h := sha512.New384()
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil), nil
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		h := sha512.New()
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil), nil
	case registry.SuiteLabClassical:
		h := sha256.New()
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil), nil
	default:
		return nil, fmt.Errorf("crypto: unsupported suite 0x%x", suite)
	}
}

func SuiteHashLength(suite uint64) (int, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20:
		return 48, nil
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		return 64, nil
	case registry.SuiteLabClassical:
		return 32, nil
	default:
		return 0, fmt.Errorf("crypto: unsupported suite 0x%x", suite)
	}
}

func AEADKeyLength(suite uint64) (int, error) {
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid1024AESGCM, registry.SuiteLabClassical:
		return 32, nil
	case registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20, registry.SuiteHybrid1024ChaCha20:
		return 32, nil
	default:
		return 0, fmt.Errorf("crypto: unsupported suite 0x%x", suite)
	}
}
