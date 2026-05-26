package auroracrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/aurora-protocol/aurora-core/registry"
)

func HMACForSuite(suite uint64, key, msg []byte) ([]byte, error) {
	var h func() hash.Hash
	switch suite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20:
		h = sha512.New384
	case registry.SuiteHybrid1024AESGCM, registry.SuiteHybrid1024ChaCha20:
		h = sha512.New
	case registry.SuiteLabClassical:
		h = sha256.New
	default:
		return nil, fmt.Errorf("crypto: unsupported suite 0x%x", suite)
	}
	mac := hmac.New(h, key)
	mac.Write(msg)
	return mac.Sum(nil), nil
}
