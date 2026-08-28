package labfixture

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// zeroLabBytes erases one owned buffer.
func zeroLabBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// zeroLabBigInt erases a big.Int including its retained backing words.
func zeroLabBigInt(value *big.Int) {
	if value == nil {
		return
	}
	words := value.Bits()
	clear(words)
	value.SetInt64(0)
}

// zeroLabECDSAKey erases an ECDSA private key that is no longer needed.
func zeroLabECDSAKey(key *ecdsa.PrivateKey) {
	if key == nil {
		return
	}
	zeroLabBigInt(key.D)
	*key = ecdsa.PrivateKey{}
}

// zeroLabRSAKey erases an RSA private key that is no longer needed.
func zeroLabRSAKey(key *rsa.PrivateKey) {
	if key == nil {
		return
	}
	zeroLabBigInt(key.D)
	for _, prime := range key.Primes {
		zeroLabBigInt(prime)
	}
	zeroLabBigInt(key.Precomputed.Dp)
	zeroLabBigInt(key.Precomputed.Dq)
	zeroLabBigInt(key.Precomputed.Qinv)
	//lint:ignore SA1019 Clear legacy retained CRT limbs if a parser populated them.
	for _, value := range key.Precomputed.CRTValues {
		zeroLabBigInt(value.Exp)
		zeroLabBigInt(value.Coeff)
		zeroLabBigInt(value.R)
	}
	*key = rsa.PrivateKey{}
}

// zeroLabMLDSA65Key erases an ML-DSA-65 private key that is no longer needed.
func zeroLabMLDSA65Key(key *mldsa65.PrivateKey) {
	if key != nil {
		*key = mldsa65.PrivateKey{}
	}
}
