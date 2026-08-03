package auroracrypto

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func BenchmarkAEAD1200(b *testing.B) {
	for _, tc := range []struct {
		name  string
		suite uint64
	}{
		{name: "aes_gcm", suite: registry.SuiteHybrid768AESGCM},
		{name: "chacha20_poly1305", suite: registry.SuiteHybrid768ChaCha20},
	} {
		b.Run(tc.name, func(b *testing.B) {
			key := bytes.Repeat([]byte{0x31}, 32)
			nonce := bytes.Repeat([]byte{0x32}, 12)
			aad := []byte("aurora benchmark aad")
			plaintext := bytes.Repeat([]byte{0x5a}, 1200)
			ciphertext, err := SealForSuite(tc.suite, key, nonce, aad, plaintext)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("seal_1200", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := SealForSuite(tc.suite, key, nonce, aad, plaintext); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("open_1200", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := OpenForSuite(tc.suite, key, nonce, aad, ciphertext); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
