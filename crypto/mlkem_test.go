package auroracrypto

import (
	"bytes"
	"sync"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestMLKEMForSuiteRandomizedRoundTrip(t *testing.T) {
	for _, suite := range productionMLKEMSuites() {
		t.Run(suiteName(suite), func(t *testing.T) {
			first, err := GenerateMLKEMForSuite(suite)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Destroy()
			second, err := GenerateMLKEMForSuite(suite)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Destroy()

			firstPublic := first.EncapsulationKeyBytes()
			secondPublic := second.EncapsulationKeyBytes()
			if len(firstPublic) == 0 || len(secondPublic) == 0 {
				t.Fatal("generated ML-KEM public key is empty")
			}
			if bytes.Equal(firstPublic, secondPublic) {
				t.Fatal("independent ML-KEM keys are identical")
			}

			shared, ciphertext, err := EncapsulateMLKEMForSuite(suite, firstPublic)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := first.Decapsulate(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(shared, opened) {
				t.Fatal("ML-KEM shared secret mismatch")
			}
		})
	}
}

func TestMLKEMForSuiteReturnsOwnedBytes(t *testing.T) {
	for _, suite := range productionMLKEMSuites() {
		t.Run(suiteName(suite), func(t *testing.T) {
			key, err := GenerateMLKEMForSuite(suite)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			public := key.EncapsulationKeyBytes()
			wantPublic := append([]byte(nil), public...)
			public[0] ^= 0xff
			if !bytes.Equal(key.EncapsulationKeyBytes(), wantPublic) {
				t.Fatal("encapsulation key bytes alias private key state")
			}

			shared, ciphertext, err := EncapsulateMLKEMForSuite(suite, wantPublic)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := key.Decapsulate(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			shared[0] ^= 0xff
			ciphertext[0] ^= 0xff
			if len(opened) == 0 || bytes.Equal(shared, opened) {
				t.Fatal("encapsulation output aliases decapsulation output")
			}
		})
	}
}

func TestMLKEMForSuiteDestroyIsIdempotentAndTerminal(t *testing.T) {
	key, err := GenerateMLKEMForSuite(registry.SuiteHybrid768AESGCM)
	if err != nil {
		t.Fatal(err)
	}
	public := key.EncapsulationKeyBytes()
	_, ciphertext, err := EncapsulateMLKEMForSuite(registry.SuiteHybrid768AESGCM, public)
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	key.Destroy()
	if got := key.EncapsulationKeyBytes(); got != nil {
		t.Fatalf("destroyed key returned %d public bytes", len(got))
	}
	if _, err := key.Decapsulate(ciphertext); err == nil {
		t.Fatal("destroyed key decapsulated ciphertext")
	}
}

func TestMLKEMForSuiteConcurrentDestroyDoesNotRaceOrPanic(t *testing.T) {
	key, err := GenerateMLKEMForSuite(registry.SuiteHybrid768AESGCM)
	if err != nil {
		t.Fatal(err)
	}
	_, ciphertext, err := EncapsulateMLKEMForSuite(registry.SuiteHybrid768AESGCM, key.EncapsulationKeyBytes())
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, _ = key.Decapsulate(ciphertext)
			_ = key.EncapsulationKeyBytes()
		}()
	}
	close(start)
	key.Destroy()
	workers.Wait()
	if _, err := key.Decapsulate(ciphertext); err == nil {
		t.Fatal("destroyed key remained usable after concurrent access")
	}
}

func TestMLKEMForSuiteRejectsUnsupportedOrMalformedInputs(t *testing.T) {
	for _, suite := range []uint64{0, registry.SuiteLabClassical, 0xffff} {
		if _, err := GenerateMLKEMForSuite(suite); err == nil {
			t.Fatalf("GenerateMLKEMForSuite accepted suite 0x%x", suite)
		}
		if _, _, err := EncapsulateMLKEMForSuite(suite, []byte{1}); err == nil {
			t.Fatalf("EncapsulateMLKEMForSuite accepted suite 0x%x", suite)
		}
	}

	for _, suite := range productionMLKEMSuites() {
		t.Run(suiteName(suite), func(t *testing.T) {
			if _, _, err := EncapsulateMLKEMForSuite(suite, []byte{1}); err == nil {
				t.Fatal("malformed encapsulation key accepted")
			}
			key, err := GenerateMLKEMForSuite(suite)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			if _, err := key.Decapsulate([]byte{1}); err == nil {
				t.Fatal("malformed ciphertext accepted")
			}
		})
	}
}

func productionMLKEMSuites() []uint64 {
	return []uint64{
		registry.SuiteHybrid768AESGCM,
		registry.SuiteHybrid768P256AESGCM,
		registry.SuiteHybrid768ChaCha20,
		registry.SuiteHybrid768P256ChaCha20,
		registry.SuiteHybrid1024AESGCM,
		registry.SuiteHybrid1024ChaCha20,
	}
}

func suiteName(suite uint64) string {
	switch suite {
	case registry.SuiteHybrid768AESGCM:
		return "hybrid768_aes"
	case registry.SuiteHybrid768P256AESGCM:
		return "hybrid768_p256_aes"
	case registry.SuiteHybrid768ChaCha20:
		return "hybrid768_chacha"
	case registry.SuiteHybrid768P256ChaCha20:
		return "hybrid768_p256_chacha"
	case registry.SuiteHybrid1024AESGCM:
		return "hybrid1024_aes"
	case registry.SuiteHybrid1024ChaCha20:
		return "hybrid1024_chacha"
	default:
		return "unknown"
	}
}
