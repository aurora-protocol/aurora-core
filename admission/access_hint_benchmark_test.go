package admission

import "testing"

// BenchmarkComputeAccessHint measures the per-request access-hint computation
// (HMAC-SHA256 over the binding inputs followed by Truncate128). This is the
// relay's hot credential-verification cost on every request.
func BenchmarkComputeAccessHint(b *testing.B) {
	cred := validHintCredential()
	bindingContext := rep(0x70, 48)
	clientNonce := rep(0x71, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ComputeAccessHint(cred, bindingContext, clientNonce); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkComputeSpentHintKey measures the spent-key preimage hash (SHA-384
// PreHash) used to record a spent access hint in the replay cache.
func BenchmarkComputeSpentHintKey(b *testing.B) {
	cred := validHintCredential()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ComputeSpentHintKey(cred); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRFC9577TokenChallengeDigest measures the token challenge digest
// (wire encode + SHA-256) computed on the issuance/redemption path.
func BenchmarkRFC9577TokenChallengeDigest(b *testing.B) {
	redemptionContextHash := rep(0x72, 48)
	issuerName := []byte("issuer.example")
	originInfo := []byte("origin.example")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := RFC9577TokenChallengeDigest(1, issuerName, originInfo, redemptionContextHash); err != nil {
			b.Fatal(err)
		}
	}
}