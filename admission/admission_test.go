package admission

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func rep(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestAccessHintIsOneTimeForCredential(t *testing.T) {
	cred := AccessHintCredential{
		HintIssuerID:  rep(0x01, 16),
		RelayBucketID: rep(0x02, 16),
		HintEpochID:   7,
		HintSelector:  rep(0x03, 16),
		HintSecret:    rep(0x04, 32),
		MaxUses:       1,
	}
	binding := rep(0xaa, 48)
	nonce := rep(0xbb, 32)
	hint, err := ComputeAccessHint(cred, binding, nonce)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewMemoryReplayCache()
	if err := VerifyAndSpendAccessHint(cache, cred, binding, nonce, hint); err != nil {
		t.Fatalf("first hint spend failed: %v", err)
	}
	if err := VerifyAndSpendAccessHint(cache, cred, binding, rep(0xbc, 32), hint); err == nil {
		t.Fatalf("expected replayed credential to fail")
	}
}

func TestAccessHintRejectsExpiredCredentialBeforeSpend(t *testing.T) {
	cred := AccessHintCredential{
		HintIssuerID:  rep(0x11, 16),
		RelayBucketID: rep(0x12, 16),
		HintEpochID:   8,
		HintSelector:  rep(0x13, 16),
		HintSecret:    rep(0x14, 32),
		ExpiryUnix:    100,
		MaxUses:       1,
	}
	binding := rep(0x15, 48)
	nonce := rep(0x16, 32)
	hint, err := ComputeAccessHint(cred, binding, nonce)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewMemoryReplayCache()
	if err := VerifyAndSpendAccessHintAt(cache, cred, binding, nonce, hint, 100); err == nil {
		t.Fatalf("expired access hint accepted")
	}
	spentKey, err := ComputeSpentHintKey(cred)
	if err != nil {
		t.Fatal(err)
	}
	if cache.Has(spentKey) {
		t.Fatalf("expired access hint was spent")
	}
	if err := VerifyAndSpendAccessHintAt(cache, cred, binding, nonce, hint, 99); err != nil {
		t.Fatalf("valid access hint rejected: %v", err)
	}
}

func TestReplayTokenSpentKeyIgnoresReplayProofNonce(t *testing.T) {
	admissionContext := rep(0x20, 48)
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofLabStaticToken,
		IssuerID:              rep(0x01, 16),
		TokenKeyID:            rep(0x02, 32),
		RelayBucketID:         rep(0x03, 16),
		TokenScopeID:          rep(0x04, 16),
		ExpiryUnix:            2000000000,
		TokenNonce:            rep(0x05, 32),
		RedemptionContextHash: admissionContext,
		TokenPublicMetadata:   []byte("meta"),
		TokenAuthenticator:    []byte("structural-token"),
	}
	redemption, err := TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	spent1, err := TokenSpentKey(redemption)
	if err != nil {
		t.Fatal(err)
	}
	replay1 := protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       9,
		TokenRedemptionHash: redemption,
		ClientReplayNonce:   rep(0x06, 32),
		ReplayWindowID:      rep(0x07, 16),
	}
	replay2 := replay1
	replay2.ClientReplayNonce = rep(0x08, 32)
	spent2, err := TokenSpentKey(redemption)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spent1, spent2) {
		t.Fatalf("token spent key changed with replay nonce")
	}

	ctx1, err := ReplayContextHash(redemption, replay1, 0x42, 0, rep(0x09, 48), admissionContext)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, err := ReplayContextHash(redemption, replay2, 0x42, 0, rep(0x09, 48), admissionContext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ctx1, ctx2) {
		t.Fatalf("replay context hash should change with client replay nonce")
	}
}

func TestVerifyAndSpendReplayRejectsSecondSpendWithChangedReplayNonce(t *testing.T) {
	admissionContext := rep(0x30, 48)
	handshakeBinding := rep(0x31, 48)
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofLabStaticToken,
		IssuerID:              rep(0x01, 16),
		TokenKeyID:            rep(0x02, 32),
		RelayBucketID:         rep(0x03, 16),
		TokenScopeID:          rep(0x04, 16),
		ExpiryUnix:            2000000000,
		TokenNonce:            rep(0x05, 32),
		RedemptionContextHash: admissionContext,
		TokenAuthenticator:    []byte("structural-token"),
	}
	redemption, err := TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	replay := protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       9,
		TokenRedemptionHash: redemption,
		ClientReplayNonce:   rep(0x06, 32),
		ReplayWindowID:      rep(0x07, 16),
	}
	replay.ReplayContextHash, err = ReplayContextHash(redemption, replay, 0x42, 0, handshakeBinding, admissionContext)
	if err != nil {
		t.Fatal(err)
	}
	tokenCache := NewMemoryReplayCache()
	bootstrapCache := NewMemoryReplayCache()
	if _, _, err := VerifyAndSpendReplay(ReplayVerificationInput{
		AdmissionProof:          proof,
		ReplayProof:             replay,
		RouteInstanceID:         0x42,
		HopIndex:                0,
		HandshakeBindingContext: handshakeBinding,
		AdmissionContextHash:    admissionContext,
		TokenSpentCache:         tokenCache,
		BootstrapDedupCache:     bootstrapCache,
	}); err != nil {
		t.Fatalf("first replay spend failed: %v", err)
	}
	replay.ClientReplayNonce = rep(0x08, 32)
	replay.ReplayContextHash, err = ReplayContextHash(redemption, replay, 0x42, 0, handshakeBinding, admissionContext)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyAndSpendReplay(ReplayVerificationInput{
		AdmissionProof:          proof,
		ReplayProof:             replay,
		RouteInstanceID:         0x42,
		HopIndex:                0,
		HandshakeBindingContext: handshakeBinding,
		AdmissionContextHash:    admissionContext,
		TokenSpentCache:         tokenCache,
		BootstrapDedupCache:     NewMemoryReplayCache(),
	}); err == nil {
		t.Fatalf("expected changed replay nonce to fail primary token-spent cache")
	}
}
