package admission

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestReplayCacheDurabilityMarkers(t *testing.T) {
	if NewMemoryReplayCache().Durable() {
		t.Fatal("memory replay cache reported durable")
	}
	cache, err := NewFileReplayCache(filepath.Join(t.TempDir(), "durability.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	if !cache.Durable() {
		t.Fatal("file replay cache did not report durable")
	}
}

func TestFileReplayCachePersistsSpentKeysAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay-cache.log")
	key := rep(0x77, 48)

	cache, err := NewFileReplayCache(path)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := cache.InsertIfAbsent(key)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatalf("first insert reported replay")
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileReplayCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.Has(key) {
		t.Fatalf("reopened cache did not load spent key")
	}
	inserted, err = reopened.InsertIfAbsent(key)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatalf("reopened cache accepted duplicate spent key")
	}
}

func TestFileReplayCacheRejectsDuplicateFromStaleOpenInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay-cache.log")
	key := rep(0x78, 48)

	first, err := NewFileReplayCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewFileReplayCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	inserted, err := first.InsertIfAbsent(key)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatalf("first insert reported replay")
	}
	inserted, err = second.InsertIfAbsent(key)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatalf("stale open cache accepted duplicate spent key")
	}
	if !second.Has(key) {
		t.Fatalf("stale open cache did not observe key written by peer")
	}
}

func TestVerifyAndSpendReplayFailsClosedWhenReplayCacheWriteFails(t *testing.T) {
	proof, replay, handshakeBinding, admissionContext := replayVerificationFixture(t)
	_, _, err := VerifyAndSpendReplay(ReplayVerificationInput{
		AdmissionProof:          proof,
		ReplayProof:             replay,
		RouteInstanceID:         0x42,
		HopIndex:                0,
		HandshakeBindingContext: handshakeBinding,
		AdmissionContextHash:    admissionContext,
		TokenSpentCache:         failingReplayCache{err: errors.New("replay store unavailable")},
		BootstrapDedupCache:     NewMemoryReplayCache(),
		AllowLabProofs:          true,
	})
	if err == nil {
		t.Fatalf("replay verification accepted cache write failure")
	}
	if !strings.Contains(err.Error(), "replay store unavailable") {
		t.Fatalf("replay verification did not preserve cache failure: %v", err)
	}
}

func TestVerifyAndSpendReplayRetainsTokenSpendWhenBootstrapCacheWriteFails(t *testing.T) {
	proof, replay, handshakeBinding, admissionContext := replayVerificationFixture(t)
	tokenCache := NewMemoryReplayCache()
	_, _, err := VerifyAndSpendReplay(ReplayVerificationInput{
		AdmissionProof:          proof,
		ReplayProof:             replay,
		RouteInstanceID:         0x42,
		HopIndex:                0,
		HandshakeBindingContext: handshakeBinding,
		AdmissionContextHash:    admissionContext,
		TokenSpentCache:         tokenCache,
		BootstrapDedupCache:     failingReplayCache{err: errors.New("replay store unavailable")},
		AllowLabProofs:          true,
	})
	if err == nil {
		t.Fatal("replay verification accepted bootstrap cache write failure")
	}
	redemptionHash, hashErr := TokenRedemptionHash(proof)
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	tokenKey, keyErr := TokenSpentKey(redemptionHash)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if !tokenCache.Has(tokenKey) {
		t.Fatal("replay verification rolled back an authoritative token spend")
	}
}

func TestVerifyAndSpendReplayRequiresReplayCaches(t *testing.T) {
	proof, replay, handshakeBinding, admissionContext := replayVerificationFixture(t)
	for name, input := range map[string]ReplayVerificationInput{
		"missing token cache": {
			TokenSpentCache:     nil,
			BootstrapDedupCache: NewMemoryReplayCache(),
		},
		"missing bootstrap cache": {
			TokenSpentCache:     NewMemoryReplayCache(),
			BootstrapDedupCache: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			input.AdmissionProof = proof
			input.ReplayProof = replay
			input.RouteInstanceID = 0x42
			input.HopIndex = 0
			input.HandshakeBindingContext = handshakeBinding
			input.AdmissionContextHash = admissionContext
			input.AllowLabProofs = true
			if _, _, err := VerifyAndSpendReplay(input); err == nil {
				t.Fatalf("replay verification accepted missing replay cache")
			}
		})
	}
}

type failingReplayCache struct {
	err error
}

func (c failingReplayCache) InsertIfAbsent([]byte) (bool, error) {
	return false, c.err
}

func (c failingReplayCache) Has([]byte) bool {
	return false
}

func replayVerificationFixture(t *testing.T) (protocol.AdmissionProof, protocol.ReplayProof, []byte, []byte) {
	t.Helper()
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
	return proof, replay, handshakeBinding, admissionContext
}
