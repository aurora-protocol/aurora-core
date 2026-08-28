package route

// Retention semantics for the route wrap-nonce replay cache (spec 17.6): a
// relay rejects duplicate (hint_issuer_id, relay_bucket_id, hint_epoch_id,
// hint_selector, wrap_nonce) tuples before AccessHint spending, but the record
// only needs to live as long as the credential it guards can still verify.
// Past the retention horizon (the same MaximumRetentionDeadline the spent-hint
// record carries), a replayed envelope is rejected by
// admission.VerifyAndSpendAccessHintAt as expired regardless of wrap-nonce
// state, so the wrap-nonce record MAY be evicted and MUST NOT be resurrected
// inside the window.
//
// TestOpenAndVerifyPrivatePreludeWithWrapNonceCacheEvictsExpiredNonces is
// failing-first against the unbounded cache: the pristine InsertIfAbsent
// retains every record permanently, so the eviction assertion fails.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
)

// sealWrapNonceTestEnvelope seals a valid private prelude under env with the
// given wrap nonce and client nonce, with the AccessHint computed over the
// matching route hop binding for cred.
func sealWrapNonceTestEnvelope(t *testing.T, env EnvelopeInput, cred admission.AccessHintCredential, wrapNonce, clientNonce []byte) (EnvelopeInput, protocol.RoutePreludeEnvelope) {
	t.Helper()
	env.WrapNonce = append([]byte(nil), wrapNonce...)
	private := routeTestPrivatePrelude(t, env)
	private.ClientNonceForThisHop = append([]byte(nil), clientNonce...)
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		t.Fatal(err)
	}
	private.RoutePreludeWrapContext = context
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		t.Fatal(err)
	}
	private.AccessHint, err = admission.ComputeAccessHint(cred, binding, private.ClientNonceForThisHop)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealPrivatePrelude(env, private)
	if err != nil {
		t.Fatal(err)
	}
	return env, envelope
}

func wrapNonceCacheRetains(t *testing.T, cache *WrapNonceReplayCache, envelope protocol.RoutePreludeEnvelope) bool {
	t.Helper()
	key, err := routeWrapNonceReplayKey(envelope)
	if err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	_, ok := cache.seen[string(key)]
	return ok
}

func TestOpenAndVerifyPrivatePreludeWithWrapNonceCacheEvictsExpiredNonces(t *testing.T) {
	env := routeTestEnvelope()
	cred := routeTestAccessHintCredential(env) // ExpiryUnix 200
	wrapCache := NewWrapNonceReplayCache()

	// Two distinct wrap nonces under the same credential tuple, verified at
	// t=100 against a credential that expires at 200 with the relay epoch
	// valid until 300. Each envelope spends the one-time credential, so each
	// verification gets a fresh access-hint cache; the wrap-nonce cache is the
	// shared state under test.
	env1, envelope1 := sealWrapNonceTestEnvelope(t, env, cred, rb(0x52, 16), rb(0x45, 32))
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), wrapCache, env1, envelope1, cred, 100, 300); err != nil {
		t.Fatalf("first route prelude was rejected: %v", err)
	}
	env2, envelope2 := sealWrapNonceTestEnvelope(t, env, cred, rb(0x53, 16), rb(0x46, 32))
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), wrapCache, env2, envelope2, cred, 100, 300); err != nil {
		t.Fatalf("second route prelude was rejected: %v", err)
	}

	// Replay inside the retention window is still rejected before the
	// access-hint spend, even though the access cache is fresh.
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), wrapCache, env1, envelope1, cred, 150, 300); err == nil {
		t.Fatal("replayed route wrap nonce inside its retention window was accepted")
	}

	// A later envelope whose own credential is still valid at t=1000 sweeps
	// the expired records (their horizon was max(200, 300) + grace = 900).
	cred3 := cred
	cred3.ExpiryUnix = 2000
	env3, envelope3 := sealWrapNonceTestEnvelope(t, env, cred3, rb(0x54, 16), rb(0x47, 32))
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), wrapCache, env3, envelope3, cred3, 1000, 3000); err != nil {
		t.Fatalf("later route prelude was rejected: %v", err)
	}

	if wrapNonceCacheRetains(t, wrapCache, envelope1) || wrapNonceCacheRetains(t, wrapCache, envelope2) {
		t.Fatal("expired route wrap nonce records were retained past their retention horizon")
	}
	if !wrapNonceCacheRetains(t, wrapCache, envelope3) {
		t.Fatal("route wrap nonce record inside its retention window was evicted")
	}
}

// Without a time source (nowUnix == 0) the cache keeps its permanent
// semantics, mirroring the access-hint cache's no-time fallback: duplicates
// are still rejected and nothing is evicted.
func TestOpenAndVerifyPrivatePreludeWithWrapNonceCacheWithoutTimeRetainsPermanently(t *testing.T) {
	env := routeTestEnvelope()
	cred := routeTestAccessHintCredential(env)
	wrapCache := NewWrapNonceReplayCache()
	env, envelope := sealWrapNonceTestEnvelope(t, env, cred, rb(0x55, 16), rb(0x45, 32))
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), wrapCache, env, envelope, cred, 0, 0); err != nil {
		t.Fatalf("route prelude without time source was rejected: %v", err)
	}
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), wrapCache, env, envelope, cred, 0, 0); err == nil {
		t.Fatal("duplicate route wrap nonce without time source was accepted")
	}
	if !wrapNonceCacheRetains(t, wrapCache, envelope) {
		t.Fatal("route wrap nonce record was evicted without a time source")
	}
}

// The retention window is validated fail-closed: an invalid window rejects the
// envelope with an error instead of inserting or silently retaining.
func TestWrapNonceReplayCacheInsertIfAbsentUntilRejectsInvalidWindows(t *testing.T) {
	_, envelope := sealWrapNonceTestEnvelope(t, routeTestEnvelope(), routeTestAccessHintCredential(routeTestEnvelope()), rb(0x56, 16), rb(0x45, 32))

	var nilCache *WrapNonceReplayCache
	if _, err := nilCache.InsertIfAbsentUntil(envelope, 900, 100); err == nil {
		t.Fatal("nil wrap nonce cache accepted a retained insert")
	}

	cache := NewWrapNonceReplayCache()
	for _, tc := range []struct {
		name        string
		retainUntil uint64
		nowUnix     uint64
	}{
		{"zero deadline", 0, 100},
		{"zero now", 900, 0},
		{"deadline equals now", 100, 100},
		{"deadline in the past", 99, 100},
	} {
		if _, err := cache.InsertIfAbsentUntil(envelope, tc.retainUntil, tc.nowUnix); err == nil {
			t.Fatalf("InsertIfAbsentUntil(%s) succeeded, want fail-closed error", tc.name)
		}
	}
	if len(cache.seen) != 0 {
		t.Fatalf("invalid retention windows inserted %d records", len(cache.seen))
	}
	if _, err := cache.InsertIfAbsentUntil(envelope, 900, 100); err != nil {
		t.Fatalf("valid retention window was rejected: %v", err)
	}
	if !wrapNonceCacheRetains(t, cache, envelope) {
		t.Fatal("valid retained insert was not recorded")
	}
}

// A record whose deadline has passed is swept by the next retained insert and
// its key may be inserted again (the replayed envelope is still rejected
// downstream by the expired access hint). Permanent records (deadline 0,
// inserted via InsertIfAbsent) survive every sweep.
func TestWrapNonceReplayCacheSweepsExpiredRecordsOnly(t *testing.T) {
	cred := routeTestAccessHintCredential(routeTestEnvelope())
	_, expiring := sealWrapNonceTestEnvelope(t, routeTestEnvelope(), cred, rb(0x57, 16), rb(0x45, 32))
	_, permanent := sealWrapNonceTestEnvelope(t, routeTestEnvelope(), cred, rb(0x58, 16), rb(0x46, 32))
	_, later := sealWrapNonceTestEnvelope(t, routeTestEnvelope(), cred, rb(0x59, 16), rb(0x47, 32))

	cache := NewWrapNonceReplayCache()
	if ok, err := cache.InsertIfAbsentUntil(expiring, 900, 100); err != nil || !ok {
		t.Fatalf("expiring insert = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := cache.InsertIfAbsent(permanent); err != nil || !ok {
		t.Fatalf("permanent insert = (%v, %v), want (true, nil)", ok, err)
	}
	// Duplicate detection holds inside the window for both record kinds.
	if ok, err := cache.InsertIfAbsentUntil(expiring, 900, 200); err != nil || ok {
		t.Fatalf("duplicate retained insert = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := cache.InsertIfAbsent(permanent); err != nil || ok {
		t.Fatalf("duplicate permanent insert = (%v, %v), want (false, nil)", ok, err)
	}
	// The next retained insert after t=900 sweeps the expired record only.
	if ok, err := cache.InsertIfAbsentUntil(later, 2000, 1000); err != nil || !ok {
		t.Fatalf("sweep-triggering insert = (%v, %v), want (true, nil)", ok, err)
	}
	if wrapNonceCacheRetains(t, cache, expiring) {
		t.Fatal("expired wrap nonce record survived the sweep")
	}
	if !wrapNonceCacheRetains(t, cache, permanent) {
		t.Fatal("permanent wrap nonce record was swept")
	}
	// The evicted key may be inserted again past its horizon; the envelope
	// itself remains unacceptable because its access hint is expired.
	if ok, err := cache.InsertIfAbsentUntil(expiring, 2500, 1000); err != nil || !ok {
		t.Fatalf("re-insert after eviction = (%v, %v), want (true, nil)", ok, err)
	}
}

// An envelope whose retention window is already closed at presentation is
// rejected fail-closed by the wrap-nonce cache before the access-hint spend.
func TestOpenAndVerifyPrivatePreludeRejectsEnvelopePastRetentionWindow(t *testing.T) {
	env := routeTestEnvelope()
	cred := routeTestAccessHintCredential(env) // ExpiryUnix 200
	env, envelope := sealWrapNonceTestEnvelope(t, env, cred, rb(0x5a, 16), rb(0x45, 32))
	accessCache := admission.NewMemoryReplayCache()
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(accessCache, NewWrapNonceReplayCache(), env, envelope, cred, 1000, 300); err == nil {
		t.Fatal("envelope whose retention window closed before presentation was accepted")
	}
	spentKey, err := admission.ComputeSpentHintKey(cred)
	if err != nil {
		t.Fatal(err)
	}
	if accessCache.Has(spentKey) {
		t.Fatal("access hint was spent for an envelope rejected by the wrap nonce cache")
	}
}
