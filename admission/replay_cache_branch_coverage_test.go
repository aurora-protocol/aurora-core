package admission

// Adversarial white-box coverage for the in-memory MemoryReplayCache of
// admission/replay_cache.go. MemoryReplayCache is a plain map[string]uint64
// guarded by a sync.Mutex plus a minDeadline watermark; it holds no file
// handles, no goroutines, no cryptography, and no network or filesystem
// state. It is DISTINCT from FileReplayCache (139+, the file-backed cache
// that owns lockReplayCacheFile/load/WriteString/Sync and that hosts the
// flaky TestRetentionFileReplayCacheMatchesFullReload): this file covers
// ONLY the in-memory cache, so it cannot itself be a source of that race.
//
// The uncovered branches are the three nil-receiver guards (InsertIfAbsent,
// InsertIfAbsentUntil, Has — each returns before the mutex is taken) and the
// InsertIfAbsentUntil retention-window validation, which rejects a zero or
// non-monotonic window before the mutex is taken. Two semantic lifecycle
// tests ground the non-nil paths so the nil-guard assertions are meaningful
// contrasts, and lock the cache's core invariants — InsertIfAbsent
// first-time-true / duplicate-false, InsertIfAbsentUntil duplicate-false for
// a still-retained key, and expiry-driven re-acceptance after the earliest
// retained deadline has passed.
//
// Targets covered:
//
//   - InsertIfAbsent:70-72 — the `c == nil` guard. The existing suite always
//     constructs via NewMemoryReplayCache, so the "missing replay cache"
//     return is unreached. A typed nil *MemoryReplayCache returns before the
//     mutex is locked at 73.
//   - InsertIfAbsentUntil:84-86 — the `c == nil` guard. The existing suite
//     always constructs via NewMemoryReplayCache, so the "missing replay
//     cache" return is unreached. A typed nil *MemoryReplayCache returns
//     before the retention-window check at 87 runs (the args are never
//     inspected, so any values are safe).
//   - InsertIfAbsentUntil:87-89 — the retention-window validation. The
//     existing suite passes only strictly-monotonic nonzero windows, so the
//     "replay cache retention window is invalid" return is unreached. All
//     three sub-conditions are exercised: retainUntilUnix == 0, nowUnix == 0,
//     and retainUntilUnix <= nowUnix (both equal and strictly less).
//   - Has:130-132 — the `c == nil` guard. The existing suite always
//     constructs via NewMemoryReplayCache, so the nil-receiver false return
//     is unreached. A typed nil *MemoryReplayCache returns before the mutex
//     is locked at 133.
//
// Dead-by-design (documented, NOT claimed):
//   - InsertIfAbsentUntil:103 — the `delete(c.seen, k)` inside the
//     `if previous, ok` block at 99, taken only when previous != 0 AND
//     previous <= nowUnix (an expired-but-still-present retained record).
//     The minDeadline watermark is the earliest retained deadline, so a
//     record with deadline <= nowUnix implies minDeadline <= nowUnix, which
//     trips the expireLocked call at 95-97 and evicts every expired record
//     (deadline <= nowUnix) before the :99 lookup runs. By contrapositive,
//     when expireLocked does not run (minDeadline > nowUnix) no retained
//     record has deadline <= nowUnix either. So at :99 a surviving previous
//     is always either 0 (permanent, but InsertIfAbsentUntil never writes 0
//     — the :87 gate rejects retainUntilUnix == 0) or > nowUnix, and the
//     :103 delete branch is unreachable. Shadowed-by-earlier-expireLocked.
//
// No new package-level helpers or types are introduced (only test functions
// and inline literals), so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no cryptography, no
// real network or filesystem, and no FileReplayCache.

import (
	"strings"
	"testing"
)

func TestMemoryReplayCacheNilReceiversAreSafe(t *testing.T) {
	// A typed nil *MemoryReplayCache returns from each method before the
	// mutex is taken, so no nil dereference occurs and the args are never
	// inspected.
	var c *MemoryReplayCache

	// 70-72: InsertIfAbsent's nil-receiver guard.
	if _, err := c.InsertIfAbsent([]byte("k")); err == nil ||
		!strings.Contains(err.Error(), "admission: missing replay cache") {
		t.Fatalf("nil.InsertIfAbsent err = %v, want substring \"admission: missing replay cache\"", err)
	}

	// 84-86: InsertIfAbsentUntil's nil-receiver guard fires before the
	// retention-window check at 87, so any window values are safe.
	if _, err := c.InsertIfAbsentUntil([]byte("k"), 200, 100); err == nil ||
		!strings.Contains(err.Error(), "admission: missing replay cache") {
		t.Fatalf("nil.InsertIfAbsentUntil err = %v, want substring \"admission: missing replay cache\"", err)
	}

	// 130-132: Has's nil-receiver guard returns false before the mutex runs.
	if c.Has([]byte("k")) {
		t.Fatal("nil.Has = true, want false")
	}
}

func TestMemoryReplayCacheInsertIfAbsentUntilRejectsInvalidRetentionWindow(t *testing.T) {
	// 87-89: every invalid sub-condition returns the retention-window error
	// before the mutex is taken. A constructed cache keeps the window check
	// meaningful (a nil cache would return at 84 first).
	c := NewMemoryReplayCache()
	key := []byte("k")

	cases := []struct {
		name            string
		retainUntilUnix uint64
		nowUnix         uint64
	}{
		{"retainUntilUnix zero", 0, 100},
		{"nowUnix zero", 100, 0},
		{"retainUntilUnix equals nowUnix", 100, 100},
		{"retainUntilUnix before nowUnix", 50, 100},
	}
	for _, tc := range cases {
		ok, err := c.InsertIfAbsentUntil(key, tc.retainUntilUnix, tc.nowUnix)
		if err == nil ||
			!strings.Contains(err.Error(), "admission: replay cache retention window is invalid") {
			t.Fatalf("InsertIfAbsentUntil(%s) err = %v, want substring \"admission: replay cache retention window is invalid\"", tc.name, err)
		}
		if ok {
			t.Fatalf("InsertIfAbsentUntil(%s) ok = true, want false", tc.name)
		}
	}
}

func TestMemoryReplayCacheInsertIfAbsentDedupLifecycle(t *testing.T) {
	// Semantic lock for the non-nil InsertIfAbsent path so the :70 nil-guard
	// assertion is a meaningful contrast, and a lock on the cache's core
	// first-time-true / duplicate-false invariant.
	c := NewMemoryReplayCache()
	key := []byte("alpha")

	ok, err := c.InsertIfAbsent(key)
	if err != nil || !ok {
		t.Fatalf("InsertIfAbsent(first) = (%v, %v), want (true, nil)", ok, err)
	}
	if !c.Has(key) {
		t.Fatal("Has(key) = false after first InsertIfAbsent, want true")
	}

	ok2, err2 := c.InsertIfAbsent(key)
	if err2 != nil || ok2 {
		t.Fatalf("InsertIfAbsent(duplicate) = (%v, %v), want (false, nil)", ok2, err2)
	}
	if !c.Has(key) {
		t.Fatal("Has(key) = false after duplicate InsertIfAbsent, want true (permanent record retained)")
	}
}

func TestMemoryReplayCacheInsertIfAbsentUntilDedupAndExpiry(t *testing.T) {
	// Semantic lock for the non-nil InsertIfAbsentUntil path so the :84/:87
	// assertions are meaningful contrasts, and a lock on retained-key dedup
	// plus expiry-driven re-acceptance. Traces the minDeadline watermark
	// (InsertIfAbsentUntil:95-108) and expireLocked (112-127) but does NOT
	// reach the dead :103 delete (an expired retained record is always
	// evicted by expireLocked before the :99 lookup, see the file comment).
	c := NewMemoryReplayCache()
	keyA := []byte("a")
	keyB := []byte("b")

	// Insert keyA retained until 150 at now 100; minDeadline becomes 150.
	ok, err := c.InsertIfAbsentUntil(keyA, 150, 100)
	if err != nil || !ok {
		t.Fatalf("InsertIfAbsentUntil(keyA first) = (%v, %v), want (true, nil)", ok, err)
	}
	// Duplicate keyA, still retained (previous 150 > now 100): rejected.
	ok2, err2 := c.InsertIfAbsentUntil(keyA, 200, 100)
	if err2 != nil || ok2 {
		t.Fatalf("InsertIfAbsentUntil(keyA duplicate) = (%v, %v), want (false, nil)", ok2, err2)
	}
	if !c.Has(keyA) {
		t.Fatal("Has(keyA) = false after duplicate, want true (still retained)")
	}

	// Advance now to 160, past the earliest deadline (150). Inserting keyB
	// trips the :95 watermark and expireLocked(160) evicts keyA first.
	ok3, err3 := c.InsertIfAbsentUntil(keyB, 200, 160)
	if err3 != nil || !ok3 {
		t.Fatalf("InsertIfAbsentUntil(keyB) = (%v, %v), want (true, nil)", ok3, err3)
	}
	if c.Has(keyA) {
		t.Fatal("Has(keyA) = true after expiry at now 160, want false (evicted)")
	}
	if !c.Has(keyB) {
		t.Fatal("Has(keyB) = false, want true")
	}

	// keyA was evicted, so it is accepted again (the :99 lookup misses).
	ok4, err4 := c.InsertIfAbsentUntil(keyA, 250, 160)
	if err4 != nil || !ok4 {
		t.Fatalf("InsertIfAbsentUntil(keyA re-insert after expiry) = (%v, %v), want (true, nil)", ok4, err4)
	}
	if !c.Has(keyA) {
		t.Fatal("Has(keyA) = false after re-insert, want true")
	}
}
