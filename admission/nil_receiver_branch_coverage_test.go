package admission

// Adversarial white-box coverage for the count-0 nil-receiver first-statement
// safety guards on the FileReplayCache and RetentionFileReplayCache methods.
// Each guard exists so a caller that holds a nil *FileReplayCache or
// *RetentionFileReplayCache pointer does not panic: the method returns at its
// very first statement, before any field (c.mu, c.file, c.directory, c.lock) is
// dereferenced or any file is touched. The existing admission tests only ever
// drive caches built by the open/retention constructors (which never return a
// nil pointer) and exercise the happy read/insert/close path, so the nil-receiver
// guards stayed count-0 even though each is plainly reachable: call the method on
// a nil *T.
//
// These are nil-RECEIVER guards (none is a ctx==nil guard), so there is no SA1012
// surface. No file I/O, no network, no goroutine — each call returns at the first
// statement and never reaches the lock/file/retention body.
//
//   - replay_cache.go:197          FileReplayCache.InsertIfAbsent   c == nil
//     -> false, "admission: replay cache is closed"
//   - replay_cache.go:232          FileReplayCache.Has             c == nil -> false
//   - replay_cache.go:245          FileReplayCache.Close           c == nil -> nil
//   - replay_cache_retention.go:104 RetentionFileReplayCache.Has   c == nil -> false
//   - replay_cache_retention.go:117 RetentionFileReplayCache.Close c == nil -> nil
//
// NOTE: the admission package hosts the known flake TestRetentionFileReplayCache-
// MatchesFullReload (a retention full-reload comparison that races on timing).
// These nil-receiver guards are a SEPARATE code path — each returns at the first
// statement without touching files, locks, or retention state — so there is no
// overlap with that test. This test file adds only TestXxx entry points and uses
// existing exported symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestFileReplayCacheNilReceiverGuards(t *testing.T) {
	// 197/232/245: a nil *FileReplayCache returns at the first statement of
	// InsertIfAbsent / Has / Close rather than dereferencing c.mu / c.file.
	var c *FileReplayCache

	ok, err := c.InsertIfAbsent([]byte("k"))
	if ok {
		t.Fatal("nil.InsertIfAbsent ok = true, want false (:197 should reject the nil cache)")
	}
	if err == nil {
		t.Fatal("nil.InsertIfAbsent err = nil, want non-nil (:197 should return \"replay cache is closed\")")
	}
	if !strings.Contains(err.Error(), "replay cache is closed") {
		t.Fatalf("nil.InsertIfAbsent err = %q, want it to contain \"replay cache is closed\" (:197)", err.Error())
	}

	if c.Has([]byte("k")) {
		t.Fatal("nil.Has = true, want false (:232 should return false for the nil cache)")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:245 should return nil)", err)
	}
}

func TestRetentionFileReplayCacheNilReceiverGuards(t *testing.T) {
	// 104/117: a nil *RetentionFileReplayCache returns at the first statement of
	// Has / Close rather than dereferencing c.mu / c.directory / c.lock.
	var c *RetentionFileReplayCache

	if c.Has([]byte("k")) {
		t.Fatal("nil.Has = true, want false (:104 should return false for the nil cache)")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:117 should return nil)", err)
	}
}
