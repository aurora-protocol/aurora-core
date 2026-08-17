package admission

// Adversarial white-box coverage for three count-0 nil-safety guards in the
// retention file replay cache (a sibling of FileReplayCache): a nil-directory
// constructor-arg guard, a nil-receiver entry guard, and a nil-directory field
// guard on the insert path.
//
//   - replay_cache_retention.go:35 NewRetentionFileReplayCacheAt
//     directory == nil -> return "admission: retention replay cache directory
//     entry is invalid" (the first clause of the compound :35 guard; short-
//     circuits before name / nowUnix validation).
//   - replay_cache_retention.go:70 (*RetentionFileReplayCache).InsertIfAbsentUntil
//     c == nil -> return "admission: replay cache retention window is invalid"
//     (the first clause of the compound :70 guard; short-circuits before the
//     !ready-style field derefs, so a nil receiver is safe).
//   - replay_cache_retention.go:78 (*RetentionFileReplayCache).InsertIfAbsentUntil
//     c.directory == nil -> return "admission: replay cache is closed" (fires
//     after the :70 receiver/window guard and the :73 empty-key guard and the
//     :76 c.mu.Lock, before any seen map or file IO).
//
// The existing admission tests construct a real retention cache (valid
// directory + lock + seen) and drive InsertIfAbsentUntil only on the success
// and key/empty paths, so :35 / :70 / :78 stayed count-0 even though each is
// plainly reachable with a nil directory arg, a nil receiver, or a zero-value
// cache.
//
// Proof technique:
//   - :35 (nil-arg clean return): NewRetentionFileReplayCacheAt(nil, "cache", 1)
//     — directory == nil short-circuits the compound :35 guard before name /
//     nowUnix are inspected, so :36 returns. The valid name / nowUnix rule out
//     the sibling clauses, isolating the directory == nil branch.
//   - :70 (nil-receiver clean return): (*RetentionFileReplayCache)(nil).
//     InsertIfAbsentUntil([]byte("k"), 2, 1) — c == nil short-circuits the
//     compound :70 guard before any field deref, so :71 returns. Calling a
//     method on a nil *RetentionFileReplayCache is safe because :70 is the
//     first statement and guards the receiver.
//   - :78 (nil-field clean return): (&RetentionFileReplayCache{}).
//     InsertIfAbsentUntil([]byte("k"), 2, 1) — a non-nil receiver with valid
//     key/window args passes :70 and :73, locks the zero-value c.mu at :76
//     (a usable zero-value mutex), and :78 sees c.directory == nil and returns
//     before any seen map or file IO. The deferred :77 Unlock balances the
//     :76 Lock on return. Pure (no IO; the guard returns before the file/seen
//     paths).
//
// No context is involved, so there is no SA1012 surface. No network, no
// goroutine, no file IO — :35 returns before openReplayCacheFileAt; :70
// returns before c.mu is touched; :78 returns before the seen map / files.
// In-package (package admission) because NewRetentionFileReplayCacheAt,
// InsertIfAbsentUntil, and RetentionFileReplayCache are in-package (the
// first two are exported, so this could be an external test, but in-package
// matches the sibling FileReplayCache coverage test).
//
// This test file adds only TestXxx entry points and references the exported
// NewRetentionFileReplayCacheAt / RetentionFileReplayCache.InsertIfAbsentUntil
// symbols and the standard library strings / testing packages, so it adds no
// U1000 surface.

import (
	"strings"
	"testing"
)

func TestNewRetentionFileReplayCacheAtNilDirectoryGuard(t *testing.T) {
	// 35: a nil directory short-circuits the compound guard before name / nowUnix
	// are inspected; :36 returns. The valid name / nowUnix isolate the directory
	// == nil branch (the sibling clauses are all false).
	_, err := NewRetentionFileReplayCacheAt(nil, "cache", 1)
	if err == nil {
		t.Fatal("NewRetentionFileReplayCacheAt(nil dir) returned nil, want non-nil (:36)")
	}
	if !strings.Contains(err.Error(), "retention replay cache directory entry is invalid") {
		t.Fatalf("NewRetentionFileReplayCacheAt nil-dir err = %q, want \"...directory entry is invalid\" (:36)", err.Error())
	}
}

func TestRetentionFileReplayCacheInsertIfAbsentUntilNilReceiverGuard(t *testing.T) {
	// 70: c == nil short-circuits the compound guard before any field deref;
	// :71 returns. Calling the method on a nil receiver is safe because :70 is
	// the first statement.
	_, err := (*RetentionFileReplayCache)(nil).InsertIfAbsentUntil([]byte("k"), 2, 1)
	if err == nil {
		t.Fatal("InsertIfAbsentUntil(nil receiver) returned nil, want non-nil (:71)")
	}
	if !strings.Contains(err.Error(), "replay cache retention window is invalid") {
		t.Fatalf("InsertIfAbsentUntil nil-receiver err = %q, want \"...retention window is invalid\" (:71)", err.Error())
	}
}

func TestRetentionFileReplayCacheInsertIfAbsentUntilNilDirectoryGuard(t *testing.T) {
	// 78: a non-nil zero-value receiver with valid key/window args passes :70
	// and :73, locks the zero-value c.mu at :76, and :78 sees c.directory == nil
	// and returns "replay cache is closed" before any seen map / file IO.
	_, err := (&RetentionFileReplayCache{}).InsertIfAbsentUntil([]byte("k"), 2, 1)
	if err == nil {
		t.Fatal("InsertIfAbsentUntil(zero cache) returned nil, want non-nil (:79)")
	}
	if !strings.Contains(err.Error(), "replay cache is closed") {
		t.Fatalf("InsertIfAbsentUntil nil-directory err = %q, want \"...replay cache is closed\" (:79)", err.Error())
	}
}
