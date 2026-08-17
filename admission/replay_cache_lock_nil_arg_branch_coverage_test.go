package admission

// Adversarial white-box coverage for the count-0 first-statement nil-argument
// safety guards on the replay-cache file lock helpers. lockReplayCacheFile and
// unlockReplayCacheFile each begin with `if file == nil { return ... }` so a
// caller that passes a nil *os.File does not panic or proceed into the
// platform-specific lock primitive (unix.Flock on _unix, windows.LockFileEx on
// _windows, or the unsupported-error path on _other) or dereference file.Fd().
// The existing admission tests only ever drive a populated *os.File along the
// live replay-cache path, so the nil guards stayed count-0 even though each is
// plainly reachable.
//
// The lock helpers are defined once per build target across three mutually
// exclusive source files (replay_cache_lock_unix.go, _windows.go, _other.go),
// each carrying the identical `file == nil` first-statement guard returning
// "admission: replay cache is closed". This test file carries NO build tag,
// so it compiles on every platform and exercises whichever variant is active
// (the _unix variant on linux/darwin/bsd, which the coverage floor measures;
// the _windows variant on windows). The guard and its message are identical
// across all three, so the single assertion is valid on every platform.
//
// This is a nil-ARGUMENT first-statement guard on unexported helpers, so the
// test is in-package (package admission). No context is involved, so there is
// no SA1012 surface. No filesystem, no real file descriptor, no lock primitive
// — each guard returns before file.Fd() / the platform lock call, so the test
// is pure and cannot perturb the replay-cache integration tests.
//
//   - replay_cache_lock_unix.go:15  lockReplayCacheFile(file *os.File)
//     file == nil -> "admission: replay cache is closed" (fires before
//     unix.Flock(file.Fd(), LOCK_EX))
//   - replay_cache_lock_unix.go:25  unlockReplayCacheFile(file *os.File)
//     file == nil -> "admission: replay cache is closed" (fires before
//     unix.Flock(file.Fd(), LOCK_UN))
//
// This test file adds only a TestXxx entry point and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestReplayCacheFileLockNilArgumentGuards(t *testing.T) {
	// 15/25: lockReplayCacheFile(nil) / unlockReplayCacheFile(nil) return at the
	// first statement rather than dereferencing file.Fd() or invoking the
	// platform lock primitive. The "replay cache is closed" message
	// distinguishes the nil-argument path from a non-nil file that hits the
	// platform-specific lock error.
	if err := lockReplayCacheFile(nil); err == nil {
		t.Fatal("lockReplayCacheFile(nil) err = nil, want non-nil (:15 should reject)")
	} else if !strings.Contains(err.Error(), "replay cache is closed") {
		t.Fatalf("lockReplayCacheFile(nil) err = %q, want substring \"replay cache is closed\" (:15)", err.Error())
	}

	if err := unlockReplayCacheFile(nil); err == nil {
		t.Fatal("unlockReplayCacheFile(nil) err = nil, want non-nil (:25 should reject)")
	} else if !strings.Contains(err.Error(), "replay cache is closed") {
		t.Fatalf("unlockReplayCacheFile(nil) err = %q, want substring \"replay cache is closed\" (:25)", err.Error())
	}
}
