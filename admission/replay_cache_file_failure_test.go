package admission

// Failure-path coverage for the file replay cache openers in
// admission/replay_cache.go and the retention compaction paths in
// admission/replay_cache_retention.go. These tests pin the intended
// fail-closed behavior: a cache that cannot trust its on-disk state must
// refuse to open or insert rather than admit a replay.
//
// Deliberately NOT covered (dead-by-design without fault injection):
//   - replay_cache.go:179 (lock failure inside newFileReplayCache) and
//     replay_cache.go:188 (unlock failure): flock on a valid regular-file fd
//     effectively always succeeds, and the lock is taken with LOCK_EX (no
//     LOCK_NB), so a contending second opener would block rather than error.
//     A double-open "lock conflict" therefore cannot produce an error to
//     assert; the intended concurrent-open behavior is pinned instead by
//     TestFileReplayCacheRejectsDuplicateFromStaleOpenInstance and
//     TestRetentionFileReplayCacheRejectsDuplicateAcrossInstances.
//   - replay_cache_retention.go rewrite/advanceGeneration write, sync, and
//     rename failure branches: require an fd or directory that fails mid-way
//     through a compaction, not triggerable through the filesystem alone.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileReplayCacheFailsClosedOnCorruptCacheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay-cache.log")
	if err := os.WriteFile(path, []byte("not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := NewFileReplayCache(path)
	if cache != nil {
		_ = cache.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "malformed key") {
		t.Fatalf("corrupt cache open error = %v, want malformed key failure", err)
	}
}

func TestNewFileReplayCacheRejectsClosedFileHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay-cache.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	cache, err := newFileReplayCache(path, file)
	if cache != nil {
		_ = cache.Close()
	}
	if err == nil {
		t.Fatal("newFileReplayCache accepted a closed file handle")
	}
}
