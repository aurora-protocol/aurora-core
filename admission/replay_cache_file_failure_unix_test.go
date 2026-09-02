//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package admission

// Permission-driven failure paths for the file replay caches, unix-only
// because they rely on chmod-based permission denial. Each test restores
// directory permissions in a cleanup registered after t.TempDir so the
// testing framework can still remove the tree.
//
// The retention compaction tests pin fail-closed behavior: when the cache
// directory becomes unwritable, rewrite/advanceGeneration must surface the
// error so callers reject the spend (the inserted flag is only meaningful
// alongside a nil error — the record is already resident in memory when
// persistence fails, matching how TestVerifyAndSpendReplayFailsClosedWhenReplayCacheWriteFails
// treats any cache error as admission failure).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewFileReplayCacheRejectsUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based denial is ineffective as root")
	}
	directoryPath := t.TempDir()
	restricted := filepath.Join(directoryPath, "restricted")
	if err := os.Mkdir(restricted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(restricted, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(restricted, 0o700) })
	cache, err := NewFileReplayCache(filepath.Join(restricted, "replay-cache.log"))
	if cache != nil {
		_ = cache.Close()
	}
	if err == nil {
		t.Fatal("file replay cache opened inside a permission-denied directory")
	}
}

func TestRetentionFileReplayCacheCompactionFailsClosedWhenDirectoryReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based denial is ineffective as root")
	}
	directoryPath := t.TempDir()
	directory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	defer cache.Close()
	if inserted, err := cache.InsertIfAbsentUntil([]byte("expiring"), 150, 100); err != nil || !inserted {
		t.Fatalf("insert expiring key: inserted=%t err=%v", inserted, err)
	}
	if err := os.Chmod(directoryPath, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directoryPath, 0o700) })
	// now=200 expires the resident record, so the insert must compact; the
	// read-only directory makes the compaction temporary uncreatable and the
	// error must surface so the caller rejects the spend.
	if _, err := cache.InsertIfAbsentUntil([]byte("next"), 300, 200); err == nil {
		t.Fatal("compaction into a read-only directory succeeded")
	}
}

func TestRetentionFileReplayCacheAdvanceGenerationFailsWhenDirectoryReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based denial is ineffective as root")
	}
	directoryPath := t.TempDir()
	directory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	defer cache.Close()
	if err := os.Chmod(directoryPath, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directoryPath, 0o700) })
	if _, err := cache.advanceGeneration(); err == nil {
		t.Fatal("advanceGeneration succeeded in a read-only directory")
	}
}
