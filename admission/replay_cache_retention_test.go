package admission

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionFileReplayCacheCompactsExpiredEntries(t *testing.T) {
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	defer cache.Close()
	if inserted, err := cache.InsertIfAbsentUntil([]byte("expired"), 101, 100); err != nil || !inserted {
		t.Fatalf("insert expiring key: inserted=%t err=%v", inserted, err)
	}
	if inserted, err := cache.InsertIfAbsentUntil([]byte("live"), 200, 101); err != nil || !inserted {
		t.Fatalf("insert live key: inserted=%t err=%v", inserted, err)
	}
	if inserted, err := cache.InsertIfAbsentUntil([]byte("next"), 300, 102); err != nil || !inserted {
		t.Fatalf("prune and insert: inserted=%t err=%v", inserted, err)
	}
	if cache.Has([]byte("expired")) {
		t.Fatal("expired key remained resident")
	}
	if !cache.Has([]byte("live")) || !cache.Has([]byte("next")) {
		t.Fatal("live keys were lost")
	}
}

func TestRetentionFileReplayCacheKeepsLegacyEntry(t *testing.T) {
	directoryPath := t.TempDir()
	key := []byte("legacy")
	if err := os.WriteFile(filepath.Join(directoryPath, "replay.log"), []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	if inserted, err := cache.InsertIfAbsentUntil(key, 200, 100); err != nil || inserted {
		t.Fatalf("legacy duplicate decision: inserted=%t err=%v", inserted, err)
	}
}

func TestRetentionFileReplayCacheRejectsDuplicateAcrossInstances(t *testing.T) {
	directoryPath := t.TempDir()
	firstDirectory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewRetentionFileReplayCacheAt(firstDirectory, "replay.log", 100)
	if err != nil {
		_ = firstDirectory.Close()
		t.Fatal(err)
	}
	defer first.Close()
	secondDirectory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRetentionFileReplayCacheAt(secondDirectory, "replay.log", 100)
	if err != nil {
		_ = secondDirectory.Close()
		t.Fatal(err)
	}
	defer second.Close()
	if inserted, err := first.InsertIfAbsentUntil([]byte("key"), 200, 100); err != nil || !inserted {
		t.Fatalf("first insert: inserted=%t err=%v", inserted, err)
	}
	if inserted, err := second.InsertIfAbsentUntil([]byte("key"), 200, 100); err != nil || inserted {
		t.Fatalf("duplicate decision: inserted=%t err=%v", inserted, err)
	}
}
