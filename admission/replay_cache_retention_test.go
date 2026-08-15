package admission

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionFileReplayCacheCompactsExpiredEntries(t *testing.T) {
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
	contents, err := os.ReadFile(filepath.Join(directoryPath, "replay.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString([]byte("live")) + "\t200\n" + hex.EncodeToString([]byte("next")) + "\t300\n"
	if string(contents) != want {
		t.Fatalf("compacted cache contents = %q, want %q", contents, want)
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

func TestRetentionFileReplayCacheRejectsMalformedDeadline(t *testing.T) {
	for _, deadline := range []string{"010", "200 "} {
		t.Run(deadline, func(t *testing.T) {
			directoryPath := t.TempDir()
			if err := os.WriteFile(filepath.Join(directoryPath, "replay.log"), []byte(hex.EncodeToString([]byte("key"))+"\t"+deadline+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			directory, err := os.Open(directoryPath)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			if cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100); err == nil || cache != nil {
				if cache != nil {
					_ = cache.Close()
				}
				t.Fatal("malformed retention deadline accepted")
			}
		})
	}
}

func TestRetentionFileReplayCacheRejectsEmptyKey(t *testing.T) {
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
	if inserted, err := cache.InsertIfAbsentUntil(nil, 200, 100); err == nil || inserted {
		t.Fatalf("empty key insert: inserted=%t err=%v", inserted, err)
	}
}

func TestRetentionFileReplayCacheRecoversStaleCompactionFile(t *testing.T) {
	directoryPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(directoryPath, "replay.log"), []byte(hex.EncodeToString([]byte("expired"))+"\t100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directoryPath, ".replay.log.compact"), []byte("incomplete"), 0o600); err != nil {
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
	if cache.Has([]byte("expired")) {
		t.Fatal("expired replay key remained resident")
	}
	contents, err := os.ReadFile(filepath.Join(directoryPath, "replay.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 0 {
		t.Fatalf("recovered cache contents = %q, want empty", contents)
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

func TestRetentionFileReplayCacheDoesNotExposeEntriesAfterClose(t *testing.T) {
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	key := []byte("key")
	if inserted, err := cache.InsertIfAbsentUntil(key, 200, 100); err != nil || !inserted {
		t.Fatalf("insert retained key: inserted=%t err=%v", inserted, err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	if cache.Has(key) {
		t.Fatal("closed replay cache exposed retained entry")
	}
}
