package admission

// Regression test: a crash can tear the final append, leaving a syntactically
// valid but unterminated record at the end of the data file. consume parses
// that record into seen (fail-closed) but deliberately does not consume it.
// The next insert then appends at EOF, concatenating the torn bytes with the
// new record into one malformed on-disk line, and advances loadedSize past
// bytes it never parsed. The cache must repair the torn tail (rewrite) instead
// of appending after it; otherwise the next full reload fails and the
// incremental reload can even fabricate a phantom record from mid-line bytes.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionFileReplayCacheRepairsTornTailBeforeAppend(t *testing.T) {
	directoryPath := t.TempDir()
	cache := openRetentionCache(t, directoryPath, 100)
	if !mustInsert(t, cache, "alpha", 5000, 100) {
		t.Fatal("alpha was not inserted")
	}

	// Simulate a crash in the middle of an append: a complete-looking record
	// without its terminating newline sits at the end of the file.
	dataPath := filepath.Join(directoryPath, "replay.log")
	file, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	tornKey, err := hex.DecodeString("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("deadbeef\t999"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	// The first insert after the crash must not append behind the torn record.
	if !mustInsert(t, cache, "beta", 5000, 101) {
		t.Fatal("beta was not inserted")
	}
	// In-process operation must keep working.
	if !mustInsert(t, cache, "gamma", 5000, 102) {
		t.Fatal("gamma was not inserted")
	}

	// A fresh handle reparses the file from scratch; the torn line must have
	// been repaired instead of corrupting the record that followed it.
	fresh := openRetentionCache(t, directoryPath, 103)
	for _, key := range []string{"alpha", "beta", "gamma"} {
		if !fresh.Has([]byte(key)) {
			t.Fatalf("reopened cache lost record %q", key)
		}
	}
	// The torn record was parsed fail-closed and must remain spent.
	if !fresh.Has(tornKey) {
		t.Fatal("reopened cache lost the torn record")
	}
	if inserted, err := fresh.InsertIfAbsentUntil(tornKey, 5000, 104); err != nil || inserted {
		t.Fatalf("torn key reinserted = %t, %v; want duplicate", inserted, err)
	}
}
