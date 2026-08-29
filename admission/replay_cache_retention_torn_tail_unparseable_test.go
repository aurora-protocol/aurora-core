package admission

// Regression test: a crash can tear the final append anywhere inside the
// record, not only between its fields. Such a tail (an odd number of hex
// digits, a dangling tab, a partial deadline) does not parse as a record. It
// was never acknowledged as inserted (append syncs before reporting success),
// so it must be repaired like any other torn tail instead of making the cache
// unopenable until an operator edits the file by hand.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionFileReplayCacheRepairsUnparseableTornTail(t *testing.T) {
	for name, tail := range map[string]string{
		"odd hex digits":    "deadbee",
		"dangling tab":      "deadbeef\t",
		"partial hex value": "deadbeef\tabc",
	} {
		t.Run(name, func(t *testing.T) {
			directoryPath := t.TempDir()
			cache := openRetentionCache(t, directoryPath, 100)
			if !mustInsert(t, cache, "alpha", 5000, 100) {
				t.Fatal("alpha was not inserted")
			}
			if err := cache.Close(); err != nil {
				t.Fatal(err)
			}
			dataPath := filepath.Join(directoryPath, "replay.log")
			file, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(tail); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			// Reopening after the crash must succeed and keep every completed record.
			directory, err := os.Open(directoryPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = directory.Close() })
			reopened, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 101)
			if err != nil {
				t.Fatalf("reopen after torn tail %q: %v", tail, err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			if !reopened.Has([]byte("alpha")) {
				t.Fatal("reopened cache lost the completed record")
			}
			if !mustInsert(t, reopened, "beta", 5000, 102) {
				t.Fatal("beta was not inserted")
			}
			// A completed record that follows the repair is not concatenated with
			// the torn bytes: a fresh handle parses the file from scratch.
			fresh := openRetentionCache(t, directoryPath, 103)
			for _, key := range []string{"alpha", "beta"} {
				if !fresh.Has([]byte(key)) {
					t.Fatalf("fresh cache lost record %q", key)
				}
			}
		})
	}
}
