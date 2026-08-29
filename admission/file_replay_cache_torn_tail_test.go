package admission

// Regression test: a crash can tear the final append of the file replay cache
// anywhere inside a record. Such a record was never acknowledged, because
// InsertIfAbsent syncs before reporting success, so the cache must repair the
// tail instead of refusing to open or appending behind it.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func appendTornFileReplayCacheTail(t *testing.T, path, tail string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open replay cache for tearing: %v", err)
	}
	if _, err := file.WriteString(tail); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close replay cache: %v", err)
	}
}

func TestFileReplayCacheRepairsTornTail(t *testing.T) {
	for _, testCase := range []struct {
		name string
		tail string
	}{
		{name: "unparseable", tail: hex.EncodeToString([]byte("torn"))[:5]},
		{name: "parseable", tail: hex.EncodeToString([]byte("torn"))},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "replay-cache.log")
			cache, err := NewFileReplayCache(path)
			if err != nil {
				t.Fatalf("NewFileReplayCache failed: %v", err)
			}
			if inserted, err := cache.InsertIfAbsent([]byte("first")); err != nil || !inserted {
				t.Fatalf("InsertIfAbsent(first) = %t, %v", inserted, err)
			}
			if err := cache.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}
			appendTornFileReplayCacheTail(t, path, testCase.tail)

			reopened, err := NewFileReplayCache(path)
			if err != nil {
				t.Fatalf("NewFileReplayCache after a torn append = %v, want a repaired cache", err)
			}
			if inserted, err := reopened.InsertIfAbsent([]byte("second")); err != nil || !inserted {
				t.Fatalf("InsertIfAbsent(second) = %t, %v", inserted, err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			final, err := NewFileReplayCache(path)
			if err != nil {
				t.Fatalf("NewFileReplayCache after the repair = %v", err)
			}
			defer final.Close()
			for _, key := range [][]byte{[]byte("first"), []byte("second")} {
				if !final.Has(key) {
					t.Fatalf("acknowledged key %q was lost across the torn append", key)
				}
			}
			if inserted, err := final.InsertIfAbsent([]byte("second")); err != nil || inserted {
				t.Fatalf("InsertIfAbsent(replayed second) = %t, %v, want false (fail closed)", inserted, err)
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(contents, []byte(testCase.tail+hex.EncodeToString([]byte("second")))) {
				t.Fatalf("the torn tail was concatenated with the next record: %q", contents)
			}
		})
	}
}
