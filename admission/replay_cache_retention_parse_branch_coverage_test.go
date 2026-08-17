package admission

// Adversarial white-box branch coverage for the two count-0 parse-rejection guards
// in RetentionFileReplayCache.parseRecord (admission/replay_cache_retention.go):
//
//	func (c *RetentionFileReplayCache) parseRecord(record string) (string, uint64, error) {
//	    fields := strings.Split(record, "\t")
//	    if len(fields) > 2 || len(fields) == 2 && fields[1] == "" {           // :218 <-- COUNT 0
//	        return "", 0, fmt.Errorf("... malformed entry", c.path)
//	    }
//	    key, err := hex.DecodeString(fields[0])
//	    if err != nil || len(key) == 0 || hex.EncodeToString(key) != fields[0] { // :222 <-- COUNT 0
//	        return "", 0, fmt.Errorf("... malformed key", c.path)
//	    }
//	    ...
//	}
//
// parseRecord is reached via the real entry point: NewRetentionFileReplayCacheAt ->
// withLock -> load -> consume -> parseRecord. The malformed-deadline guard (:228) is
// already covered by TestRetentionFileReplayCacheRejectsMalformedDeadline (which pre-seeds
// a record whose deadline field fails strconv.ParseUint/FormatUint round-trip). The two
// EARLIER guards (:218 field-count, :222 key hex) are not: every existing fixture uses a
// valid lowercase hex key with zero or one well-formed deadline field, so :218/:222 stay
// count 0. This file pre-seeds a malformed record file and asserts the constructor rejects
// it, mirroring the existing malformed-deadline test exactly:
//
//	- :218 "too many fields"      -> hex(key)+"\t100\textra\n" (3 fields)      -> :218 before hex decode
//	- :218 "empty deadline field" -> hex(key)+"\t\n"            (2 fields, 2nd empty) -> :218 before hex decode
//	- :222 "malformed key"        -> "ZZ\t100\n"                (invalid hex key)     -> :222 (hex.DecodeString fails)
//
// The field-count guard (:218) is checked BEFORE hex.DecodeString (:221), so a too-many-
// fields or empty-deadline-field record is rejected as a malformed entry regardless of the
// key. The malformed-key subtest uses a two-field record with a non-empty deadline so it
// skips :218 and reaches :221, where hex.DecodeString("ZZ") fails and :222 fires. All three
// pre-seeded files are read by load (openReplayCacheFileAt opens existing content without
// truncating, as the existing malformed-deadline test relies on). The per-line coverage
// flips (:218 0->1, :222 0->1) are the rigorous proof.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionFileReplayCacheRejectsMalformedRecord(t *testing.T) {
	// :218 — a record with more than two tab-separated fields is rejected as a malformed
	// entry at :218, before the key is decoded at :221.
	t.Run("too many fields", func(t *testing.T) {
		directoryPath := t.TempDir()
		if err := os.WriteFile(filepath.Join(directoryPath, "replay.log"), []byte(hex.EncodeToString([]byte("key"))+"\t100\textra\n"), 0o600); err != nil {
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
			t.Fatal("malformed entry (too many fields) accepted")
		}
	})

	// :218 — a two-field record whose deadline field is empty (a trailing tab) is rejected
	// as a malformed entry at :218, before the key is decoded.
	t.Run("empty deadline field", func(t *testing.T) {
		directoryPath := t.TempDir()
		if err := os.WriteFile(filepath.Join(directoryPath, "replay.log"), []byte(hex.EncodeToString([]byte("key"))+"\t\n"), 0o600); err != nil {
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
			t.Fatal("malformed entry (empty deadline field) accepted")
		}
	})

	// :222 — a record whose key is not valid lowercase hex is rejected as a malformed key
	// at :222 (hex.DecodeString fails). The deadline field is well-formed and non-empty so
	// the record skips :218 and reaches the hex decode at :221.
	t.Run("malformed key", func(t *testing.T) {
		directoryPath := t.TempDir()
		if err := os.WriteFile(filepath.Join(directoryPath, "replay.log"), []byte("ZZ\t100\n"), 0o600); err != nil {
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
			t.Fatal("malformed key accepted")
		}
	})
}
