package admission

import (
	"encoding/binary"
	"testing"
)

func memoryCacheResident(cache *MemoryReplayCache) int {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.seen)
}

// TestMemoryReplayCacheReclaimsUnrepeatedKeys covers the shape that matters for
// one-time credentials: distinct keys that are never presented again. A cache
// that only expired a record when its own key returned would hold every one of
// them for the process lifetime.
func TestMemoryReplayCacheReclaimsUnrepeatedKeys(t *testing.T) {
	cache := NewMemoryReplayCache()
	key := make([]byte, 32)
	const records = 5000
	for i := 0; i < records; i++ {
		binary.BigEndian.PutUint64(key[24:], uint64(i))
		now := uint64(100 + i)
		inserted, err := cache.InsertIfAbsentUntil(key, now+10, now)
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		if !inserted {
			t.Fatalf("unique key %d was reported as a duplicate", i)
		}
	}
	// Each record is retained for ten seconds and the clock advances by one
	// second per insert, so only the most recent handful may remain resident.
	if resident := memoryCacheResident(cache); resident > 12 {
		t.Fatalf("cache retained %d records, want at most 12", resident)
	}
}

func TestMemoryReplayCacheKeepsUnexpiredRecords(t *testing.T) {
	cache := NewMemoryReplayCache()
	if inserted, err := cache.InsertIfAbsentUntil([]byte("short"), 110, 100); err != nil || !inserted {
		t.Fatalf("insert short: inserted=%t err=%v", inserted, err)
	}
	if inserted, err := cache.InsertIfAbsentUntil([]byte("long"), 5000, 100); err != nil || !inserted {
		t.Fatalf("insert long: inserted=%t err=%v", inserted, err)
	}
	// Advancing past the first deadline must drop only the expired record.
	if inserted, err := cache.InsertIfAbsentUntil([]byte("next"), 5000, 200); err != nil || !inserted {
		t.Fatalf("insert next: inserted=%t err=%v", inserted, err)
	}
	if cache.Has([]byte("short")) {
		t.Fatal("expired record stayed resident")
	}
	if !cache.Has([]byte("long")) || !cache.Has([]byte("next")) {
		t.Fatal("unexpired records were dropped")
	}
	// The dropped record is spendable again, exactly as before the sweep.
	if inserted, err := cache.InsertIfAbsentUntil([]byte("short"), 5000, 200); err != nil || !inserted {
		t.Fatalf("expired key was not reusable: inserted=%t err=%v", inserted, err)
	}
	// A live record is still rejected.
	if inserted, err := cache.InsertIfAbsentUntil([]byte("long"), 5000, 200); err != nil || inserted {
		t.Fatalf("live key was accepted twice: inserted=%t err=%v", inserted, err)
	}
}

func TestMemoryReplayCacheKeepsRecordsWithoutRetention(t *testing.T) {
	cache := NewMemoryReplayCache()
	if inserted, err := cache.InsertIfAbsent([]byte("permanent")); err != nil || !inserted {
		t.Fatalf("insert permanent: inserted=%t err=%v", inserted, err)
	}
	if inserted, err := cache.InsertIfAbsentUntil([]byte("expiring"), 110, 100); err != nil || !inserted {
		t.Fatalf("insert expiring: inserted=%t err=%v", inserted, err)
	}
	if inserted, err := cache.InsertIfAbsentUntil([]byte("trigger"), 1_000_000, 999_999); err != nil || !inserted {
		t.Fatalf("insert trigger: inserted=%t err=%v", inserted, err)
	}
	if !cache.Has([]byte("permanent")) {
		t.Fatal("record inserted without retention was reclaimed")
	}
	if cache.Has([]byte("expiring")) {
		t.Fatal("expired record stayed resident")
	}
	if inserted, err := cache.InsertIfAbsentUntil([]byte("permanent"), 1_000_000, 999_999); err != nil || inserted {
		t.Fatalf("record without retention was accepted twice: inserted=%t err=%v", inserted, err)
	}
}
