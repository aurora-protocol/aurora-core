package admission

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func openRetentionCache(t *testing.T, directoryPath string, nowUnix uint64) *RetentionFileReplayCache {
	t.Helper()
	directory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", nowUnix)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cache.Close()
		_ = directory.Close()
	})
	return cache
}

func mustInsert(t *testing.T, cache *RetentionFileReplayCache, key string, retainUntil, now uint64) bool {
	t.Helper()
	inserted, err := cache.InsertIfAbsentUntil([]byte(key), retainUntil, now)
	if err != nil {
		t.Fatalf("insert %q: %v", key, err)
	}
	return inserted
}

func TestRetentionFileReplayCacheSeesConcurrentAppends(t *testing.T) {
	directoryPath := t.TempDir()
	first := openRetentionCache(t, directoryPath, 100)
	second := openRetentionCache(t, directoryPath, 100)

	if !mustInsert(t, first, "alpha", 500, 100) {
		t.Fatal("first handle did not insert alpha")
	}
	if mustInsert(t, second, "alpha", 500, 101) {
		t.Fatal("second handle missed a record appended by the first handle")
	}
	if !mustInsert(t, second, "beta", 500, 101) {
		t.Fatal("second handle did not insert beta")
	}
	if mustInsert(t, first, "beta", 500, 102) {
		t.Fatal("first handle missed a record appended by the second handle")
	}
	if mustInsert(t, first, "alpha", 500, 102) {
		t.Fatal("first handle accepted its own record twice")
	}
}

func TestRetentionFileReplayCacheReloadsAfterConcurrentCompaction(t *testing.T) {
	directoryPath := t.TempDir()
	first := openRetentionCache(t, directoryPath, 100)
	second := openRetentionCache(t, directoryPath, 100)

	if !mustInsert(t, first, "expiring", 200, 100) {
		t.Fatal("expiring record was not inserted")
	}
	// Grow the file well past the offset the first handle has consumed, so the
	// compacted file stays larger than that offset. A cache that trusted its
	// offset would resume reading in the middle of the replacement file.
	for _, key := range []string{"durable-a", "durable-b", "durable-c", "durable-d", "durable-e"} {
		if !mustInsert(t, second, key, 5000, 100) {
			t.Fatalf("%s was not inserted", key)
		}
	}
	// The second handle passes the first record's deadline, so its insert
	// compacts the file and replaces the directory entry.
	if !mustInsert(t, second, "later", 5000, 300) {
		t.Fatal("later record was not inserted")
	}
	if second.Has([]byte("expiring")) {
		t.Fatal("expired record survived compaction")
	}
	info, err := os.Stat(filepath.Join(directoryPath, "replay.log"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= first.loadedSize {
		t.Fatalf("compacted file is %d bytes, which does not exceed the stale offset %d", info.Size(), first.loadedSize)
	}

	// The first handle must notice the replacement rather than trusting the
	// offset it had already consumed.
	if mustInsert(t, first, "later", 5000, 301) {
		t.Fatal("first handle missed a record written before compaction")
	}
	if mustInsert(t, first, "durable-c", 5000, 301) {
		t.Fatal("first handle lost a live record across compaction")
	}
	if !first.Has([]byte("durable-a")) || !first.Has([]byte("later")) {
		t.Fatal("first handle did not reload the compacted file")
	}
}

func TestRetentionFileReplayCacheReloadsAfterTruncation(t *testing.T) {
	directoryPath := t.TempDir()
	cache := openRetentionCache(t, directoryPath, 100)
	if !mustInsert(t, cache, "first", 5000, 100) {
		t.Fatal("record was not inserted")
	}
	if err := os.Truncate(filepath.Join(directoryPath, "replay.log"), 0); err != nil {
		t.Fatal(err)
	}
	// A truncated file cannot prove the record was retained, so the cache must
	// reparse instead of reporting a duplicate from stale memory.
	if !mustInsert(t, cache, "first", 5000, 101) {
		t.Fatal("cache did not reload after truncation")
	}
	contents, err := os.ReadFile(filepath.Join(directoryPath, "replay.log"))
	if err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString([]byte("first")) + "\t5000\n"; string(contents) != want {
		t.Fatalf("cache contents = %q, want %q", contents, want)
	}
}

func TestRetentionFileReplayCacheExpiresResidentRecords(t *testing.T) {
	directoryPath := t.TempDir()
	cache := openRetentionCache(t, directoryPath, 100)
	if !mustInsert(t, cache, "short", 200, 100) {
		t.Fatal("short record was not inserted")
	}
	if !mustInsert(t, cache, "long", 5000, 100) {
		t.Fatal("long record was not inserted")
	}
	// "short" was resident and unexpired when it was loaded; advancing the clock
	// must still drop it.
	if !mustInsert(t, cache, "next", 5000, 300) {
		t.Fatal("next record was not inserted")
	}
	if cache.Has([]byte("short")) {
		t.Fatal("record past its retention deadline stayed resident")
	}
	if !cache.Has([]byte("long")) || !cache.Has([]byte("next")) {
		t.Fatal("live records were dropped")
	}
	contents, err := os.ReadFile(filepath.Join(directoryPath, "replay.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString([]byte("long")) + "\t5000\n" + hex.EncodeToString([]byte("next")) + "\t5000\n"
	if string(contents) != want {
		t.Fatalf("cache contents = %q, want %q", contents, want)
	}
}

// TestRetentionFileReplayCacheMatchesFullReload drives two handles over the same
// directory with randomized inserts and an advancing clock, and checks every
// decision against a model that keeps unexpired records. It also reopens the
// directory to confirm the on-disk state agrees with resident state.
func TestRetentionFileReplayCacheMatchesFullReload(t *testing.T) {
	directoryPath := t.TempDir()
	handles := []*RetentionFileReplayCache{
		openRetentionCache(t, directoryPath, 100),
		openRetentionCache(t, directoryPath, 100),
	}
	model := map[string]uint64{}
	random := rand.New(rand.NewSource(7))
	now := uint64(100)

	key := make([]byte, 8)
	for step := 0; step < 600; step++ {
		now += uint64(random.Intn(4))
		// Reuse a small key space so duplicates and expiries both occur.
		binary.BigEndian.PutUint64(key, uint64(random.Intn(40)))
		retainUntil := now + 1 + uint64(random.Intn(12))
		handle := handles[random.Intn(len(handles))]

		for modelKey, deadline := range model {
			if deadline <= now {
				delete(model, modelKey)
			}
		}
		_, present := model[string(key)]
		want := !present

		inserted, err := handle.InsertIfAbsentUntil(key, retainUntil, now)
		if err != nil {
			t.Fatalf("step %d: insert: %v", step, err)
		}
		if inserted != want {
			t.Fatalf("step %d: key %x at now=%d inserted=%t, want %t", step, key, now, inserted, want)
		}
		if inserted {
			model[string(key)] = retainUntil
		}
	}

	// A fresh handle reparses the file from scratch and must agree.
	fresh := openRetentionCache(t, directoryPath, now)
	for modelKey := range model {
		if !fresh.Has([]byte(modelKey)) {
			t.Fatalf("reopened cache lost record %x", modelKey)
		}
	}
	for i := 0; i < 40; i++ {
		binary.BigEndian.PutUint64(key, uint64(i))
		_, present := model[string(key)]
		if got := fresh.Has(key); got != present {
			t.Fatalf("reopened cache reports key %x resident=%t, want %t", key, got, present)
		}
	}
}

func BenchmarkRetentionFileReplayCacheInsert(b *testing.B) {
	for _, resident := range []int{0, 1_000, 20_000} {
		b.Run(residentName(resident), func(b *testing.B) {
			directory, err := os.Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			defer directory.Close()
			cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100)
			if err != nil {
				b.Fatal(err)
			}
			defer cache.Close()
			key := make([]byte, 32)
			for i := 0; i < resident; i++ {
				binary.BigEndian.PutUint64(key[24:], uint64(i))
				if _, err := cache.InsertIfAbsentUntil(key, 1<<40, 100); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				binary.BigEndian.PutUint64(key[24:], uint64(resident+i))
				if _, err := cache.InsertIfAbsentUntil(key, 1<<40, 100); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func residentName(resident int) string {
	switch resident {
	case 0:
		return "empty"
	case 1_000:
		return "1k-records"
	default:
		return "20k-records"
	}
}

// TestRetentionFileReplayCacheInsertDoesNotScaleWithResidentRecords guards the
// property that makes admission affordable: an insert consumes only the records
// appended since the last one, so its allocation count must not grow with the
// number of records the cache already holds. Reparsing the whole file on each
// insert regresses this by orders of magnitude.
func TestRetentionFileReplayCacheInsertDoesNotScaleWithResidentRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("insert allocation measurement performs durable writes")
	}
	measure := func(resident int) float64 {
		directory, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		cache, err := NewRetentionFileReplayCacheAt(directory, "replay.log", 100)
		if err != nil {
			t.Fatal(err)
		}
		defer cache.Close()
		key := make([]byte, 32)
		next := 0
		insert := func() {
			binary.BigEndian.PutUint64(key[24:], uint64(next))
			next++
			inserted, err := cache.InsertIfAbsentUntil(key, 1<<40, 100)
			if err != nil {
				t.Fatalf("insert: %v", err)
			}
			if !inserted {
				t.Fatal("unique key was reported as a duplicate")
			}
		}
		for i := 0; i < resident; i++ {
			insert()
		}
		return testing.AllocsPerRun(5, insert)
	}

	const (
		fewRecords  = 100
		manyRecords = 1000
	)
	small := measure(fewRecords)
	large := measure(manyRecords)
	// Ten times more resident records must not cost meaningfully more
	// allocations. The slack absorbs map growth, not per-record parsing.
	if limit := small + 24; large > limit {
		t.Fatalf("insert allocated %.0f times with %d resident records and %.0f with %d; want at most %.0f",
			large, manyRecords, small, fewRecords, limit)
	}
}
