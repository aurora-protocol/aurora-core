package admission

import (
	"encoding/binary"
	"testing"
)

func BenchmarkMemoryReplayCacheInsert32(b *testing.B) {
	cache := NewMemoryReplayCache()
	key := make([]byte, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(key[24:], uint64(i))
		inserted, err := cache.InsertIfAbsent(key)
		if err != nil {
			b.Fatal(err)
		}
		if !inserted {
			b.Fatal("unique replay key was already present")
		}
	}
}

func BenchmarkMemoryReplayCacheHasDuplicate32(b *testing.B) {
	cache := NewMemoryReplayCache()
	key := make([]byte, 32)
	if inserted, err := cache.InsertIfAbsent(key); err != nil || !inserted {
		b.Fatal("failed to seed replay cache")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !cache.Has(key) {
			b.Fatal("duplicate replay key was not found")
		}
	}
}
