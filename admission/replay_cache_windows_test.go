//go:build windows

package admission

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestWindowsFileReplayCacheIsDurable(t *testing.T) {
	if !replayCacheFileDurable() {
		t.Fatal("Windows file replay cache did not report durable locking")
	}
}

func TestWindowsFileReplayCacheSerializesConcurrentInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay-cache.log")
	first, err := NewFileReplayCache(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := NewFileReplayCache(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	for iteration := byte(0); iteration < 100; iteration++ {
		key := []byte{0x77, iteration}
		start := make(chan struct{})
		results := make(chan bool, 2)
		errors := make(chan error, 2)
		var callers sync.WaitGroup
		for _, cache := range []*FileReplayCache{first, second} {
			callers.Add(1)
			go func(cache *FileReplayCache) {
				defer callers.Done()
				<-start
				inserted, insertErr := cache.InsertIfAbsent(key)
				results <- inserted
				errors <- insertErr
			}(cache)
		}
		close(start)
		callers.Wait()

		insertedCount := 0
		for range 2 {
			if insertErr := <-errors; insertErr != nil {
				t.Fatal(insertErr)
			}
			if <-results {
				insertedCount++
			}
		}
		if insertedCount != 1 {
			t.Fatalf("iteration %d inserted key %d times, want 1", iteration, insertedCount)
		}
	}
}
