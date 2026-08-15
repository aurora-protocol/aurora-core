package main

import (
	"fmt"
	"sync"
	"testing"
	"unsafe"
)

func TestNativeOutputRegistryRecordsAllocationLength(t *testing.T) {
	p := unsafe.Pointer(new(byte))
	registerNativeOutput(p, 32)

	length, ok := takeNativeOutput(p)
	if !ok {
		t.Fatal("native output allocation was not registered")
	}
	if length != 32 {
		t.Fatalf("recorded output length = %d, want 32", length)
	}
}

func TestNativeOutputRegistryRejectsDuplicateRelease(t *testing.T) {
	p := unsafe.Pointer(new(byte))
	registerNativeOutput(p, 1)
	if _, ok := takeNativeOutput(p); !ok {
		t.Fatal("registered output was not released")
	}

	if _, ok := takeNativeOutput(p); ok {
		t.Fatal("released output remained registered")
	}
}

func TestNativeOutputRegistryReleasesConcurrentAllocations(t *testing.T) {
	const allocations = 128
	pointers := make([]*byte, allocations)
	for index := range pointers {
		pointers[index] = new(byte)
		registerNativeOutput(unsafe.Pointer(pointers[index]), index+1)
	}

	start := make(chan struct{})
	errors := make(chan error, allocations)
	var group sync.WaitGroup
	for index, p := range pointers {
		group.Add(1)
		go func(index int, p *byte) {
			defer group.Done()
			<-start
			length, ok := takeNativeOutput(unsafe.Pointer(p))
			if !ok || length != index+1 {
				errors <- fmt.Errorf("allocation %d: length=%d registered=%t", index, length, ok)
			}
		}(index, p)
	}
	close(start)
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
