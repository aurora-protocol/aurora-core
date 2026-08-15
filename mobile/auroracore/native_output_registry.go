package main

import (
	"sync"
	"unsafe"
)

type nativeOutputRegistry struct {
	mu      sync.Mutex
	lengths map[unsafe.Pointer]int
}

var nativeOutputs = nativeOutputRegistry{
	lengths: make(map[unsafe.Pointer]int),
}

func registerNativeOutput(p unsafe.Pointer, length int) {
	if p == nil {
		return
	}
	nativeOutputs.mu.Lock()
	nativeOutputs.lengths[p] = length
	nativeOutputs.mu.Unlock()
}

func takeNativeOutput(p unsafe.Pointer) (int, bool) {
	if p == nil {
		return 0, false
	}
	nativeOutputs.mu.Lock()
	length, ok := nativeOutputs.lengths[p]
	if ok {
		delete(nativeOutputs.lengths, p)
	}
	nativeOutputs.mu.Unlock()
	return length, ok
}
