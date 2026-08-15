//go:build cgo

package main

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestReleaseNativeOutputScrubsBeforeRelease(t *testing.T) {
	output := []byte("sensitive native output")
	p := unsafe.Pointer(&output[0])
	registerNativeOutput(p, len(output))

	released := false
	releaseNativeOutputWith(p, func(releasedOutput unsafe.Pointer, length int) {
		released = true
		if releasedOutput != p || length != len(output) {
			t.Fatalf("release allocation = (%p, %d), want (%p, %d)", releasedOutput, length, p, len(output))
		}
	})
	if !released {
		t.Fatal("registered native output was not released")
	}
	if !bytes.Equal(output, make([]byte, len(output))) {
		t.Fatal("native output was not scrubbed before release")
	}
}
