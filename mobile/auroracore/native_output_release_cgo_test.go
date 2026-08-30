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

func TestReleaseNativeOutputIgnoresUnknownAndDuplicatePointers(t *testing.T) {
	registered := []byte("registered native output")
	registeredPointer := unsafe.Pointer(&registered[0])
	unknown := []byte("unknown native output")
	unknownPointer := unsafe.Pointer(&unknown[0])
	registerNativeOutput(registeredPointer, len(registered))

	releases := 0
	release := func(releasedOutput unsafe.Pointer, length int) {
		releases++
		if releasedOutput != registeredPointer || length != len(registered) {
			t.Fatalf(
				"release allocation = (%p, %d), want (%p, %d)",
				releasedOutput,
				length,
				registeredPointer,
				len(registered),
			)
		}
	}

	releaseNativeOutputWith(nil, release)
	releaseNativeOutputWith(unknownPointer, release)
	releaseNativeOutputWith(registeredPointer, release)
	releaseNativeOutputWith(registeredPointer, release)

	if releases != 1 {
		t.Fatalf("native output release calls = %d, want exactly 1", releases)
	}
	if !bytes.Equal(unknown, []byte("unknown native output")) {
		t.Fatal("unknown native output was modified")
	}
}
