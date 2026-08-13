//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"testing"
)

func TestValidateRestrictedOwnerFileUID(t *testing.T) {
	if err := validateRestrictedOwnerFileUID(uint32(os.Geteuid())); err != nil {
		t.Fatalf("current user owner check failed: %v", err)
	}
	if err := validateRestrictedOwnerFileUID(uint32(os.Geteuid()) + 1); err == nil {
		t.Fatal("different user owner check succeeded")
	}
}
