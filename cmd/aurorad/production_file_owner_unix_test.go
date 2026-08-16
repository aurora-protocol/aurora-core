//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

// Adversarial coverage for validateProductionFileOwner: the nil-info branch
// (line 12-13) and the bad-Sys-type-assertion branch (line 16-17). The existing
// TestValidateProductionFileOwnerUID covers only validateProductionFileOwnerUID
// directly; validateProductionFileOwner's own two early-return branches need a
// nil FileInfo and a FileInfo whose Sys() is not *syscall.Stat_t, neither of
// which a real os.Stat result can produce on unix.

import (
	"os"
	"testing"
	"time"
)

func TestValidateProductionFileOwnerUID(t *testing.T) {
	if err := validateProductionFileOwnerUID(uint32(os.Geteuid())); err != nil {
		t.Fatalf("current user owner check failed: %v", err)
	}
	if err := validateProductionFileOwnerUID(uint32(os.Geteuid()) + 1); err == nil {
		t.Fatal("different user owner check succeeded")
	}
}

func TestValidateProductionFileOwnerRejectsUnavailable(t *testing.T) {
	t.Run("nil info", func(t *testing.T) {
		if err := validateProductionFileOwner(nil); err == nil {
			t.Fatal("validateProductionFileOwner accepted a nil FileInfo")
		}
	})
	t.Run("sys not a syscall.Stat_t", func(t *testing.T) {
		// A FileInfo whose Sys() returns a non-*syscall.Stat_t fails the type
		// assertion, exercising the !ok branch (line 16-17).
		if err := validateProductionFileOwner(fakeFileInfoForCoverage{}); err == nil {
			t.Fatal("validateProductionFileOwner accepted a FileInfo without a unix stat")
		}
	})
}

// fakeFileInfoForCoverage is a minimal os.FileInfo whose Sys() returns nil, so
// the *syscall.Stat_t type assertion in validateProductionFileOwner fails
// without any real filesystem fixture.
type fakeFileInfoForCoverage struct{}

func (fakeFileInfoForCoverage) Name() string       { return "fake" }
func (fakeFileInfoForCoverage) Size() int64         { return 0 }
func (fakeFileInfoForCoverage) Mode() os.FileMode  { return 0 }
func (fakeFileInfoForCoverage) ModTime() time.Time { return time.Time{} }
func (fakeFileInfoForCoverage) IsDir() bool        { return false }
func (fakeFileInfoForCoverage) Sys() interface{}   { return nil }
