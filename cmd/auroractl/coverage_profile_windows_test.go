//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnsafeWindowsCoverageProfilePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: `\\.\NUL`, want: true},
		{path: `\\.\PIPE\coverage`, want: true},
		{path: `\\?\PIPE\coverage`, want: true},
		{path: `\\?\GLOBALROOT\Device\HarddiskVolume1\coverage.out`, want: true},
		{path: `\Device\NamedPipe\coverage`, want: true},
		{path: `C:\evidence\coverage.out`, want: false},
		{path: `\\server\share\coverage.out`, want: false},
	}

	for _, tc := range tests {
		if got := unsafeWindowsCoverageProfilePath(tc.path); got != tc.want {
			t.Errorf("unsafeWindowsCoverageProfilePath(%q) = %t, want %t", tc.path, got, tc.want)
		}
	}
}

func TestOpenCoverageProfileAcceptsRegularWindowsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(path, []byte("mode: atomic\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	profile, err := openCoverageProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Close(); err != nil {
		t.Fatal(err)
	}
}
