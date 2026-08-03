//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenCoverageProfileRejectsFIFOWithoutWriterPromptly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coverage.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	profile, err := openCoverageProfile(path)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("openCoverageProfile blocked for %s", elapsed)
	}
	if profile != nil {
		if closeErr := profile.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("openCoverageProfile accepted FIFO")
	}
	if err == nil {
		t.Fatal("openCoverageProfile accepted FIFO")
	}

	var out bytes.Buffer
	started = time.Now()
	err = coverageCheck([]string{"--profile", path}, &out)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("coverageCheck blocked for %s", elapsed)
	}
	if err == nil || err.Error() != "coverage-check: unable to read profile" {
		t.Fatalf("coverageCheck error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("coverageCheck wrote output for FIFO: %q", out.String())
	}
}
