package main

// Coverage for usage (main.go:131), the auroractl command synopsis printed to
// os.Stderr when no or an unknown command is given. It is a direct os.Stderr
// writer, so the test captures os.Stderr through a pipe — mirroring
// captureStdoutForTest in release_gate_commands_test.go.

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestUsagePrintsCommandSynopsis(t *testing.T) {
	output := captureStderrForTest(t, usage)
	if !strings.HasPrefix(output, "usage: auroractl ") {
		t.Fatalf("usage output = %q, want an \"usage: auroractl ...\" synopsis", output)
	}
	for _, command := range []string{"vectors", "release-gate-check", "coverage-check", "check-config"} {
		if !strings.Contains(output, command) {
			t.Fatalf("usage output does not mention %q:\n%s", command, output)
		}
	}
}

// captureStderrForTest redirects os.Stderr for the duration of fn and returns
// what was written.
func captureStderrForTest(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	defer func() { os.Stderr = original }()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}
