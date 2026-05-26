package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadinessCheckReportsRunnableServer(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--readiness-check"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d stderr=%s", code, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{
		"server_check passed=true",
		"health=true",
		"cover=true",
		"issuer_metadata=true",
		"blind_rsa_issue=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("readiness output missing %q:\n%s", want, text)
		}
	}
}

func TestRunRejectsEmptyListenAddress(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--listen", ""}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted empty listen address stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "listen address") {
		t.Fatalf("stderr missing listen address error: %s", stderr.String())
	}
}
