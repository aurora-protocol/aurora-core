package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRequiresExplicitCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run(nil) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "harness|serve") {
		t.Fatalf("usage does not name commands: %s", stderr.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"unknown"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run unknown command code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unknown-command error missing: %s", stderr.String())
	}
}

func TestServeRejectsMissingProductionConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"serve"}, &stdout, &stderr); code != 2 {
		t.Fatalf("serve missing config code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "listen address") {
		t.Fatalf("serve missing config error = %s", stderr.String())
	}
}

func TestServeRejectsHarnessOnlyFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"serve", "--packet-mode", "loopback"}, &stdout, &stderr); code != 2 {
		t.Fatalf("serve harness flag code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "packet-mode") {
		t.Fatalf("serve harness flag error = %s", stderr.String())
	}
}

func TestServeHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"serve", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("serve help code = %d, want 0", code)
	}
	for _, want := range []string{"-relay-descriptor", "-max-sessions", "-egress-max-flows"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("serve help missing %q: %s", want, stderr.String())
		}
	}
}

func TestHarnessHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"harness", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("harness help code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "-readiness-check") {
		t.Fatalf("harness help missing readiness option: %s", stderr.String())
	}
}

func TestReadRestrictedProductionFileRejectsUnsafeInputs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "private.bin")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := readRestrictedProductionFile(path)
	if err != nil {
		t.Fatalf("read private configuration file: %v", err)
	}
	if string(encoded) != "secret" {
		t.Fatalf("private configuration contents = %q", encoded)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRestrictedProductionFile(path); err == nil {
		t.Fatal("world-readable private configuration file accepted")
	}
	link := filepath.Join(directory, "private-link.bin")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProductionFile(link); err == nil {
		t.Fatal("symlinked production configuration file accepted")
	}
}

func TestProductionReplayCachesMustBeDistinctAndPrivate(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first.log")
	second := filepath.Join(directory, "second.log")
	if err := validateProductionCachePaths([]string{first, first, second}); err == nil {
		t.Fatal("duplicate replay cache paths accepted")
	}
	if err := os.WriteFile(first, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateProductionCachePaths([]string{first, second, filepath.Join(directory, "third.log")}); err == nil {
		t.Fatal("world-readable replay cache accepted")
	}
}

func TestServeReportsIncompleteTLSConfiguration(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseProductionConfig([]string{"--listen", "0.0.0.0:8443", "--authority", "cover.example:443", "--path", "/assets/upload/42"}, &stderr)
	if err == nil || !strings.Contains(stderr.String(), "TLS certificate") {
		t.Fatalf("incomplete TLS configuration error = %v stderr=%s", err, stderr.String())
	}
}

func TestRunServeReportsListenerFailure(t *testing.T) {
	config := newProductionCommandFixture(t)
	restoreListen := setProductionListenForTest(func(string) (net.Listener, error) {
		return nil, errors.New("listener failure")
	})
	defer restoreListen()
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"serve"}, productionCommandArguments(config)...), &stdout, &stderr); code != 1 {
		t.Fatalf("serve listener failure code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "listen") {
		t.Fatalf("listener failure error = %s", stderr.String())
	}
}
