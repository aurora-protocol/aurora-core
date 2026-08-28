package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/internal/labfixture"
)

func TestRunRequiresSubcommandAndPrintsLabBanner(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run(nil) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "auroralab <mint|serve|import-code>") {
		t.Fatalf("usage = %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "LOCAL LAB TESTING ONLY") {
		t.Fatalf("banner missing lab-only warning: %q", stderr.String())
	}
	if code := run([]string{"deploy"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown command code = %d, want 2", code)
	}
}

func TestMintValidatesFlags(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args []string
	}{
		{"missing dir", nil},
		{"blank dir", []string{"--dir", " "}},
		{"unexpected args", []string{"--dir", filepath.Join(t.TempDir(), "d"), "extra"}},
		{"bad relay host", []string{"--dir", filepath.Join(t.TempDir(), "d"), "--relay-host", "bad host"}},
		{"relay port out of range", []string{"--dir", filepath.Join(t.TempDir(), "d"), "--relay-port", "70000"}},
		{"ports equal", []string{"--dir", filepath.Join(t.TempDir(), "d"), "--relay-port", "9443", "--issuer-port", "9443"}},
		{"entries out of range", []string{"--dir", filepath.Join(t.TempDir(), "d"), "--entries", "65"}},
		{"validity too small", []string{"--dir", filepath.Join(t.TempDir(), "d"), "--validity", "1s"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(append([]string{"mint"}, testCase.args...), &stdout, &stderr); code == 0 {
				t.Fatalf("mint %v succeeded, want failure", testCase.args)
			}
		})
	}
}

func TestMintWritesDeployment(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"mint", "--dir", dir, "--entries", "2"}, &stdout, &stderr); code != 0 {
		t.Fatalf("mint code != 0: stderr=%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "relay=https://127.0.0.1:9443/assets/upload/42") {
		t.Fatalf("mint output = %q", stdout.String())
	}
	for _, name := range []string{
		labfixture.FileManifest,
		labfixture.FileWallet,
		labfixture.FileNativeProvisioningTrust,
		labfixture.FileRelayDescriptor,
		labfixture.FileTLSPrivateKey,
	} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("minted file %s: %v", name, err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("minted file %s is not regular", name)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(dir, labfixture.FileManifest))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), labfixture.ManifestWarning) {
		t.Fatal("manifest is missing the lab-only warning")
	}

	// A second mint into the same directory must refuse to overwrite.
	if code := run([]string{"mint", "--dir", dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("re-mint code = %d, want 1", code)
	}
}

func TestServeValidatesFlags(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args []string
	}{
		{"missing everything", nil},
		{"missing listen", []string{"--dir", t.TempDir()}},
		{"bad listen", []string{"--dir", t.TempDir(), "--listen", "nope"}},
		{"listen zero port", []string{"--dir", t.TempDir(), "--listen", "127.0.0.1:0"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(append([]string{"serve"}, testCase.args...), &stdout, &stderr); code == 0 {
				t.Fatalf("serve %v succeeded, want failure", testCase.args)
			}
		})
	}
}

// mintDeploymentForServeTest mints a deployment bound to reserved free
// loopback ports and returns the directory and relay port.
func mintDeploymentForServeTest(t *testing.T) (string, int) {
	t.Helper()
	relayPort := reserveFreePort(t)
	issuerPort := reserveFreePort(t)
	dir := filepath.Join(t.TempDir(), "deployment")
	material, err := labfixture.Mint(labfixture.MintOptions{RelayPort: relayPort, IssuerPort: issuerPort, Entries: 2, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	defer material.Zero()
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	return dir, relayPort
}

// reserveFreePort returns a currently free loopback TCP port; the caller must
// bind it promptly.
func reserveFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestServeRejectsNonLoopbackWithoutFlag(t *testing.T) {
	dir, relayPort := mintDeploymentForServeTest(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve", "--dir", dir, "--listen", fmt.Sprintf("0.0.0.0:%d", relayPort)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("non-loopback serve code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--allow-non-loopback") {
		t.Fatalf("non-loopback error = %q", stderr.String())
	}
}

func TestServeRejectsPortMismatch(t *testing.T) {
	dir, relayPort := mintDeploymentForServeTest(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve", "--dir", dir, "--listen", fmt.Sprintf("127.0.0.1:%d", relayPort+1)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("port-mismatch serve code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "does not match the minted wallet relay port") {
		t.Fatalf("port-mismatch error = %q", stderr.String())
	}
}

func TestServeRejectsMissingDeployment(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve", "--dir", filepath.Join(t.TempDir(), "missing"), "--listen", fmt.Sprintf("127.0.0.1:%d", reserveFreePort(t))}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("missing-deployment serve code = %d, want 1", code)
	}
}

// TestServeStartsAndStops runs the full serve path on loopback until the
// injected signal context cancels it.
func TestServeStartsAndStops(t *testing.T) {
	dir, relayPort := mintDeploymentForServeTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	previous := labSignalContext
	labSignalContext = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	defer func() { labSignalContext = previous }()

	stdoutReader, stdoutWriter := io.Pipe()
	defer stdoutReader.Close()
	result := make(chan int, 1)
	go func() {
		code := run([]string{"serve", "--dir", dir, "--listen", fmt.Sprintf("127.0.0.1:%d", relayPort)}, stdoutWriter, io.Discard)
		_ = stdoutWriter.Close()
		result <- code
	}()
	// io.Pipe is synchronous: drain every line so serve never blocks writing.
	lines := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(stdoutReader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	select {
	case line := <-lines:
		want := fmt.Sprintf("auroralab serving relay=https://127.0.0.1:%d/", relayPort)
		if !strings.Contains(line, want) || !strings.Contains(line, "cover=http://127.0.0.1:") {
			t.Fatalf("serve startup line = %q, want prefix %q", line, want)
		}
	case code := <-result:
		t.Fatalf("serve exited before startup line with code %d", code)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not print a startup line")
	}
	cancel()
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("serve shutdown code = %d, want 0", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop after cancellation")
	}
}
