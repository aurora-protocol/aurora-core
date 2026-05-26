package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/platform"
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

func TestRunTunPacketModeOpensLinuxTUNDevice(t *testing.T) {
	var opened platform.LinuxTUNConfig
	device := &recordingPacketDevice{}
	restoreOpen := setOpenLinuxPacketDeviceForTest(func(config platform.LinuxTUNConfig) (io.ReadWriteCloser, int, error) {
		opened = config
		return device, 1400, nil
	})
	defer restoreOpen()
	restoreListen := setListenAndServeForTest(func(addr string, handler http.Handler) error {
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--packet-mode", "tun",
		"--tun-device", "/tmp/aurora-tun",
		"--tun-iface", "aurtest0",
		"--tun-mtu", "1400",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if opened.DevicePath != "/tmp/aurora-tun" || opened.InterfaceName != "aurtest0" || opened.MTU != 1400 {
		t.Fatalf("opened TUN config = %+v", opened)
	}
	if !device.closed {
		t.Fatal("packet device was not closed when aurorad exited")
	}
	if !strings.Contains(stdout.String(), "packet_mode=tun") {
		t.Fatalf("stdout missing packet mode: %s", stdout.String())
	}
}

func TestRunTLSModeServesHTTPSForAppleClients(t *testing.T) {
	spentTokenCachePath := filepath.Join(t.TempDir(), "spent-token-cache.log")
	var gotAddr, gotCert, gotKey string
	device := &recordingPacketDevice{}
	restoreOpen := setOpenLinuxPacketDeviceForTest(func(config platform.LinuxTUNConfig) (io.ReadWriteCloser, int, error) {
		return device, 1400, nil
	})
	defer restoreOpen()
	restoreCover := setNewCoverOriginForTest(func(raw string) (http.Handler, error) {
		if raw != "https://cover.example" {
			t.Fatalf("cover origin URL = %s", raw)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("cover"))
		}), nil
	})
	defer restoreCover()
	restoreListen := setListenAndServeTLSForTest(func(addr string, handler http.Handler, certFile, keyFile string) error {
		gotAddr = addr
		gotCert = certFile
		gotKey = keyFile
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("TLS handler health response = %d", rec.Code)
		}
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--listen", "0.0.0.0:9443",
		"--tls-cert", "/tmp/aurora-cert.pem",
		"--tls-key", "/tmp/aurora-key.pem",
		"--cover-origin-url", "https://cover.example",
		"--spent-token-cache", spentTokenCachePath,
		"--packet-mode", "tun",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if gotAddr != "0.0.0.0:9443" || gotCert != "/tmp/aurora-cert.pem" || gotKey != "/tmp/aurora-key.pem" {
		t.Fatalf("TLS listener args = addr=%q cert=%q key=%q", gotAddr, gotCert, gotKey)
	}
	if !strings.Contains(stdout.String(), "scheme=https") {
		t.Fatalf("stdout missing HTTPS scheme: %s", stdout.String())
	}
	if !device.closed {
		t.Fatal("packet device was not closed when aurorad exited")
	}
}

func TestREADMEPublicLinuxCommandUsesRequiredRuntimeGates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	var command string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "go run ./cmd/aurorad --listen 0.0.0.0:9443") {
			command = line
			break
		}
	}
	if command == "" {
		t.Fatal("README is missing the public Linux aurorad command")
	}
	for _, want := range []string{
		"--tls-cert",
		"--tls-key",
		"--cover-origin-url",
		"--spent-token-cache",
		"--packet-mode tun",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("README public Linux aurorad command missing %q: %s", want, command)
		}
	}
}

func TestRunRejectsNonLoopbackTLSWithoutPersistentSpentTokenCache(t *testing.T) {
	restoreListen := setListenAndServeTLSForTest(func(addr string, handler http.Handler, certFile, keyFile string) error {
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--listen", "0.0.0.0:9443",
		"--tls-cert", "/tmp/aurora-cert.pem",
		"--tls-key", "/tmp/aurora-key.pem",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted public TLS without persistent spent-token cache stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "persistent spent-token") || !strings.Contains(stderr.String(), "non-loopback") {
		t.Fatalf("stderr missing persistent replay-cache requirement: %s", stderr.String())
	}
}

func TestRunRejectsNonLoopbackTLSWithoutCoverOriginURL(t *testing.T) {
	spentTokenCachePath := filepath.Join(t.TempDir(), "spent-token-cache.log")
	restoreListen := setListenAndServeTLSForTest(func(addr string, handler http.Handler, certFile, keyFile string) error {
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--listen", "0.0.0.0:9443",
		"--tls-cert", "/tmp/aurora-cert.pem",
		"--tls-key", "/tmp/aurora-key.pem",
		"--spent-token-cache", spentTokenCachePath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted public TLS without cover origin URL stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "cover origin") || !strings.Contains(stderr.String(), "non-loopback") {
		t.Fatalf("stderr missing cover-origin requirement: %s", stderr.String())
	}
}

func TestRunRejectsNonLoopbackTLSWithoutTUNPacketMode(t *testing.T) {
	spentTokenCachePath := filepath.Join(t.TempDir(), "spent-token-cache.log")
	restoreCover := setNewCoverOriginForTest(func(raw string) (http.Handler, error) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("cover"))
		}), nil
	})
	defer restoreCover()
	restoreListen := setListenAndServeTLSForTest(func(addr string, handler http.Handler, certFile, keyFile string) error {
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--listen", "0.0.0.0:9443",
		"--tls-cert", "/tmp/aurora-cert.pem",
		"--tls-key", "/tmp/aurora-key.pem",
		"--cover-origin-url", "https://cover.example",
		"--spent-token-cache", spentTokenCachePath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted public TLS without TUN packet mode stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "packet mode tun") || !strings.Contains(stderr.String(), "non-loopback") {
		t.Fatalf("stderr missing public packet-mode requirement: %s", stderr.String())
	}
}

func TestRunRejectsNonLoopbackPlainHTTP(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--listen", "0.0.0.0:9443"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted non-loopback HTTP stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "TLS") || !strings.Contains(stderr.String(), "non-loopback") {
		t.Fatalf("stderr missing non-loopback TLS requirement: %s", stderr.String())
	}
}

func TestRunCoverOriginURLServesReverseProxiedCover(t *testing.T) {
	restoreCover := setNewCoverOriginForTest(func(raw string) (http.Handler, error) {
		if raw != "https://cover.example" {
			t.Fatalf("cover origin URL = %s", raw)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/cover-page" {
				t.Fatalf("cover origin path = %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("proxied cover"))
		}), nil
	})
	defer restoreCover()
	restoreListen := setListenAndServeForTest(func(addr string, handler http.Handler) error {
		req := httptest.NewRequest(http.MethodGet, "/cover-page", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted || rec.Body.String() != "proxied cover" {
			t.Fatalf("proxied cover response = %d %q", rec.Code, rec.Body.String())
		}
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{"--cover-origin-url", "https://cover.example"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestRunOpensPersistentSpentTokenCacheWhenConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent-token-cache.log")
	restoreListen := setListenAndServeForTest(func(addr string, handler http.Handler) error {
		return http.ErrServerClosed
	})
	defer restoreListen()

	var stdout, stderr bytes.Buffer
	code := run([]string{"--spent-token-cache", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run returned %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("spent-token cache file was not created: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("spent-token cache mode = %o, want 600", got)
	}
}

func TestRunRejectsUnknownPacketMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--packet-mode", "bogus"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run accepted unknown packet mode stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "packet mode") {
		t.Fatalf("stderr missing packet mode error: %s", stderr.String())
	}
}

type recordingPacketDevice struct {
	writes [][]byte
	closed bool
}

func (d *recordingPacketDevice) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (d *recordingPacketDevice) Write(packet []byte) (int, error) {
	d.writes = append(d.writes, append([]byte(nil), packet...))
	return len(packet), nil
}

func (d *recordingPacketDevice) Close() error {
	d.closed = true
	return nil
}

func setOpenLinuxPacketDeviceForTest(fn func(platform.LinuxTUNConfig) (io.ReadWriteCloser, int, error)) func() {
	previous := openLinuxPacketDevice
	openLinuxPacketDevice = fn
	return func() {
		openLinuxPacketDevice = previous
	}
}

func setListenAndServeForTest(fn func(string, http.Handler) error) func() {
	previous := listenAndServe
	listenAndServe = fn
	return func() {
		listenAndServe = previous
	}
}

func setListenAndServeTLSForTest(fn func(string, http.Handler, string, string) error) func() {
	previous := listenAndServeTLS
	listenAndServeTLS = fn
	return func() {
		listenAndServeTLS = previous
	}
}

func setNewCoverOriginForTest(fn func(string) (http.Handler, error)) func() {
	previous := newCoverOrigin
	newCoverOrigin = fn
	return func() {
		newCoverOrigin = previous
	}
}
