package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
)

func TestRunRequiresClientCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run(nil) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "aurorac <proxy|tun>") {
		t.Fatalf("usage = %q, want client command", stderr.String())
	}
}

func TestProxyRejectsNonLinuxHostBeforeProvisioning(t *testing.T) {
	restore := setProxyGOOSForTest("darwin")
	defer restore()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"proxy", "--provisioning", "/private/provisioning.bin"}, &stdout, &stderr); code != 2 {
		t.Fatalf("non-Linux proxy code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires a Linux host") {
		t.Fatalf("non-Linux proxy error = %s", stderr.String())
	}
}

func TestProxyRejectsPublicListenersBeforeProvisioning(t *testing.T) {
	restore := setProxyGOOSForTest("linux")
	defer restore()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"proxy", "--provisioning", "/private/provisioning.bin", "--http-listen", "0.0.0.0:8080"}, &stdout, &stderr); code != 2 {
		t.Fatalf("public listener proxy code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("public listener error = %s", stderr.String())
	}
}

func TestTUNRejectsNonLinuxHostBeforeProvisioning(t *testing.T) {
	restore := setProxyGOOSForTest("darwin")
	defer restore()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"tun", "--provisioning", "/private/provisioning.bin"}, &stdout, &stderr); code != 2 {
		t.Fatalf("non-Linux tunnel code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires a Linux host") {
		t.Fatalf("non-Linux tunnel error = %s", stderr.String())
	}
}

func TestReadRestrictedProvisioningFileRejectsUnsafeInputs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "provisioning.bin")
	if err := os.WriteFile(path, []byte("private provisioning"), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := readRestrictedProvisioningFile(path)
	if err != nil {
		t.Fatalf("read restricted provisioning: %v", err)
	}
	if string(encoded) != "private provisioning" {
		t.Fatalf("restricted provisioning contents = %q", encoded)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := readRestrictedProvisioningFile(path); err == nil {
			t.Fatal("group-readable provisioning file was accepted")
		}
	}
	link := filepath.Join(directory, "provisioning-link.bin")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRestrictedProvisioningFile(link); err == nil {
		t.Fatal("symlinked provisioning file was accepted")
	}
}

func TestExchangeIssuerWorkPostsOpaqueNoStoreRequest(t *testing.T) {
	var receivedBody []byte
	restore := setNewIssuerHTTPClientForTest(func() *http.Client {
		return &http.Client{Transport: issuerRoundTripper(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPost || request.URL.String() != "https://issuer.example/assets/issue/42" {
				t.Fatalf("issuer request = %s %s", request.Method, request.URL)
			}
			if request.Header.Get("Content-Type") != "application/octet-stream" || request.Header.Get("Accept") != "application/octet-stream" || request.Header.Get("Cache-Control") != "no-store" || request.Header.Get("Pragma") != "no-cache" {
				t.Fatalf("issuer request headers = %#v", request.Header)
			}
			var err error
			receivedBody, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/octet-stream"}},
				Body:       io.NopCloser(strings.NewReader("issuer response")),
			}, nil
		})}
	})
	defer restore()
	response, err := exchangeIssuerWork(context.Background(), time.Second, client.IssuerWork{
		IssuerURL:         "https://issuer.example",
		IssuerCarrierPath: "/assets/issue/42",
		RequestBody:       []byte("issuer request"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(receivedBody) != "issuer request" || string(response) != "issuer response" {
		t.Fatalf("issuer exchange body=%q response=%q", receivedBody, response)
	}
}

func TestExchangeIssuerWorkRejectsRedirectAndInvalidContentType(t *testing.T) {
	tests := []struct {
		name     string
		response *http.Response
	}{
		{
			name: "redirect",
			response: &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": {"https://other.example/assets/issue/42"}},
				Body:       io.NopCloser(strings.NewReader("redirect")),
			},
		},
		{
			name: "content type",
			response: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("not a carrier")),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restore := setNewIssuerHTTPClientForTest(func() *http.Client {
				return &http.Client{Transport: issuerRoundTripper(func(*http.Request) (*http.Response, error) {
					return test.response, nil
				})}
			})
			defer restore()
			if _, err := exchangeIssuerWork(context.Background(), time.Second, client.IssuerWork{
				IssuerURL:         "https://issuer.example",
				IssuerCarrierPath: "/assets/issue/42",
				RequestBody:       []byte("issuer request"),
			}); err == nil {
				t.Fatal("unsafe issuer response was accepted")
			}
		})
	}
}

func TestIssuerWorkURLRejectsNonCanonicalInputs(t *testing.T) {
	for _, work := range []client.IssuerWork{
		{IssuerURL: "https://user@issuer.example", IssuerCarrierPath: "/assets/issue/42", RequestBody: []byte("issuer request")},
		{IssuerURL: "https://issuer.example", IssuerCarrierPath: "//assets/issue/42", RequestBody: []byte("issuer request")},
		{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/../issue/42", RequestBody: []byte("issuer request")},
	} {
		if _, err := issuerWorkURL(work); err == nil {
			t.Fatalf("noncanonical issuer work was accepted: %+v", work)
		}
	}
}

func TestRunProxyComponentsStopsOnCancellation(t *testing.T) {
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Write:           session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Read:            session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
	})
	if err != nil {
		t.Fatal(err)
	}
	carrier, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	established := &handshake.EstablishedSession{Application: application, ReadCarrier: carrier, WriteCarrier: carrier}
	runtime, err := client.NewTCPProxyRuntime(application, client.TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = httpListener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runProxyComponents(ctx, established, runtime, httpListener, socksListener) }()
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy components did not stop after cancellation")
	}
	for _, address := range []string{httpListener.Addr().String(), socksListener.Addr().String()} {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			t.Fatalf("listener remained reachable after cancellation: %s", address)
		}
	}
}

func TestRunTUNComponentsCleansRoutesBeforeClosingDevice(t *testing.T) {
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Write:           session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Read:            session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
	})
	if err != nil {
		t.Fatal(err)
	}
	device := newTUNComponentDevice()
	adapter, err := client.NewPacketAdapter(application, client.PacketAdapterOptions{MaxFlows: 1, MaxPacketBytes: 1500})
	if err != nil {
		_ = application.Close()
		t.Fatal(err)
	}
	runtime, err := client.NewPacketTUNRuntime(adapter, device, client.PacketTUNRuntimeOptions{ReadBufferBytes: 1500})
	if err != nil {
		_ = application.Close()
		t.Fatal(err)
	}
	carrier, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	established := &handshake.EstablishedSession{Application: application, ReadCarrier: carrier, WriteCarrier: carrier}
	ctx, cancel := context.WithCancel(context.Background())
	cleanupObserved := make(chan bool, 1)
	result := make(chan error, 1)
	go func() {
		result <- runTUNComponents(ctx, established, runtime, func() error {
			cleanupObserved <- device.Closed()
			return nil
		})
	}()
	select {
	case <-device.Started():
	case <-time.After(time.Second):
		t.Fatal("tunnel device loop did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("tunnel components did not stop after cancellation")
	}
	if observed := <-cleanupObserved; observed {
		t.Fatal("tunnel device closed before route cleanup")
	}
	if !device.Closed() {
		t.Fatal("tunnel device remained open after component shutdown")
	}
}

type issuerRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip issuerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type tunComponentDevice struct {
	closed        chan struct{}
	started       chan struct{}
	closeOnce     sync.Once
	readStartOnce sync.Once
}

func newTUNComponentDevice() *tunComponentDevice {
	return &tunComponentDevice{closed: make(chan struct{}), started: make(chan struct{})}
}

func (d *tunComponentDevice) Read([]byte) (int, error) {
	d.readStartOnce.Do(func() { close(d.started) })
	<-d.closed
	return 0, io.ErrClosedPipe
}

func (d *tunComponentDevice) Write(packet []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(packet), nil
	}
}

func (d *tunComponentDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *tunComponentDevice) Closed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func (d *tunComponentDevice) Started() <-chan struct{} {
	return d.started
}

var _ io.ReadWriteCloser = (*tunComponentDevice)(nil)
