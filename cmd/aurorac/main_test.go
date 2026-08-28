package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"github.com/aurora-protocol/aurora-core/transport"
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
	if code := run([]string{"proxy", "--provisioning", "/private/provisioning.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin"}, &stdout, &stderr); code != 2 {
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
	if code := run([]string{"proxy", "--provisioning", "/private/provisioning.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin", "--http-listen", "0.0.0.0:8080"}, &stdout, &stderr); code != 2 {
		t.Fatalf("public listener proxy code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("public listener error = %s", stderr.String())
	}
}

func TestParseProxyConfigValidatesProvisioningSource(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args []string
		want bool
	}{
		{"single provisioning", []string{"--provisioning", "/private/provisioning.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin"}, true},
		{"wallet provisioning", []string{"--provisioning-wallet", "/private/wallet.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin"}, true},
		{"both sources", []string{"--provisioning", "/private/provisioning.bin", "--provisioning-wallet", "/private/wallet.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin"}, false},
		{"missing roots", []string{"--provisioning", "/private/provisioning.bin", "--wallet-state", "/private/wallet-state.bin"}, false},
		{"single missing state", []string{"--provisioning", "/private/provisioning.bin"}, false},
		{"wallet missing state", []string{"--provisioning-wallet", "/private/wallet.bin"}, false},
		{"state without source", []string{"--wallet-state", "/private/wallet-state.bin"}, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := parseProxyConfig(testCase.args, io.Discard)
			if (err == nil) != testCase.want {
				t.Fatalf("parse proxy config error = %v, want success=%t", err, testCase.want)
			}
		})
	}
}

func TestParseProxyConfigAcceptsAggregatePendingWriteLimit(t *testing.T) {
	config, err := parseProxyConfig([]string{
		"--provisioning", "/private/provisioning.bin",
		"--wallet-state", "/private/wallet-state.bin",
		"--signed-seed-roots", "/private/roots.bin",
		"--max-total-pending-write-bytes", "2097152",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.runtimeOptions.MaxTotalPendingWriteBytes; got != 2<<20 {
		t.Fatalf("aggregate pending write limit = %d, want %d", got, 2<<20)
	}
}

func TestTUNRejectsNonLinuxHostBeforeProvisioning(t *testing.T) {
	restore := setProxyGOOSForTest("darwin")
	defer restore()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"tun", "--provisioning", "/private/provisioning.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin"}, &stdout, &stderr); code != 2 {
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

func TestZeroProxyProvisioningClearsIssuerMaterial(t *testing.T) {
	issuerMetadata := []byte("issuer metadata")
	signedSeed := []byte("signed seed")
	provisioning := client.NativeProvisioning{
		IssuerMetadata: issuerMetadata,
		SignedSeed:     signedSeed,
	}

	zeroProxyProvisioning(&provisioning)

	for label, value := range map[string][]byte{
		"issuer metadata": issuerMetadata,
		"signed seed":     signedSeed,
	} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("%s was not cleared: %x", label, value)
		}
	}
	if provisioning.IssuerMetadata != nil || provisioning.SignedSeed != nil {
		t.Fatalf("provisioning retained issuer material: %+v", provisioning)
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

func TestExchangeIssuerWorkClosesResponseWhenCanceled(t *testing.T) {
	body := newIssuerBlockingResponseBody()
	restore := setNewIssuerHTTPClientForTest(func() *http.Client {
		return &http.Client{Transport: issuerRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/octet-stream"}},
				Body:       body,
			}, nil
		})}
	})
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := exchangeIssuerWork(ctx, time.Second, client.IssuerWork{
			IssuerURL:         "https://issuer.example",
			IssuerCarrierPath: "/assets/issue/42",
			RequestBody:       []byte("issuer request"),
		})
		result <- err
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("issuer response body was not read")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("issuer cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		_ = body.Close()
		<-result
		t.Fatal("issuer response body remained open after cancellation")
	}
	if !body.Closed() {
		t.Fatal("issuer response body was not closed after cancellation")
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

func TestRunWithCarrierRecoveryUsesBoundedBackoff(t *testing.T) {
	terminal := errors.New("local listener failed")
	var delays []time.Duration
	attempts := 0
	err := runWithCarrierRecovery(context.Background(), carrierRecoveryPolicy{
		InitialDelay: 100 * time.Millisecond,
		MaximumDelay: 250 * time.Millisecond,
		Jitter: func(delay time.Duration) (time.Duration, error) {
			return delay, nil
		},
		Wait: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	}, func(context.Context) (bool, error) {
		attempts++
		if attempts < 4 {
			return true, io.ErrUnexpectedEOF
		}
		return false, terminal
	})
	if !errors.Is(err, terminal) {
		t.Fatalf("recovery error = %v, want terminal attempt error", err)
	}
	if want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 250 * time.Millisecond}; len(delays) != len(want) {
		t.Fatalf("recovery delays = %v, want %v", delays, want)
	} else {
		for index := range want {
			if delays[index] != want[index] {
				t.Fatalf("recovery delays = %v, want %v", delays, want)
			}
		}
	}
}

func TestRunWithCarrierRecoveryWaitsForJitteredDelay(t *testing.T) {
	var jitterInputs []time.Duration
	var waitDelays []time.Duration
	attempts := 0
	terminal := errors.New("terminal failure")
	err := runWithCarrierRecovery(context.Background(), carrierRecoveryPolicy{
		InitialDelay: 100 * time.Millisecond,
		MaximumDelay: 200 * time.Millisecond,
		Jitter: func(delay time.Duration) (time.Duration, error) {
			jitterInputs = append(jitterInputs, delay)
			return delay - 25*time.Millisecond, nil
		},
		Wait: func(_ context.Context, delay time.Duration) error {
			waitDelays = append(waitDelays, delay)
			return nil
		},
	}, func(context.Context) (bool, error) {
		attempts++
		if attempts == 1 {
			return true, io.ErrUnexpectedEOF
		}
		return false, terminal
	})
	if !errors.Is(err, terminal) {
		t.Fatalf("recovery error = %v, want terminal attempt error", err)
	}
	if len(jitterInputs) != 1 || jitterInputs[0] != 100*time.Millisecond || len(waitDelays) != 1 || waitDelays[0] != 75*time.Millisecond {
		t.Fatalf("jitter inputs = %v, wait delays = %v", jitterInputs, waitDelays)
	}
}

func TestRunWithCarrierRecoveryStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitStarted := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runWithCarrierRecovery(ctx, carrierRecoveryPolicy{
			InitialDelay: time.Millisecond,
			MaximumDelay: time.Millisecond,
			Wait: func(ctx context.Context, _ time.Duration) error {
				close(waitStarted)
				<-ctx.Done()
				return ctx.Err()
			},
		}, func(context.Context) (bool, error) {
			return true, io.EOF
		})
	}()
	select {
	case <-waitStarted:
	case <-time.After(time.Second):
		t.Fatal("recovery did not begin waiting")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("recovery cancellation error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery did not stop after cancellation")
	}
}

func TestRunWithCarrierRecoveryTreatsAttemptCancellationAsCleanShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := runWithCarrierRecovery(ctx, carrierRecoveryPolicy{}, func(context.Context) (bool, error) {
		cancel()
		return false, context.Canceled
	})
	if err != nil {
		t.Fatalf("attempt cancellation error = %v, want nil", err)
	}
}

func TestRunWithCarrierRecoveryReturnsCleanupFailureAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closeErr := errors.New("proxy listener close failed")
	err := runWithCarrierRecovery(ctx, carrierRecoveryPolicy{}, func(context.Context) (bool, error) {
		cancel()
		return false, closeErr
	})
	if !errors.Is(err, closeErr) {
		t.Fatalf("recovery error = %v, want cleanup failure", err)
	}
}

func TestRunWithProvisioningWalletReservesFreshEntryForEachRecoveryAttempt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	reserves := 0
	attempts := 0
	terminal := errors.New("terminal failure")
	err := runWithProvisioningWallet(context.Background(), carrierRecoveryPolicy{
		InitialDelay: time.Millisecond,
		MaximumDelay: time.Millisecond,
		Jitter:       func(delay time.Duration) (time.Duration, error) { return delay, nil },
		Wait:         func(context.Context, time.Duration) error { return nil },
	}, func(time.Time) (client.NativeProvisioningReservation, error) {
		reserves++
		return client.NativeProvisioningReservation{
			SpentHintKey:         bytes.Repeat([]byte{byte(reserves)}, 48),
			RelayBucketID:        bytes.Repeat([]byte{0x22}, 16),
			AccessHintExpiryUnix: uint64(now.Add(time.Hour).Unix()),
		}, nil
	}, func(_ context.Context, reservation client.NativeProvisioningReservation) error {
		attempts++
		if reservation.AccessHintExpiryUnix == 0 || len(reservation.SpentHintKey) != 48 {
			t.Fatalf("invalid wallet reservation: %+v", reservation)
		}
		if attempts == 1 {
			return &componentFailure{name: encryptedCarrierComponent, err: fmt.Errorf("%w: %w", transport.ErrCarrierRead, io.ErrUnexpectedEOF)}
		}
		return terminal
	})
	if !errors.Is(err, terminal) {
		t.Fatalf("wallet recovery error = %v, want terminal attempt error", err)
	}
	if reserves != 2 || attempts != 2 {
		t.Fatalf("wallet reserves=%d attempts=%d, want 2 each", reserves, attempts)
	}
}

func TestRunWithProvisioningWalletTreatsReservationFailureAsTerminal(t *testing.T) {
	want := errors.New("wallet unavailable")
	err := runWithProvisioningWallet(context.Background(), carrierRecoveryPolicy{}, func(time.Time) (client.NativeProvisioningReservation, error) {
		return client.NativeProvisioningReservation{}, want
	}, func(context.Context, client.NativeProvisioningReservation) error {
		t.Fatal("attempt ran without a reservation")
		return nil
	})
	if !errors.Is(err, want) {
		t.Fatalf("wallet reservation error = %v, want %v", err, want)
	}
}

func TestRunProxyComponentsClassifiesCarrierReadFailure(t *testing.T) {
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
		_ = established.Close()
		t.Fatal(err)
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = runtime.Close()
		_ = established.Close()
		t.Fatal(err)
	}
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = httpListener.Close()
		_ = runtime.Close()
		_ = established.Close()
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- runProxyComponents(context.Background(), established, runtime, httpListener, socksListener)
	}()
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !isRecoverableCarrierFailure(err) {
			t.Fatalf("carrier close error = %v, want recoverable carrier failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy components did not stop after carrier loss")
	}
}

func TestRunTUNComponentsClassifiesCarrierReadFailure(t *testing.T) {
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
	result := make(chan error, 1)
	go func() {
		result <- runTUNComponents(context.Background(), established, runtime, nil)
	}()
	select {
	case <-device.Started():
	case <-time.After(time.Second):
		t.Fatal("tunnel device loop did not start")
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !isRecoverableCarrierFailure(err) {
			t.Fatalf("carrier close error = %v, want recoverable carrier failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("tunnel components did not stop after carrier loss")
	}
	if !device.Closed() {
		t.Fatal("tunnel device remained open after carrier loss")
	}
}

func TestRecoverableCarrierFailureRequiresEncryptedCarrierComponent(t *testing.T) {
	carrierFailure := &componentFailure{name: encryptedCarrierComponent, err: fmt.Errorf("%w: %w", transport.ErrCarrierRead, io.ErrUnexpectedEOF)}
	if !isRecoverableCarrierFailure(carrierFailure) {
		t.Fatal("carrier read failure was not recoverable")
	}
	listenerFailure := &componentFailure{name: "HTTP CONNECT listener", err: fmt.Errorf("%w: %w", transport.ErrCarrierRead, io.ErrUnexpectedEOF)}
	if isRecoverableCarrierFailure(listenerFailure) {
		t.Fatal("listener failure became recoverable")
	}
	malformedCarrierFailure := &componentFailure{name: encryptedCarrierComponent, err: transport.ErrEmptyRecord}
	if isRecoverableCarrierFailure(malformedCarrierFailure) {
		t.Fatal("malformed carrier record became recoverable")
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

func TestRunProxyComponentsWaitsForDelayedThirdComponent(t *testing.T) {
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Write:           session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Read:            session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
	})
	if err != nil {
		t.Fatal(err)
	}
	carrier := newDelayedProxyCarrier()
	established := &handshake.EstablishedSession{Application: application, ReadCarrier: carrier, WriteCarrier: carrier}
	runtime, err := client.NewTCPProxyRuntime(application, client.TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		_ = established.Close()
		t.Fatal(err)
	}
	httpListener := newDelayedProxyListener()
	socksListener := newDelayedProxyListener()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runProxyComponents(ctx, established, runtime, httpListener, socksListener)
	}()

	for name, started := range map[string]<-chan struct{}{
		"HTTP listener":  httpListener.acceptStarted,
		"SOCKS listener": socksListener.acceptStarted,
		"carrier read":   carrier.readStarted,
	} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("%s did not start", name)
		}
	}
	cancel()
	for name, listener := range map[string]*delayedProxyListener{
		"HTTP listener":  httpListener,
		"SOCKS listener": socksListener,
	} {
		for closeCall := 1; closeCall <= 3; closeCall++ {
			select {
			case <-listener.closeCalls:
			case <-time.After(time.Second):
				t.Fatalf("%s close call %d did not occur", name, closeCall)
			}
		}
		close(listener.releaseAccept)
		select {
		case <-listener.acceptReturned:
		case <-time.After(time.Second):
			t.Fatalf("%s accept did not return", name)
		}
	}

	select {
	case err := <-result:
		t.Fatalf("proxy components returned before delayed carrier component: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(carrier.releaseRead)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("proxy cancellation error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy components did not return after delayed carrier completed")
	}
}

type delayedProxyListener struct {
	acceptStarted  chan struct{}
	acceptReturned chan struct{}
	releaseAccept  chan struct{}
	closeCalls     chan struct{}
	startOnce      sync.Once
	returnOnce     sync.Once
}

func newDelayedProxyListener() *delayedProxyListener {
	return &delayedProxyListener{
		acceptStarted:  make(chan struct{}),
		acceptReturned: make(chan struct{}),
		releaseAccept:  make(chan struct{}),
		closeCalls:     make(chan struct{}, 3),
	}
}

func (l *delayedProxyListener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() { close(l.acceptStarted) })
	<-l.releaseAccept
	l.returnOnce.Do(func() { close(l.acceptReturned) })
	return nil, net.ErrClosed
}

func (l *delayedProxyListener) Close() error {
	l.closeCalls <- struct{}{}
	return nil
}

func (l *delayedProxyListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

type delayedProxyCarrier struct {
	readStarted chan struct{}
	releaseRead chan struct{}
	startOnce   sync.Once
}

func newDelayedProxyCarrier() *delayedProxyCarrier {
	return &delayedProxyCarrier{readStarted: make(chan struct{}), releaseRead: make(chan struct{})}
}

func (c *delayedProxyCarrier) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.releaseRead
	return 0, io.EOF
}

func (*delayedProxyCarrier) Write(payload []byte) (int, error) {
	return len(payload), nil
}

func (*delayedProxyCarrier) Close() error {
	return nil
}

func TestRunProxyComponentsReturnsCloseFailureOnCancellation(t *testing.T) {
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
	closeErr := errors.New("HTTP listener close failed")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runProxyComponents(ctx, established, runtime, proxyCloseErrorListener{Listener: httpListener, err: closeErr}, socksListener)
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, closeErr) {
			t.Fatalf("proxy shutdown error = %v, want close failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy components did not stop after cancellation")
	}
}

type proxyCloseErrorListener struct {
	net.Listener
	err error
}

func (l proxyCloseErrorListener) Close() error {
	_ = l.Listener.Close()
	return l.err
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

type issuerBlockingResponseBody struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newIssuerBlockingResponseBody() *issuerBlockingResponseBody {
	return &issuerBlockingResponseBody{started: make(chan struct{}), closed: make(chan struct{})}
}

func (b *issuerBlockingResponseBody) Read([]byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.closed
	return 0, context.Canceled
}

func (b *issuerBlockingResponseBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

func (b *issuerBlockingResponseBody) Closed() bool {
	select {
	case <-b.closed:
		return true
	default:
		return false
	}
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
