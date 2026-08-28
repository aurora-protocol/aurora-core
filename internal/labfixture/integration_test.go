package labfixture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/transport"
)

// reserveLabPort returns a currently free loopback TCP port. The caller must
// bind it promptly; this is acceptable for lab tests.
func reserveLabPort(t *testing.T) int {
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

// TestLabDeploymentEndToEnd mints a deployment, serves it on loopback, then
// drives the real production client path — wallet reservation, provisioned
// handshake, live HTTPS issuer exchange, SOCKS5 proxying through the relay —
// to the lab cover origin.
func TestLabDeploymentEndToEnd(t *testing.T) {
	relayPort := reserveLabPort(t)
	issuerPort := reserveLabPort(t)
	material, err := Mint(MintOptions{RelayHost: "127.0.0.1", RelayPort: relayPort, IssuerPort: issuerPort, Entries: 2, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	labServer, err := NewServer(loaded, ServerOptions{
		PublicAddress: fmt.Sprintf("0.0.0.0:%d", relayPort),
		DNSUpstream:   "127.0.0.1:53",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := labServer.Shutdown(shutdownCtx); err != nil {
			t.Errorf("lab relay shutdown: %v", err)
		}
		if err := labServer.Close(); err != nil {
			t.Errorf("lab server close: %v", err)
		}
	})

	relayListener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", relayPort))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = labServer.ServeFirstHop(relayListener) }()
	issuerServer := &http.Server{
		Handler:           labServer.IssuerHandler(),
		TLSConfig:         labServer.IssuerTLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	issuerListener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", issuerPort))
	if err != nil {
		t.Fatal(err)
	}
	defer issuerListener.Close()
	go func() { _ = issuerServer.Serve(tls.NewListener(issuerListener, issuerServer.TLSConfig)) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = issuerServer.Shutdown(shutdownCtx)
	})

	// The client trusts only the minted lab TLS certificate for the issuer
	// exchange; the relay carrier pins the same certificate through the
	// provisioning trust roots.
	certificatePEM, err := os.ReadFile(filepath.Join(dir, FileTLSCertificate))
	if err != nil {
		t.Fatal(err)
	}
	issuerRoots := x509.NewCertPool()
	if !issuerRoots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("minted TLS certificate did not parse as PEM")
	}

	trustEncoded, err := os.ReadFile(filepath.Join(dir, FileNativeProvisioningTrust))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := client.ParseNativeProvisioningTrust(trustEncoded)
	if err != nil {
		t.Fatalf("minted trust file rejected: %v", err)
	}
	walletEncoded, err := os.ReadFile(filepath.Join(dir, FileWallet))
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := client.ParseNativeProvisioningWalletWithTrust(walletEncoded, trusted, time.Now().UTC())
	if err != nil {
		t.Fatalf("minted wallet rejected: %v", err)
	}
	defer wallet.Zero()
	reservation, err := wallet.Reserve(nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Zero()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provisioned, work, err := client.BeginProvisionedSession(ctx, reservation.Provisioning, client.ProvisionedSessionOptions{IssuerTimeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("begin provisioned session against lab relay: %v", err)
	}
	defer provisioned.Close()

	// Live issuer exchange, mirroring aurorac's exchangeIssuerWork with a
	// lab-trusted TLS client. The work fields are copied before Zero erases
	// the caller-owned work buffer.
	issuerClient := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: issuerRoots},
	}}
	var (
		issuerURL         = work.IssuerURL
		issuerCarrierPath = work.IssuerCarrierPath
		issuerRequestBody = append([]byte(nil), work.RequestBody...)
	)
	work.Zero()
	defer func(b []byte) {
		for i := range b {
			b[i] = 0
		}
	}(issuerRequestBody)
	issuerRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, issuerURL+issuerCarrierPath, bytes.NewReader(issuerRequestBody))
	if err != nil {
		t.Fatal(err)
	}
	issuerRequest.Header.Set("Accept", "application/octet-stream")
	issuerRequest.Header.Set("Content-Type", "application/octet-stream")
	issuerResponseHTTP, err := issuerClient.Do(issuerRequest)
	if err != nil {
		t.Fatalf("lab issuer request: %v", err)
	}
	defer issuerResponseHTTP.Body.Close()
	if issuerResponseHTTP.StatusCode != http.StatusOK {
		t.Fatalf("lab issuer status = %d", issuerResponseHTTP.StatusCode)
	}
	issuerResponse, err := io.ReadAll(io.LimitReader(issuerResponseHTTP.Body, 1<<20+1))
	if err != nil {
		t.Fatal(err)
	}
	defer func(b []byte) {
		for i := range b {
			b[i] = 0
		}
	}(issuerResponse)
	established, err := provisioned.Complete(ctx, issuerResponse)
	if err != nil {
		t.Fatalf("complete provisioned session: %v", err)
	}
	defer established.Close()

	// Run the production local proxy runtime over the established session.
	runtime, err := client.NewTCPProxyRuntime(established.Application, client.TCPProxyRuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	socksListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksListener.Close()
	go func() { _ = runtime.Serve(ctx, socksListener) }()
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(ctx, established.ReadCarrier, established.WriteCarrier, established.Application, runtime.HandleFrameBlock, transport.DefaultMaxRecordBodyBytes)
	}()

	// Drive a SOCKS5 CONNECT through the tunnel to the lab cover origin.
	response := socks5GetThroughTunnel(t, ctx, socksListener.Addr().String(), labServer.CoverAddress(), "/")
	if !strings.Contains(response, "auroralab cover origin") {
		t.Fatalf("tunneled response did not reach the lab cover origin: %q", response)
	}

	cancel()
	select {
	case err := <-pumpResult:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("packet pump stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("packet pump did not stop after cancellation")
	}
}

// socks5GetThroughTunnel performs a no-auth SOCKS5 CONNECT to targetHostPort
// via the proxy at proxyAddr, issues an HTTP GET, and reads the response.
func socks5GetThroughTunnel(t *testing.T, ctx context.Context, proxyAddr, targetHostPort, path string) string {
	t.Helper()
	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := connection.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(connection, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting = %x", greeting)
	}
	host, portText, err := net.SplitHostPort(targetHostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("lab test target is not IPv4: %s", host)
	}
	request := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(request[8:], uint16(port))
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 connect reply = %x", reply)
	}
	var rest int
	switch reply[3] {
	case 0x01:
		rest = 4 + 2
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(connection, length); err != nil {
			t.Fatal(err)
		}
		rest = int(length[0]) + 2
	default:
		t.Fatalf("SOCKS5 reply address type = %d", reply[3])
	}
	if _, err := io.ReadFull(connection, make([]byte, rest)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, targetHostPort); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("tunneled HTTP status line = %q", strings.TrimSpace(status))
	}
	body, err := io.ReadAll(io.LimitReader(reader, 1<<16))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
