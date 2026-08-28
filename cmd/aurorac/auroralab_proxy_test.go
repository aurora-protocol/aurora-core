package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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

	"github.com/aurora-protocol/aurora-core/internal/labfixture"
)

// TestProxyCompletesAgainstAuroralabDeployment runs the real aurorac proxy
// command path against a deployment minted and served by auroralab
// (internal/labfixture) on loopback. Only the two existing test seams are
// overridden: the Linux host gate (aurorac proxy is Linux-only in production;
// this test exercises the identical code path on the development host) and
// the issuer HTTP client (production trusts system roots; the lab issuer is
// self-signed, so the test client trusts exactly the minted certificate).
//
// This is the acceptance proof that a minted wallet + trust file drive a real
// client handshake and proxied request end to end.
func TestProxyCompletesAgainstAuroralabDeployment(t *testing.T) {
	relayPort := reserveLabFreePort(t)
	issuerPort := reserveLabFreePort(t)
	material, err := labfixture.Mint(labfixture.MintOptions{
		RelayHost:  "127.0.0.1",
		RelayPort:  relayPort,
		IssuerPort: issuerPort,
		Entries:    2,
		Now:        time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}

	loaded, err := labfixture.Load(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	labServer, err := labfixture.NewServer(loaded, labfixture.ServerOptions{
		PublicAddress: fmt.Sprintf("0.0.0.0:%d", relayPort),
		DNSUpstream:   "127.0.0.1:53",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
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
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = issuerServer.Shutdown(shutdownCtx)
	})

	// The lab issuer is self-signed; trust exactly the minted certificate.
	certificatePEM, err := os.ReadFile(filepath.Join(dir, labfixture.FileTLSCertificate))
	if err != nil {
		t.Fatal(err)
	}
	issuerRoots := x509.NewCertPool()
	if !issuerRoots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("minted TLS certificate did not parse")
	}
	restoreIssuerClient := setNewIssuerHTTPClientForTest(func() *http.Client {
		return &http.Client{Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: issuerRoots},
		}}
	})
	defer restoreIssuerClient()
	restoreGOOS := setProxyGOOSForTest("linux")
	defer restoreGOOS()
	proxyCtx, proxyCancel := context.WithCancel(context.Background())
	defer proxyCancel()
	previousSignalContext := proxySignalContext
	proxySignalContext = func() (context.Context, context.CancelFunc) { return proxyCtx, func() {} }
	defer func() { proxySignalContext = previousSignalContext }()

	httpPort := reserveLabFreePort(t)
	socksPort := reserveLabFreePort(t)
	stdoutReader, stdoutWriter := io.Pipe()
	defer stdoutReader.Close()
	var stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		code := run([]string{
			"proxy",
			"--provisioning-wallet", filepath.Join(dir, labfixture.FileWallet),
			"--wallet-state", filepath.Join(dir, "wallet-state.bin"),
			"--signed-seed-roots", filepath.Join(dir, labfixture.FileNativeProvisioningTrust),
			"--http-listen", fmt.Sprintf("127.0.0.1:%d", httpPort),
			"--socks-listen", fmt.Sprintf("127.0.0.1:%d", socksPort),
		}, stdoutWriter, &stderr)
		_ = stdoutWriter.Close()
		result <- code
	}()
	lines := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(stdoutReader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	var socksAddress string
	select {
	case line := <-lines:
		// Expect: aurorac local proxy http=127.0.0.1:X socks=127.0.0.1:Y
		const marker = " socks="
		index := strings.Index(line, marker)
		if !strings.HasPrefix(line, "aurorac local proxy http=") || index < 0 {
			t.Fatalf("proxy startup line = %q", line)
		}
		socksAddress = strings.TrimSpace(line[index+len(marker):])
	case code := <-result:
		t.Fatalf("proxy exited before startup with code %d: stderr=%s", code, stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("proxy did not establish a session against the lab deployment")
	}

	// Drive a SOCKS5 request through the production proxy to the lab cover
	// origin; this proves wallet reservation, handshake, issuer exchange, and
	// relay egress all work with the minted material.
	response := labSOCKS5Get(t, socksAddress, labServer.CoverAddress(), "/")
	if !strings.Contains(response, "auroralab cover origin") {
		t.Fatalf("proxied response did not reach the lab cover origin: %q", response)
	}

	proxyCancel()
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("proxy shutdown code = %d, want 0", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("proxy did not stop after cancellation")
	}
}

// reserveLabFreePort returns a currently free loopback TCP port.
func reserveLabFreePort(t *testing.T) int {
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

// labSOCKS5Get performs a no-auth SOCKS5 CONNECT via the proxy and issues an
// HTTP GET, returning the response body.
func labSOCKS5Get(t *testing.T, proxyAddress, targetHostPort, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp4", proxyAddress)
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
		t.Fatalf("target is not IPv4: %s", host)
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
		t.Fatalf("proxied HTTP status line = %q", strings.TrimSpace(status))
	}
	body, err := io.ReadAll(io.LimitReader(reader, 1<<16))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
