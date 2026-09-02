package client

// Coverage for the SOCKS5/HTTP-CONNECT parsing and UDP-association failure
// branches in tcp_proxy_runtime.go: readTCPProxyHeader (:482),
// tcpProxyReadExact (:601), tcpProxySOCKS5AddressBytes (:575),
// socks5UDPDatagram (:928), and serveSOCKS5UDPAssociation (:697). Truncated
// and malformed inputs must be rejected without panics, and the UDP
// association must honor its lifecycle (context cancel, runtime close,
// association limit). In-package (package client) because the helpers are
// unexported; reuses tcpProxyRuntimeApplications. No external network:
// control connections are loopback TCP or net.Pipe.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadTCPProxyHeaderRejectsInvalidLimit(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("CONNECT target.example:443 HTTP/1.1\r\n\r\n"))
	if _, err := readTCPProxyHeader(reader, minimumTCPProxyReadBufferBytes-1); err == nil || !strings.Contains(err.Error(), "header limit is invalid") {
		t.Fatalf("readTCPProxyHeader below the minimum limit error = %v", err)
	}
}

func TestReadTCPProxyHeaderRejectsTruncatedHeader(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("CONNECT target.example:443 HTTP/1.1\r\n"))
	if _, err := readTCPProxyHeader(reader, minimumTCPProxyReadBufferBytes); !errors.Is(err, io.EOF) {
		t.Fatalf("truncated header error = %v, want EOF", err)
	}
}

func TestReadTCPProxyHeaderRejectsOversizedHeader(t *testing.T) {
	line := bytes.Repeat([]byte{0x41}, minimumTCPProxyReadBufferBytes)
	reader := bufio.NewReader(bytes.NewReader(append(line, '\r', '\n')))
	if _, err := readTCPProxyHeader(reader, minimumTCPProxyReadBufferBytes); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversized header error = %v", err)
	}
}

func TestReadTCPProxyHeaderRejectsOverlongLine(t *testing.T) {
	// A line that never fits the bufio buffer surfaces bufio.ErrBufferFull and
	// must be reported as a limit violation rather than a raw read error.
	reader := bufio.NewReaderSize(strings.NewReader(string(bytes.Repeat([]byte{0x42}, 256))), 64)
	if _, err := readTCPProxyHeader(reader, minimumTCPProxyReadBufferBytes); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("overlong header line error = %v", err)
	}
}

func TestReadTCPProxyHeaderReturnsCompleteHeader(t *testing.T) {
	header := "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\n"
	raw, err := readTCPProxyHeader(bufio.NewReader(strings.NewReader(header)), minimumTCPProxyReadBufferBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != header {
		t.Fatalf("readTCPProxyHeader = %q, want %q", raw, header)
	}
}

func TestTCPProxyReadExactRejectsInvalidLength(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("abcdef"))
	if _, err := tcpProxyReadExact(reader, 0); err == nil || !strings.Contains(err.Error(), "invalid SOCKS5 address length") {
		t.Fatalf("zero-length read error = %v", err)
	}
}

func TestTCPProxyReadExactRejectsShortRead(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("ab"))
	if _, err := tcpProxyReadExact(reader, 6); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short read error = %v, want unexpected EOF", err)
	}
}

func TestTCPProxyReadExactReadsExactLength(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("abcdef"))
	value, err := tcpProxyReadExact(reader, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "abcd" {
		t.Fatalf("tcpProxyReadExact = %q, want %q", value, "abcd")
	}
}

func TestTCPProxySOCKS5AddressBytesRejectsUnsupportedType(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\x01\x02\x03\x04"))
	if _, err := tcpProxySOCKS5AddressBytes(reader, 0x09); err == nil || !strings.Contains(err.Error(), "unsupported SOCKS5 address type") {
		t.Fatalf("unsupported address type error = %v", err)
	}
}

func TestTCPProxySOCKS5AddressBytesReadsIPv4AndIPv6(t *testing.T) {
	ipv4 := []byte{203, 0, 113, 9, 0x01, 0xbb}
	value, err := tcpProxySOCKS5AddressBytes(bufio.NewReader(bytes.NewReader(ipv4)), socksATYPIPv4)
	if err != nil || !bytes.Equal(value, ipv4) {
		t.Fatalf("IPv4 address bytes = %x, err = %v", value, err)
	}
	ipv6 := append(bytes.Repeat([]byte{0x20}, 16), 0x14, 0xe9)
	value, err = tcpProxySOCKS5AddressBytes(bufio.NewReader(bytes.NewReader(ipv6)), socksATYPIPv6)
	if err != nil || !bytes.Equal(value, ipv6) {
		t.Fatalf("IPv6 address bytes = %x, err = %v", value, err)
	}
}

func TestTCPProxySOCKS5AddressBytesRejectsEmptyDomain(t *testing.T) {
	reader := bufio.NewReader(bytes.NewReader([]byte{0x00}))
	if _, err := tcpProxySOCKS5AddressBytes(reader, socksATYPDomain); err == nil || !strings.Contains(err.Error(), "domain target is empty") {
		t.Fatalf("empty domain error = %v", err)
	}
}

func TestTCPProxySOCKS5AddressBytesRejectsMissingDomainLength(t *testing.T) {
	reader := bufio.NewReader(bytes.NewReader(nil))
	if _, err := tcpProxySOCKS5AddressBytes(reader, socksATYPDomain); !errors.Is(err, io.EOF) {
		t.Fatalf("missing domain length error = %v, want EOF", err)
	}
}

func TestTCPProxySOCKS5AddressBytesRejectsTruncatedDomain(t *testing.T) {
	reader := bufio.NewReader(bytes.NewReader([]byte{0x0a, 'e', 'x', 'a'}))
	if _, err := tcpProxySOCKS5AddressBytes(reader, socksATYPDomain); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated domain error = %v, want unexpected EOF", err)
	}
}

func TestTCPProxySOCKS5AddressBytesReadsDomain(t *testing.T) {
	encoded := append([]byte{byte(len("target.example"))}, []byte("target.example")...)
	encoded = append(encoded, 0x01, 0xbb)
	value, err := tcpProxySOCKS5AddressBytes(bufio.NewReader(bytes.NewReader(encoded)), socksATYPDomain)
	if err != nil || !bytes.Equal(value, encoded) {
		t.Fatalf("domain address bytes = %x, err = %v", value, err)
	}
}

func TestSocks5UDPDatagramBuildsAddressedDatagrams(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		prefix []byte
	}{
		{name: "IPv4", host: "203.0.113.9", prefix: []byte{0, 0, 0, socksATYPIPv4, 203, 0, 113, 9, 0x14, 0xe9}},
		{name: "IPv6", host: "2001:db8::1", prefix: []byte{0, 0, 0, socksATYPIPv6, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x14, 0xe9}},
		{name: "domain", host: "target.example", prefix: append([]byte{0, 0, 0, socksATYPDomain, byte(len("target.example"))}, append([]byte("target.example"), 0x14, 0xe9)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, err := socks5UDPDatagram(test.host, 5353, []byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			want := append(test.prefix, []byte("payload")...)
			if !bytes.Equal(packet, want) {
				t.Fatalf("SOCKS5 UDP datagram = %x, want %x", packet, want)
			}
		})
	}
}

func TestSocks5UDPDatagramRejectsInvalidTargets(t *testing.T) {
	if _, err := socks5UDPDatagram("", 5353, nil); err == nil {
		t.Fatal("empty SOCKS5 UDP target was accepted")
	}
	if _, err := socks5UDPDatagram("bad/target", 5353, nil); err == nil {
		t.Fatal("invalid SOCKS5 UDP domain was accepted")
	}
	oversized := strings.Repeat("a", 256)
	if _, err := socks5UDPDatagram(oversized, 5353, nil); err == nil || !strings.Contains(err.Error(), "domain is too long") {
		t.Fatalf("oversized SOCKS5 UDP domain error = %v", err)
	}
}

func TestServeSOCKS5UDPAssociationRequiresLiveContext(t *testing.T) {
	clientApplication, _ := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.serveSOCKS5UDPAssociation(ctx, bufio.NewReader(clientConnection), serverConnection, "0.0.0.0", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled UDP association error = %v, want context canceled", err)
	}
}

func TestServeSOCKS5UDPAssociationRejectsNonTCPControlPeer(t *testing.T) {
	clientApplication, _ := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()
	err = runtime.serveSOCKS5UDPAssociation(context.Background(), bufio.NewReader(clientConnection), serverConnection, "0.0.0.0", 0)
	var requestErr *socks5RequestError
	if !errors.As(err, &requestErr) || requestErr.reply != socksReplyGeneralFailure {
		t.Fatalf("non-TCP control peer error = %v, want SOCKS5 general failure", err)
	}
}

func socks5UDPAssociationControlPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	acceptResult := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			acceptResult <- connection
		}
	}()
	clientConnection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConnection.Close() })
	select {
	case serverConnection := <-acceptResult:
		t.Cleanup(func() { _ = serverConnection.Close() })
		return serverConnection, clientConnection
	case <-time.After(5 * time.Second):
		t.Fatal("loopback control connection was not accepted")
		return nil, nil
	}
}

func TestServeSOCKS5UDPAssociationRejectsMismatchedPeer(t *testing.T) {
	clientApplication, _ := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	serverConnection, clientConnection := socks5UDPAssociationControlPair(t)
	err = runtime.serveSOCKS5UDPAssociation(context.Background(), bufio.NewReader(clientConnection), serverConnection, "127.0.0.2", 0)
	var requestErr *socks5RequestError
	if !errors.As(err, &requestErr) || !strings.Contains(err.Error(), "does not match control connection") {
		t.Fatalf("mismatched UDP peer error = %v", err)
	}
}

func TestServeSOCKS5UDPAssociationHonorsAssociationLimit(t *testing.T) {
	clientApplication, _ := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately no runtime.Close: the placeholder association has no socket,
	// matching TestTCPProxyRuntimeBoundsUDPAssociations.
	if err := runtime.addUDPAssociation(&udpProxyAssociation{}); err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := socks5UDPAssociationControlPair(t)
	if err := runtime.serveSOCKS5UDPAssociation(context.Background(), bufio.NewReader(clientConnection), serverConnection, "0.0.0.0", 0); !errors.Is(err, ErrTCPProxyFlowLimit) {
		t.Fatalf("UDP association beyond the limit error = %v, want flow limit", err)
	}
}

func TestServeSOCKS5UDPAssociationStopsOnContextCancel(t *testing.T) {
	clientApplication, _ := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	serverConnection, clientConnection := socks5UDPAssociationControlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- runtime.serveSOCKS5UDPAssociation(ctx, bufio.NewReader(clientConnection), serverConnection, "0.0.0.0", 0)
	}()
	response := tcpProxyRuntimeReadExactly(t, clientConnection, len(socksSuccessResponse))
	if response[0] != socksVersion5 || response[1] != 0 {
		t.Fatalf("SOCKS5 UDP associate response = %x", response)
	}
	cancel()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("cancelled UDP association serve error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UDP association did not stop on context cancel")
	}
}

func TestServeSOCKS5UDPAssociationStopsOnRuntimeClose(t *testing.T) {
	clientApplication, _ := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := socks5UDPAssociationControlPair(t)
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- runtime.serveSOCKS5UDPAssociation(context.Background(), bufio.NewReader(clientConnection), serverConnection, "0.0.0.0", 0)
	}()
	response := tcpProxyRuntimeReadExactly(t, clientConnection, len(socksSuccessResponse))
	if response[0] != socksVersion5 || response[1] != 0 {
		t.Fatalf("SOCKS5 UDP associate response = %x", response)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("runtime-closed UDP association serve error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UDP association did not stop on runtime close")
	}
}
