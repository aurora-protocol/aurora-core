//go:build cgo

package main

import (
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
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/internal/labfixture"
)

// auroralabServeFixture mints a lab deployment and serves it through
// labfixture (auroralab serve's exact wiring) on loopback.
type auroralabServeFixture struct {
	labServer *labfixture.Server
	dir       string
}

func newAuroralabServeFixture(t *testing.T) *auroralabServeFixture {
	t.Helper()
	relayPort := auroralabTestPort(t)
	issuerPort := auroralabTestPort(t)
	material, err := labfixture.Mint(labfixture.MintOptions{
		RelayHost:  "127.0.0.1",
		RelayPort:  relayPort,
		IssuerPort: issuerPort,
		Entries:    4,
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
	})
	if err != nil {
		t.Fatal(err)
	}
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
	go func() { _ = issuerServer.Serve(tls.NewListener(issuerListener, issuerServer.TLSConfig)) }()
	fixture := &auroralabServeFixture{labServer: labServer, dir: dir}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := labServer.Shutdown(shutdownCtx); err != nil {
			t.Errorf("lab relay shutdown: %v", err)
		}
		_ = issuerServer.Shutdown(shutdownCtx)
		if err := labServer.Close(); err != nil {
			t.Errorf("lab server close: %v", err)
		}
		_ = relayListener.Close()
		_ = issuerListener.Close()
	})
	return fixture
}

// issue performs the real HTTPS Blind RSA issuer exchange against the lab
// issuer, trusting the minted lab CA like a device with ca.pem installed.
func (f *auroralabServeFixture) issue(t *testing.T, issuerURL, carrierPath string, requestBody []byte) []byte {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(f.dir, labfixture.FileCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("minted lab CA certificate did not parse")
	}
	httpClient := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, issuerURL+carrierPath, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("lab issuer exchange: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("lab issuer status = %d", response.StatusCode)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// reserveWalletEntry loads the minted wallet through the production trust and
// returns one reserved provisioning entry, as the app's import flow does.
func (f *auroralabServeFixture) reserveWalletEntry(t *testing.T) (client.NativeProvisioning, client.NativeProvisioningTrust) {
	t.Helper()
	trustEncoded, err := os.ReadFile(filepath.Join(f.dir, labfixture.FileNativeProvisioningTrust))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(trustEncoded)
	trusted, err := client.ParseNativeProvisioningTrust(trustEncoded)
	if err != nil {
		t.Fatal(err)
	}
	walletEncoded, err := os.ReadFile(filepath.Join(f.dir, labfixture.FileWallet))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(walletEncoded)
	wallet, err := client.ParseNativeProvisioningWalletWithTrust(walletEncoded, trusted, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Zero()
	reservation, err := wallet.Reserve(nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return reservation.Provisioning, trusted
}

func auroralabTestPort(t *testing.T) int {
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

// TestNativeSessionABIAgainstAuroralabServe drives the real native session ABI
// (the exact path the Android client runs) against auroralab's serve wiring,
// and requires the packet data plane to answer DNS, TCP, and UDP packets.
func TestNativeSessionABIAgainstAuroralabServe(t *testing.T) {
	fixture := newAuroralabServeFixture(t)
	provisioning, trusted := fixture.reserveWalletEntry(t)
	issuerURL, issuerCarrierPath := provisioning.IssuerURL, provisioning.IssuerCarrierPath
	caller := newNativeIntegrationCaller(t, trusted)

	work := nativeIntegrationBegin(t, caller, provisioning)
	defer nativeIntegrationClose(t, caller, work.handle)
	issuerResponse := fixture.issue(t, issuerURL, issuerCarrierPath, work.requestBody)
	if status, payload := nativeIntegrationCall(t, caller, opCompleteNativeSessionRaw, issuerResponse, work.handle); status != statusOK || len(payload) != 0 {
		t.Fatalf("native completion = status %d payload %x", status, payload)
	}

	// DNS through the tunnel.
	query := nativeDNSQuery("anything.auroralab.test")
	dnsRequest := nativeUDPv4([4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if packets := nativeIntegrationIngress(t, caller, work.handle, dnsRequest); len(packets) != 0 {
		t.Fatalf("DNS ingress returned %d local packets before relay resolution", len(packets))
	}
	dnsResponse := nativeIntegrationNextLocalPacket(t, caller, work.handle)
	if len(dnsResponse) < 28 || binary.BigEndian.Uint16(dnsResponse[20:22]) != 53 {
		t.Fatalf("native DNS response has invalid UDP tuple: %x", dnsResponse)
	}
	dns := dnsResponse[28:]
	if len(dns) < len(query)+16 || !bytes.Equal(dns[:2], query[:2]) || dns[2]&0x80 == 0 || !bytes.Equal(dns[len(dns)-4:], []byte{127, 0, 0, 1}) {
		t.Fatalf("native DNS response = %x", dns)
	}

	// UDP echo through the tunnel.
	udpPayload := []byte("native UDP echo")
	udpRequest := nativeUDPv4([4]byte{10, 0, 0, 2}, [4]byte{192, 0, 2, 9}, 40000, 9999, udpPayload)
	_ = nativeIntegrationIngress(t, caller, work.handle, udpRequest)
	udpResponse := nativeIntegrationNextLocalPacket(t, caller, work.handle)
	if len(udpResponse) < 28 || !bytes.Equal(udpResponse[28:], udpPayload) {
		t.Fatalf("UDP echo response = %x", udpResponse)
	}

	// TCP through the tunnel to the cover origin.
	coverPort := auroralabTestPortNumber(t, fixture.labServer.CoverAddress())
	tcpRequest := nativeTCPv4([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 50000, coverPort, 100, 0, 0x02, nil)
	tcpImmediate := nativeIntegrationIngress(t, caller, work.handle, tcpRequest)
	if len(tcpImmediate) != 1 || len(tcpImmediate[0]) < 34 || tcpImmediate[0][33] != 0x12 {
		t.Fatalf("TCP SYN immediate packets = %x", tcpImmediate)
	}
	tcpData := nativeTCPv4([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 50000, coverPort, 101, binary.BigEndian.Uint32(tcpImmediate[0][24:28])+1, 0x18, []byte("GET / HTTP/1.0\r\n\r\n"))
	_ = nativeIntegrationIngress(t, caller, work.handle, tcpData)
	deadline := time.Now().Add(5 * time.Second)
	var received []byte
	for time.Now().Before(deadline) && !bytes.Contains(received, []byte("auroralab cover origin")) {
		packet := nativeIntegrationNextLocalPacket(t, caller, work.handle)
		if len(packet) > 40 {
			received = append(received, packet[40:]...)
		}
	}
	if !bytes.Contains(received, []byte("auroralab cover origin")) {
		t.Fatalf("tunneled TCP response did not include the cover body: %q", received)
	}
}

// TestNativeSessionABIAgainstAuroralabServeSurvivesFlowBurst reproduces the
// Pixel 7 on-device failure through the exact native session ABI the Android
// client drives: with lab loopback egress every flow succeeds and lingers, so
// the device-scale burst of concurrent UDP associations at VPN startup exceeds
// an under-provisioned relay flow limit, and the fail-closed first hop resets
// the carrier stream (stream 1 RST_STREAM INTERNAL_ERROR), terminalling the
// native session. The lab serve wiring must survive this burst.
func TestNativeSessionABIAgainstAuroralabServeSurvivesFlowBurst(t *testing.T) {
	fixture := newAuroralabServeFixture(t)
	provisioning, trusted := fixture.reserveWalletEntry(t)
	issuerURL, issuerCarrierPath := provisioning.IssuerURL, provisioning.IssuerCarrierPath
	caller := newNativeIntegrationCaller(t, trusted)

	work := nativeIntegrationBegin(t, caller, provisioning)
	defer nativeIntegrationClose(t, caller, work.handle)
	issuerResponse := fixture.issue(t, issuerURL, issuerCarrierPath, work.requestBody)
	if status, payload := nativeIntegrationCall(t, caller, opCompleteNativeSessionRaw, issuerResponse, work.handle); status != statusOK || len(payload) != 0 {
		t.Fatalf("native completion = status %d payload %x", status, payload)
	}

	// 32 concurrent UDP flows (distinct source ports), each expecting an echo:
	// double the 16-flow limit that killed the on-device session.
	const flows = 32
	for index := 0; index < flows; index++ {
		request := nativeUDPv4([4]byte{10, 0, 0, 2}, [4]byte{192, 0, 2, 9}, uint16(40000+index), 9999, []byte{byte(index)})
		if packets := nativeIntegrationIngress(t, caller, work.handle, request); len(packets) != 0 {
			t.Fatalf("UDP ingress %d returned %d unexpected local packets", index, len(packets))
		}
	}
	for echoes := 0; echoes < flows; echoes++ {
		response := nativeIntegrationNextLocalPacket(t, caller, work.handle)
		if len(response) < 28 {
			t.Fatalf("burst echo %d has an invalid UDP tuple: %x", echoes, response)
		}
	}
	// The carrier must still be alive and serving after the burst.
	postBurst := []byte("post-burst")
	request := nativeUDPv4([4]byte{10, 0, 0, 2}, [4]byte{192, 0, 2, 9}, 41000, 9999, postBurst)
	_ = nativeIntegrationIngress(t, caller, work.handle, request)
	response := nativeIntegrationNextLocalPacket(t, caller, work.handle)
	if len(response) < 28 || !bytes.Equal(response[28:], postBurst) {
		t.Fatalf("post-burst UDP echo response = %x", response)
	}
}

func auroralabTestPortNumber(t *testing.T, address string) uint16 {
	t.Helper()
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil || port <= 0 || port > 65535 {
		t.Fatalf("invalid port in %q", address)
	}
	return uint16(port)
}
