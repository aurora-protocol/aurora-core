package labfixture

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
	"strconv"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/transport"
)

// packetLabClient bundles a completed production client session with the
// packet adapter the mobile TUN data plane uses.
type packetLabClient struct {
	adapter      *client.PacketAdapter
	established  interface{ Close() error }
	cancel       context.CancelFunc
	pumpResult   chan error
	localPackets chan []byte
}

// startPacketLabClient mints, serves, and connects a production client, then
// attaches the production PacketAdapter exactly as the mobile native session
// does (mobile/auroracore/session.go runNativeDuplex).
func startPacketLabClient(t *testing.T, serverOptions ServerOptions) (*packetLabClient, *Server) {
	t.Helper()
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
	if serverOptions.PublicAddress == "" {
		serverOptions.PublicAddress = fmt.Sprintf("0.0.0.0:%d", relayPort)
	}
	labServer, err := NewServer(loaded, serverOptions)
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
	t.Cleanup(func() { _ = issuerListener.Close() })
	go func() { _ = issuerServer.Serve(tls.NewListener(issuerListener, issuerServer.TLSConfig)) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = issuerServer.Shutdown(shutdownCtx)
	})

	caPEM, err := os.ReadFile(filepath.Join(dir, FileCA))
	if err != nil {
		t.Fatal(err)
	}
	issuerRoots := x509.NewCertPool()
	if !issuerRoots.AppendCertsFromPEM(caPEM) {
		t.Fatal("minted lab CA certificate did not parse as PEM")
	}
	trustEncoded, err := os.ReadFile(filepath.Join(dir, FileNativeProvisioningTrust))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := client.ParseNativeProvisioningTrust(trustEncoded)
	if err != nil {
		t.Fatal(err)
	}
	walletEncoded, err := os.ReadFile(filepath.Join(dir, FileWallet))
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := client.ParseNativeProvisioningWalletWithTrust(walletEncoded, trusted, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Zero()
	reservation, err := wallet.Reserve(nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Zero()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	provisioned, work, err := client.BeginProvisionedSession(ctx, reservation.Provisioning, client.ProvisionedSessionOptions{IssuerTimeout: 20 * time.Second})
	if err != nil {
		cancel()
		t.Fatalf("begin provisioned session against lab relay: %v", err)
	}
	var (
		issuerURL         = work.IssuerURL
		issuerCarrierPath = work.IssuerCarrierPath
		issuerRequestBody = append([]byte(nil), work.RequestBody...)
	)
	work.Zero()
	issuerClient := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: issuerRoots},
	}}
	issuerRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, issuerURL+issuerCarrierPath, bytes.NewReader(issuerRequestBody))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	issuerRequest.Header.Set("Accept", "application/octet-stream")
	issuerRequest.Header.Set("Content-Type", "application/octet-stream")
	issuerResponseHTTP, err := issuerClient.Do(issuerRequest)
	if err != nil {
		cancel()
		t.Fatalf("lab issuer request: %v", err)
	}
	issuerResponse, err := io.ReadAll(io.LimitReader(issuerResponseHTTP.Body, 1<<20+1))
	_ = issuerResponseHTTP.Body.Close()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if issuerResponseHTTP.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("lab issuer status = %d", issuerResponseHTTP.StatusCode)
	}
	established, err := provisioned.Complete(ctx, issuerResponse)
	if err != nil {
		cancel()
		t.Fatalf("complete provisioned session: %v", err)
	}
	t.Cleanup(func() { _ = provisioned.Close() })

	adapter, err := client.NewPacketAdapter(established.Application, client.PacketAdapterOptions{})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	result := &packetLabClient{
		adapter:      adapter,
		established:  established,
		cancel:       cancel,
		pumpResult:   make(chan error, 1),
		localPackets: make(chan []byte, 64),
	}
	go func() {
		result.pumpResult <- transport.RunPacketDuplex(ctx, established.ReadCarrier, established.WriteCarrier, established.Application, func(frameContext context.Context, block protocol.FrameBlock) error {
			// Relay-originated local packets are returned, mirroring the
			// mobile native session's runNativeDuplex enqueue step.
			packets, err := adapter.HandleFrameBlocks(frameContext, []protocol.FrameBlock{block}, time.Now().UTC())
			for _, packet := range packets {
				select {
				case result.localPackets <- packet:
				case <-frameContext.Done():
					return frameContext.Err()
				}
			}
			return err
		}, transport.DefaultMaxRecordBodyBytes)
	}()
	t.Cleanup(func() {
		cancel()
		_ = established.Close()
		adapter.Close()
	})
	return result, labServer
}

// nextLocalPacket waits for the next local packet from either the adapter's
// internal queue (locally generated) or the pump-delivered relay packets.
func nextLocalPacket(t *testing.T, clientSide *packetLabClient, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if packets := clientSide.adapter.DrainLocalPackets(); len(packets) != 0 {
			return packets[0]
		}
		select {
		case packet := <-clientSide.localPackets:
			return packet
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no local packet arrived before the deadline")
	return nil
}

// drainLocalPackets collects all currently available local packets from both
// sources.
func drainLocalPackets(clientSide *packetLabClient) [][]byte {
	packets := clientSide.adapter.DrainLocalPackets()
	for {
		select {
		case packet := <-clientSide.localPackets:
			packets = append(packets, packet)
		default:
			return packets
		}
	}
}

// TestLabPacketDataPlaneReproducesCarrierResetOnFailedEgress demonstrates the
// Pixel 7 failure mode observed on-device ("packet carrier read failed:
// stream error: stream ID 1; INTERNAL_ERROR; received from peer"): with real
// egress, one TCP flow to a target the relay cannot dial makes the production
// first hop reset the whole carrier stream (the egress dial error escapes the
// frame handler), killing the session. This is why the lab server defaults to
// loopback egress where every flow lands on an in-process endpoint.
func TestLabPacketDataPlaneReproducesCarrierResetOnFailedEgress(t *testing.T) {
	clientSide, labServer := startPacketLabClient(t, ServerOptions{DNSUpstream: "127.0.0.1:53"})
	if labServer.LabEgress() {
		t.Fatal("internet-egress mode unexpectedly reported lab egress")
	}

	// A healthy flow first: TCP to the loopback cover origin must complete a
	// real data exchange before the failing flow.
	coverAddr := labServer.CoverAddress()
	_, coverPortText, err := net.SplitHostPort(coverAddr)
	if err != nil {
		t.Fatal(err)
	}
	coverPort, err := strconv.Atoi(coverPortText)
	if err != nil {
		t.Fatal(err)
	}
	syn := labTCPv4([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 50000, uint16(coverPort), 100, 0, 0x02, nil)
	if err := clientSide.adapter.Ingress(context.Background(), syn, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	synAck := nextLocalPacket(t, clientSide, 5*time.Second)
	if len(synAck) < 34 || synAck[33] != 0x12 {
		t.Fatalf("TCP SYN-ACK = %x", synAck)
	}
	labTCPExchange(t, clientSide, [4]byte{127, 0, 0, 1}, 50000, uint16(coverPort), synAck, "GET / HTTP/1.0\r\n\r\n")

	// Now a flow to a loopback port nothing listens on: the relay's egress
	// dial is refused instantly.
	closedPort := uint16(reserveLabPort(t))
	deadSyn := labTCPv4([4]byte{10, 0, 0, 2}, [4]byte{127, 0, 0, 1}, 50010, closedPort, 100, 0, 0x02, nil)
	if err := clientSide.adapter.Ingress(context.Background(), deadSyn, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-clientSide.pumpResult:
		if err == nil {
			t.Log("carrier closed without error")
		} else {
			t.Logf("carrier died after failed egress dial: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("carrier survived a failed egress dial; reproduction scenario no longer applies")
	}
}

func labTCPv4(source, target [4]byte, sourcePort, targetPort uint16, sequence, acknowledgment uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], source[:])
	copy(packet[16:20], target[:])
	binary.BigEndian.PutUint16(packet[10:12], labChecksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], targetPort)
	binary.BigEndian.PutUint32(packet[24:28], sequence)
	binary.BigEndian.PutUint32(packet[28:32], acknowledgment)
	packet[32] = 0x50
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:36], 65535)
	copy(packet[40:], payload)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], target[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	binary.BigEndian.PutUint16(packet[36:38], labChecksum(pseudo, packet[20:]))
	return packet
}

func labUDPv4(source, target [4]byte, sourcePort, targetPort uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], target[:])
	binary.BigEndian.PutUint16(packet[10:12], labChecksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], targetPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	copy(packet[28:], payload)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], target[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	checksum := labChecksum(pseudo, packet[20:])
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[26:28], checksum)
	return packet
}

func labDNSQuery(domain string) []byte {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for start := 0; start < len(domain); {
		end := start
		for end < len(domain) && domain[end] != '.' {
			end++
		}
		query = append(query, byte(end-start))
		query = append(query, domain[start:end]...)
		start = end + 1
	}
	return append(query, 0, 0, 1, 0, 1)
}

func labChecksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd byte
	hasOdd := false
	for _, part := range parts {
		for _, value := range part {
			if !hasOdd {
				odd = value
				hasOdd = true
				continue
			}
			sum += uint32(odd)<<8 | uint32(value)
			hasOdd = false
		}
	}
	if hasOdd {
		sum += uint32(odd) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// TestLabPacketDataPlaneLabEgress is the acceptance test for the lab egress
// wiring: with default options the production packet data plane completes a
// DNS A query, a TCP flow through the tunnel to the cover origin, a UDP echo,
// and — critically — a flow to an unreachable target no longer resets the
// carrier.
func TestLabPacketDataPlaneLabEgress(t *testing.T) {
	clientSide, labServer := startPacketLabClient(t, ServerOptions{})
	if !labServer.LabEgress() {
		t.Fatal("default options must wire lab loopback egress")
	}

	// DNS A query through the tunnel is answered with the loopback address.
	query := labDNSQuery("anything.auroralab.test")
	dnsRequest := labUDPv4([4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if err := clientSide.adapter.Ingress(context.Background(), dnsRequest, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	dnsResponse := nextLocalPacket(t, clientSide, 5*time.Second)
	if len(dnsResponse) < 28 || binary.BigEndian.Uint16(dnsResponse[20:22]) != 53 {
		t.Fatalf("DNS response has invalid UDP tuple: %x", dnsResponse)
	}
	dns := dnsResponse[28:]
	if len(dns) < len(query)+16 || !bytes.Equal(dns[:2], query[:2]) || dns[2]&0x80 == 0 || !bytes.Equal(dns[len(dns)-4:], []byte{127, 0, 0, 1}) {
		t.Fatalf("lab DNS answer = %x, want A 127.0.0.1", dns)
	}

	// TCP through the tunnel to the cover origin returns the cover body.
	coverAddr := labServer.CoverAddress()
	_, coverPortText, err := net.SplitHostPort(coverAddr)
	if err != nil {
		t.Fatal(err)
	}
	coverPort, err := strconv.Atoi(coverPortText)
	if err != nil {
		t.Fatal(err)
	}
	labTCPFlow(t, clientSide, [4]byte{127, 0, 0, 1}, uint16(coverPort), "GET / HTTP/1.0\r\n\r\n")

	// UDP echo roundtrip through the tunnel.
	udpPayload := []byte("lab UDP echo")
	udpRequest := labUDPv4([4]byte{10, 0, 0, 2}, [4]byte{192, 0, 2, 9}, 40000, 9999, udpPayload)
	if err := clientSide.adapter.Ingress(context.Background(), udpRequest, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	udpResponse := nextLocalPacket(t, clientSide, 5*time.Second)
	if len(udpResponse) < 28 || !bytes.Equal(udpResponse[28:], udpPayload) {
		t.Fatalf("UDP echo response = %x", udpResponse)
	}

	// The previously fatal flow: an unreachable target now lands on the cover
	// origin and the carrier survives.
	labTCPFlow(t, clientSide, [4]byte{203, 0, 113, 9}, 443, "GET / HTTP/1.0\r\n\r\n")
	select {
	case err := <-clientSide.pumpResult:
		t.Fatalf("carrier died in lab egress mode: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}

// labTCPFlow runs a full fake-TCP exchange through the adapter and requires
// the cover body in the response.
func labTCPFlow(t *testing.T, clientSide *packetLabClient, target [4]byte, targetPort uint16, request string) {
	t.Helper()
	syn := labTCPv4([4]byte{10, 0, 0, 2}, target, 50000+uint16(targetPort%1000), targetPort, 100, 0, 0x02, nil)
	if err := clientSide.adapter.Ingress(context.Background(), syn, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	synAck := nextLocalPacket(t, clientSide, 5*time.Second)
	if len(synAck) < 34 || synAck[33] != 0x12 {
		t.Fatalf("TCP SYN-ACK = %x", synAck)
	}
	labTCPExchange(t, clientSide, target, 50000+uint16(targetPort%1000), targetPort, synAck, request)
}

// labTCPExchange sends one request payload on an established fake-TCP flow and
// accumulates response payloads until the lab cover body arrives.
func labTCPExchange(t *testing.T, clientSide *packetLabClient, target [4]byte, sourcePort, targetPort uint16, synAck []byte, request string) {
	t.Helper()
	ack := binary.BigEndian.Uint32(synAck[24:28]) + 1
	data := labTCPv4([4]byte{10, 0, 0, 2}, target, sourcePort, targetPort, 101, ack, 0x18, []byte(request))
	if err := clientSide.adapter.Ingress(context.Background(), data, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var received []byte
	for time.Now().Before(deadline) && !bytes.Contains(received, []byte("auroralab cover origin")) {
		for _, packet := range drainLocalPackets(clientSide) {
			if len(packet) > 40 {
				received = append(received, packet[40:]...)
			}
		}
		if !bytes.Contains(received, []byte("auroralab cover origin")) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !bytes.Contains(received, []byte("auroralab cover origin")) {
		t.Fatalf("tunneled TCP response did not include the cover body: %q", received)
	}
}
