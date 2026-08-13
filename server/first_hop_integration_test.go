package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroraclient "github.com/aurora-protocol/aurora-core/client"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/evidence"
	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestLiveFirstHopRandomizedApplicationRoundTrip(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	clientDriver := fixture.newClientDriver(t)
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	clientFrames := make(chan []byte, 1)
	connectContext, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelConnect()
	established, err := clientDriver.Connect(connectContext, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	relayApplication := <-harness.relayApplications
	pumpContext, cancelPump := context.WithCancel(context.Background())
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			pumpContext,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(_ context.Context, block protocol.FrameBlock) error {
				clientFrames <- append([]byte(nil), block.Frames[0].Payload...)
				return nil
			},
			1<<20,
		)
	}()
	t.Cleanup(func() {
		cancelPump()
		_ = established.Close()
		select {
		case err := <-pumpResult:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, session.ErrClosed) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("live client packet pump stopped unexpectedly: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("live client packet pump did not stop")
		}
	})

	clientPayload := randomLiveFirstHopBytes(t, 96)
	if err := established.Application.QueueFrames(connectContext, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: clientPayload}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-harness.serverFrames:
		if !bytes.Equal(received, clientPayload) {
			t.Fatal("relay received different application payload")
		}
	case <-connectContext.Done():
		t.Fatal("client application payload did not reach relay")
	}
	serverPayload := randomLiveFirstHopBytes(t, 97)
	if err := relayApplication.QueueFrames(connectContext, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: serverPayload}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-clientFrames:
		if !bytes.Equal(received, serverPayload) {
			t.Fatal("client received different application payload")
		}
	case <-connectContext.Done():
		t.Fatal("relay application payload did not reach client")
	}

	if err := established.Application.InitiateKeyUpdate(connectContext, 1); err != nil {
		t.Fatalf("initiate client key update: %v", err)
	}
	clientUpdatedPayload := randomLiveFirstHopBytes(t, 98)
	if err := queueLiveFirstHopFrame(connectContext, established.Application, clientUpdatedPayload); err != nil {
		t.Fatalf("queue post-update client payload: %v", err)
	}
	select {
	case received := <-harness.serverFrames:
		if !bytes.Equal(received, clientUpdatedPayload) {
			t.Fatal("relay received different post-update application payload")
		}
	case <-connectContext.Done():
		t.Fatal("post-update client application payload did not reach relay")
	}

	if err := relayApplication.InitiateKeyUpdate(connectContext, 2); err != nil {
		t.Fatalf("initiate relay key update: %v", err)
	}
	relayUpdatedPayload := randomLiveFirstHopBytes(t, 99)
	if err := queueLiveFirstHopFrame(connectContext, relayApplication, relayUpdatedPayload); err != nil {
		t.Fatalf("queue post-update relay payload: %v", err)
	}
	select {
	case received := <-clientFrames:
		if !bytes.Equal(received, relayUpdatedPayload) {
			t.Fatal("client received different post-update application payload")
		}
	case <-connectContext.Done():
		t.Fatal("post-update relay application payload did not reach client")
	}
	for name, stats := range map[string]session.Stats{
		"client": established.Application.Stats(),
		"relay":  relayApplication.Stats(),
	} {
		if stats.PeakQueuedPackets == 0 || stats.PeakQueuedPackets > 32 || stats.PeakQueuedBytes == 0 || stats.PeakQueuedBytes > 256<<10 {
			t.Fatalf("%s application queue stats escaped configured bounds: %+v", name, stats)
		}
	}
}

func TestLiveFirstHopEncryptedTCPAndUDPEgress(t *testing.T) {
	tcpPayloads := [][]byte{randomLiveFirstHopBytes(t, 1024), randomLiveFirstHopBytes(t, 1537)}
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })
	tcpResult := make(chan error, 1)
	tcpObserved := make(chan []byte, len(tcpPayloads))
	tcpAccepted := make(chan struct{})
	go func() {
		connection, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			tcpResult <- acceptErr
			return
		}
		close(tcpAccepted)
		for _, payload := range tcpPayloads {
			received := make([]byte, len(payload))
			if _, readErr := io.ReadFull(connection, received); readErr != nil {
				_ = connection.Close()
				tcpResult <- readErr
				return
			}
			if !bytes.Equal(received, payload) {
				_ = connection.Close()
				tcpResult <- errors.New("TCP destination received different payload")
				return
			}
			tcpObserved <- append([]byte(nil), received...)
			if writeErr := writeLiveFirstHopAll(connection, received); writeErr != nil {
				_ = connection.Close()
				tcpResult <- writeErr
				return
			}
		}
		tcpResult <- connection.Close()
	}()

	udpPayload := randomLiveFirstHopBytes(t, 1201)
	udpConnection, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConnection.Close() })
	udpResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		count, peer, readErr := udpConnection.ReadFrom(buffer)
		if readErr != nil {
			udpResult <- readErr
			return
		}
		if !bytes.Equal(buffer[:count], udpPayload) {
			udpResult <- errors.New("UDP destination received different payload")
			return
		}
		written, writeErr := udpConnection.WriteTo(buffer[:count], peer)
		if writeErr == nil && written != count {
			writeErr = io.ErrShortWrite
		}
		udpResult <- writeErr
	}()

	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	sessionFactory, err := NewFirstHopProxySessionFactory(FirstHopProxySessionOptions{
		ExitPolicy: relay.ExitPolicy{AllowPrivate: true},
		Dialer:     &net.Dialer{},
		Resolver:   net.DefaultResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness := startLiveFirstHopHarnessWithSessionFactory(t, fixture, relayDriver, nil, sessionFactory)
	clientDriver := fixture.newClientDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	established, err := clientDriver.Connect(ctx, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	relayApplication := <-harness.relayApplications
	clientFrames := make(chan protocol.AuroraFrame, 16)
	pumpContext, cancelPump := context.WithCancel(context.Background())
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			pumpContext,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(frameContext context.Context, block protocol.FrameBlock) error {
				for _, frame := range block.Frames {
					frame.Payload = append([]byte(nil), frame.Payload...)
					select {
					case clientFrames <- frame:
					case <-frameContext.Done():
						return frameContext.Err()
					}
				}
				return nil
			},
			1<<20,
		)
	}()
	t.Cleanup(func() {
		cancelPump()
		_ = established.Close()
		select {
		case pumpErr := <-pumpResult:
			if pumpErr != nil && !errors.Is(pumpErr, context.Canceled) && !errors.Is(pumpErr, session.ErrClosed) && !errors.Is(pumpErr, net.ErrClosed) && !errors.Is(pumpErr, io.ErrClosedPipe) && !errors.Is(pumpErr, io.EOF) {
				t.Errorf("encrypted egress client pump stopped unexpectedly: %v", pumpErr)
			}
		case <-time.After(time.Second):
			t.Error("encrypted egress client pump did not stop")
		}
	})

	proxy := auroraclient.NewLocalProxy()
	tcpAddress := tcpListener.Addr().(*net.TCPAddr)
	tcpOpen, err := proxy.OpenTCPFrame(1, tcpAddress.IP.String(), uint16(tcpAddress.Port))
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{tcpOpen}})
	select {
	case <-tcpAccepted:
	case <-ctx.Done():
		t.Fatalf("TCP destination accept: %v", ctx.Err())
	}
	tcpData, err := proxy.SendTCP(1, tcpPayloads[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{tcpData}})
	if err := awaitLiveFirstHopPayload(ctx, tcpObserved, tcpPayloads[0]); err != nil {
		t.Fatalf("TCP destination receive: %v", err)
	}
	assertLiveFirstHopFrame(t, ctx, clientFrames, registry.FrameStreamData, 1, tcpPayloads[0])

	if err := established.Application.InitiateKeyUpdate(ctx, 1); err != nil {
		t.Fatalf("initiate encrypted TCP key update: %v", err)
	}
	tcpData, err = proxy.SendTCP(1, tcpPayloads[1], 0)
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{tcpData}})
	if err := awaitLiveFirstHopPayload(ctx, tcpObserved, tcpPayloads[1]); err != nil {
		t.Fatalf("post-update TCP destination receive: %v", err)
	}
	assertLiveFirstHopFrame(t, ctx, clientFrames, registry.FrameStreamData, 1, tcpPayloads[1])
	tcpClose := assertLiveFirstHopFrame(t, ctx, clientFrames, registry.FrameFlowClose, 1, nil)
	closeReader := wire.NewReader(tcpClose.Payload)
	if close := protocol.DecodeFlowClose(closeReader); closeReader.Err() != nil || !closeReader.EOF() || close.CloseCode != protocol.CloseNormal {
		t.Fatalf("TCP target EOF close = %+v, decode_err=%v", close, closeReader.Err())
	}
	if targetErr := <-tcpResult; targetErr != nil {
		t.Fatalf("TCP destination: %v", targetErr)
	}

	udpAddress := udpConnection.LocalAddr().(*net.UDPAddr)
	udpOpen, err := proxy.OpenUDPExplicitFrame(2, udpAddress.IP.String(), uint16(udpAddress.Port), uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{udpOpen}})
	confirm := assertLiveFirstHopFrame(t, ctx, clientFrames, registry.FrameUDPTargetConfirm, 2, nil)
	if err := proxy.ReceiveUDPTargetConfirmFrameAt(confirm, uint64(time.Now().Unix())); err != nil {
		t.Fatalf("receive UDP target confirmation: %v", err)
	}
	if err := relayApplication.InitiateKeyUpdate(ctx, 2); err != nil {
		t.Fatalf("initiate encrypted UDP key update: %v", err)
	}
	udpData, err := proxy.SendUDP(2, udpPayload, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{udpData}})
	assertLiveFirstHopFrame(t, ctx, clientFrames, registry.FrameDatagramData, 2, udpPayload)
	if targetErr := <-udpResult; targetErr != nil {
		t.Fatalf("UDP destination: %v", targetErr)
	}
	udpClose, err := proxy.CloseFrame(2, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{udpClose}})
}

func TestLiveFirstHopTCPProxyRuntimeEgress(t *testing.T) {
	echoListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echoListener.Close() })
	echoResult := make(chan error, 1)
	go func() {
		connection, acceptErr := echoListener.Accept()
		if acceptErr != nil {
			echoResult <- acceptErr
			return
		}
		defer connection.Close()
		payload := make([]byte, len("encrypted proxy payload"))
		if _, readErr := io.ReadFull(connection, payload); readErr != nil {
			echoResult <- readErr
			return
		}
		_, writeErr := connection.Write(payload)
		echoResult <- writeErr
	}()

	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	sessionFactory, err := NewFirstHopProxySessionFactory(FirstHopProxySessionOptions{
		ExitPolicy: relay.ExitPolicy{AllowPrivate: true},
		Dialer:     &net.Dialer{},
		Resolver:   net.DefaultResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness := startLiveFirstHopHarnessWithSessionFactory(t, fixture, relayDriver, nil, sessionFactory)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	established, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := auroraclient.NewTCPProxyRuntime(established.Application, auroraclient.TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.Serve(ctx, proxyListener) }()
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			ctx,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			runtime.HandleFrameBlock,
			1<<20,
		)
	}()
	t.Cleanup(func() {
		_ = runtime.Close()
		_ = established.Close()
		for name, result := range map[string]chan error{"proxy listener": serveResult, "carrier": pumpResult} {
			select {
			case resultErr := <-result:
				if resultErr != nil && !errors.Is(resultErr, context.Canceled) && !errors.Is(resultErr, session.ErrClosed) && !errors.Is(resultErr, net.ErrClosed) && !errors.Is(resultErr, io.ErrClosedPipe) && !errors.Is(resultErr, io.EOF) {
					t.Errorf("%s stopped unexpectedly: %v", name, resultErr)
				}
			case <-time.After(time.Second):
				t.Errorf("%s did not stop", name)
			}
		}
	})

	connection, err := net.DialTimeout("tcp4", proxyListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	target := echoListener.Addr().(*net.TCPAddr)
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.String(), target.String()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if response != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("CONNECT response = %q", response)
	}
	if empty, err := reader.ReadString('\n'); err != nil || empty != "\r\n" {
		t.Fatalf("CONNECT response terminator = %q, %v", empty, err)
	}
	payload := []byte("encrypted proxy payload")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	responsePayload := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, responsePayload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responsePayload, payload) {
		t.Fatalf("proxy response = %q, want %q", responsePayload, payload)
	}
	if err := <-echoResult; err != nil {
		t.Fatal(err)
	}
}

func TestLiveFirstHopPacketTUNRuntimeInterop(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	harness := startLiveFirstHopHarness(t, fixture, fixture.newRelayDriver(t), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	established, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	defer established.Close()
	relayApplication := <-harness.relayApplications
	adapter, err := auroraclient.NewPacketAdapter(established.Application, auroraclient.PacketAdapterOptions{MaxFlows: 1, MaxPacketBytes: 1500})
	if err != nil {
		t.Fatal(err)
	}
	device := newLiveFirstHopPacketTUNDevice()
	runtime, err := auroraclient.NewPacketTUNRuntime(adapter, device, auroraclient.PacketTUNRuntimeOptions{ReadBufferBytes: 1500})
	if err != nil {
		t.Fatal(err)
	}
	tunnelResult := make(chan error, 1)
	go func() { tunnelResult <- runtime.Serve(ctx) }()
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(ctx, established.ReadCarrier, established.WriteCarrier, established.Application, runtime.HandleFrameBlock, 1<<20)
	}()
	t.Cleanup(func() {
		_ = runtime.Close()
		_ = established.Close()
		for name, result := range map[string]chan error{"packet device": tunnelResult, "carrier": pumpResult} {
			select {
			case resultErr := <-result:
				if resultErr != nil && !errors.Is(resultErr, context.Canceled) && !errors.Is(resultErr, session.ErrClosed) && !errors.Is(resultErr, net.ErrClosed) && !errors.Is(resultErr, io.ErrClosedPipe) && !errors.Is(resultErr, io.EOF) {
					t.Errorf("%s stopped unexpectedly: %v", name, resultErr)
				}
			case <-time.After(time.Second):
				t.Errorf("%s did not stop", name)
			}
		}
	})

	device.Inject(liveFirstHopPacketTUNSYN(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100))
	synAck := device.NextWrite(t)
	if len(synAck) < 40 || binary.BigEndian.Uint16(synAck[20:22]) != 443 || binary.BigEndian.Uint16(synAck[22:24]) != 50000 || synAck[33] != 0x12 {
		t.Fatalf("synthetic tunnel SYN-ACK is invalid: %x", synAck)
	}
	var flowOpen protocol.FlowOpen
	select {
	case encoded := <-harness.serverFrames:
		reader := wire.NewReader(encoded)
		flowOpen = protocol.DecodeFlowOpen(reader)
		if reader.Err() != nil || !reader.EOF() {
			t.Fatalf("decode tunnel FLOW_OPEN: %v", reader.Err())
		}
	case <-ctx.Done():
		t.Fatalf("tunnel FLOW_OPEN did not reach relay: %v", ctx.Err())
	}
	if flowOpen.FlowKind != flow.FlowKindTCPStream || flowOpen.LocalBindingMode != flow.LocalBindingTUNPacketFlow || flowOpen.TargetPort != 443 {
		t.Fatalf("relay FLOW_OPEN is not tunnel-bound TCP: %+v", flowOpen)
	}
	frame, err := protocol.NewStreamDataFrame(flowOpen.FlowID, []byte("strict tunnel response"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	response := device.NextWrite(t)
	if payload := liveFirstHopPacketTUNPayload(response); !bytes.Equal(payload, []byte("strict tunnel response")) {
		t.Fatalf("tunnel response payload = %q", payload)
	}
}

type liveFirstHopPacketTUNDevice struct {
	reads     chan []byte
	writes    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newLiveFirstHopPacketTUNDevice() *liveFirstHopPacketTUNDevice {
	return &liveFirstHopPacketTUNDevice{
		reads:  make(chan []byte, 1),
		writes: make(chan []byte, 4),
		closed: make(chan struct{}),
	}
}

func (d *liveFirstHopPacketTUNDevice) Read(packet []byte) (int, error) {
	select {
	case input := <-d.reads:
		if len(input) > len(packet) {
			return 0, io.ErrShortBuffer
		}
		return copy(packet, input), nil
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *liveFirstHopPacketTUNDevice) Write(packet []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	copied := append([]byte(nil), packet...)
	select {
	case d.writes <- copied:
		return len(copied), nil
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *liveFirstHopPacketTUNDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *liveFirstHopPacketTUNDevice) Inject(packet []byte) {
	d.reads <- append([]byte(nil), packet...)
}

func (d *liveFirstHopPacketTUNDevice) NextWrite(t testing.TB) []byte {
	t.Helper()
	select {
	case packet := <-d.writes:
		return packet
	case <-time.After(time.Second):
		t.Fatal("live packet TUN device did not receive a packet")
		return nil
	}
}

func liveFirstHopPacketTUNSYN(t testing.TB, source, target [4]byte, sourcePort, targetPort uint16, sequence uint32) []byte {
	t.Helper()
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], source[:])
	copy(packet[16:20], target[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], targetPort)
	binary.BigEndian.PutUint32(packet[24:28], sequence)
	packet[32] = 0x50
	packet[33] = 0x02
	binary.BigEndian.PutUint16(packet[34:36], 65535)
	binary.BigEndian.PutUint16(packet[10:12], liveFirstHopPacketTUNChecksum(packet[:20]))
	pseudo := make([]byte, 12)
	copy(pseudo[:4], source[:])
	copy(pseudo[4:8], target[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	binary.BigEndian.PutUint16(packet[36:38], liveFirstHopPacketTUNChecksum(pseudo, packet[20:]))
	return packet
}

func liveFirstHopPacketTUNPayload(packet []byte) []byte {
	if len(packet) < 40 || packet[0]>>4 != 4 {
		return nil
	}
	ipHeaderBytes := int(packet[0]&0x0f) * 4
	totalBytes := int(binary.BigEndian.Uint16(packet[2:4]))
	if ipHeaderBytes < 20 || totalBytes < ipHeaderBytes+20 || totalBytes > len(packet) {
		return nil
	}
	return append([]byte(nil), packet[ipHeaderBytes+20:totalBytes]...)
}

func liveFirstHopPacketTUNChecksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd byte
	haveOdd := false
	for _, part := range parts {
		for _, value := range part {
			if !haveOdd {
				odd = value
				haveOdd = true
				continue
			}
			sum += uint32(odd)<<8 | uint32(value)
			haveOdd = false
		}
	}
	if haveOdd {
		sum += uint32(odd) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestLiveFirstHopProvisionedSessionEgress(t *testing.T) {
	now := time.Now().UTC()
	tlsMaterial := newLiveFirstHopTLSMaterial(t)
	certificate, err := x509.ParseCertificate(tlsMaterial.certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	fixture := newLiveFirstHopFixtureWithOriginSPKI(t, now, auroracrypto.PreHash(certificate.RawSubjectPublicKeyInfo))
	harness := startLiveFirstHopHarnessWithSessionFactoryAndTLS(t, fixture, fixture.newRelayDriver(t), nil, nil, tlsMaterial)
	issuer := startLiveFirstHopIssuer(t, fixture)
	provisioning := fixture.nativeProvisioningForHarness(t, harness, issuer.URL)
	encodedProvisioning, err := auroraclient.EncodeNativeProvisioning(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err = auroraclient.ParseNativeProvisioning(encodedProvisioning, now)
	zeroLiveFirstHopBytes(encodedProvisioning)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provisioned, work, err := auroraclient.BeginProvisionedSession(ctx, provisioning, auroraclient.ProvisionedSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer provisioned.Close()
	issuerResponse := liveFirstHopIssueResponse(t, issuer, work)
	work.Zero()
	defer zeroLiveFirstHopBytes(issuerResponse)
	established, err := provisioned.Complete(ctx, issuerResponse)
	if err != nil {
		t.Fatal(err)
	}
	defer established.Close()

	pumpContext, cancelPump := context.WithCancel(ctx)
	defer cancelPump()
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			pumpContext,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(context.Context, protocol.FrameBlock) error { return nil },
			1<<20,
		)
	}()
	payload := randomLiveFirstHopBytes(t, 96)
	if err := established.Application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: payload}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-harness.serverFrames:
		if !bytes.Equal(received, payload) {
			t.Fatalf("relay received provisioned payload %x, want %x", received, payload)
		}
	case <-ctx.Done():
		t.Fatalf("provisioned payload did not reach relay: %v", ctx.Err())
	}
	cancelPump()
	_ = established.Close()
	select {
	case err := <-pumpResult:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, session.ErrClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("provisioned carrier pump did not stop")
	}
}

func TestLiveFirstHopProvisioningWalletRebuildsAfterCarrierLoss(t *testing.T) {
	now := time.Now().UTC()
	tlsMaterial := newLiveFirstHopTLSMaterial(t)
	certificate, err := x509.ParseCertificate(tlsMaterial.certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	fixture := newLiveFirstHopFixtureWithOriginSPKI(t, now, auroracrypto.PreHash(certificate.RawSubjectPublicKeyInfo))
	secondCredential := cloneLiveFirstHopHintCredential(fixture.accessHint)
	secondCredential.HintSelector = randomLiveFirstHopBytes(t, 16)
	secondCredential.HintSecret = randomLiveFirstHopBytes(t, 32)
	if bytes.Equal(secondCredential.HintSelector, fixture.accessHint.HintSelector) {
		secondCredential.HintSelector[0] ^= 0xff
	}
	secondFixture := fixture
	secondFixture.accessHint = secondCredential
	relayDriver := fixture.newRelayDriver(t, liveFirstHopRelayOptions{
		hintResolver: liveFirstHopMultiHintResolver{credentials: []admission.AccessHintCredential{fixture.accessHint, secondCredential}},
	})
	harness := startLiveFirstHopHarnessWithSessionFactoryAndTLS(t, fixture, relayDriver, nil, nil, tlsMaterial)
	issuer := startLiveFirstHopIssuer(t, fixture)
	firstProvisioning := fixture.nativeProvisioningForHarness(t, harness, issuer.URL)
	secondProvisioning := secondFixture.nativeProvisioningForHarness(t, harness, issuer.URL)
	walletEncoded, err := auroraclient.EncodeNativeProvisioningWallet([]auroraclient.NativeProvisioning{firstProvisioning, secondProvisioning})
	zeroLiveFirstHopNativeProvisioning(&firstProvisioning)
	zeroLiveFirstHopNativeProvisioning(&secondProvisioning)
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := auroraclient.ParseNativeProvisioningWallet(walletEncoded, now)
	zeroLiveFirstHopBytes(walletEncoded)
	if err != nil {
		t.Fatal(err)
	}
	defer wallet.Zero()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	firstReservation, err := wallet.Reserve(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer firstReservation.Zero()
	firstProvisioned, firstEstablished := completeLiveFirstHopProvisionedSession(t, ctx, issuer, firstReservation.Provisioning)
	defer firstProvisioned.Close()
	defer firstEstablished.Close()
	firstRelayApplication := <-harness.relayApplications
	if err := firstEstablished.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstRelayApplication.Done():
	case <-time.After(time.Second):
		t.Fatal("first relay application did not stop after carrier loss")
	}

	secondReservation, err := wallet.Reserve(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	defer secondReservation.Zero()
	if bytes.Equal(firstReservation.SpentHintKey, secondReservation.SpentHintKey) {
		t.Fatal("recovery reused the first access hint")
	}
	secondProvisioned, secondEstablished := completeLiveFirstHopProvisionedSession(t, ctx, issuer, secondReservation.Provisioning)
	defer secondProvisioned.Close()
	defer secondEstablished.Close()
	secondRelayApplication := <-harness.relayApplications
	if firstEstablished.Application == secondEstablished.Application || firstRelayApplication == secondRelayApplication {
		t.Fatal("recovery reused authenticated application state")
	}

	pumpContext, cancelPump := context.WithCancel(ctx)
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			pumpContext,
			secondEstablished.ReadCarrier,
			secondEstablished.WriteCarrier,
			secondEstablished.Application,
			func(context.Context, protocol.FrameBlock) error { return nil },
			1<<20,
		)
	}()
	payload := randomLiveFirstHopBytes(t, 111)
	if err := secondEstablished.Application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: payload}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-harness.serverFrames:
		if !bytes.Equal(received, payload) {
			t.Fatalf("recovered relay payload = %x, want %x", received, payload)
		}
	case <-ctx.Done():
		t.Fatalf("recovered client payload did not reach relay: %v", ctx.Err())
	}
	cancelPump()
	if err := secondEstablished.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case pumpErr := <-pumpResult:
		if pumpErr != nil && !errors.Is(pumpErr, context.Canceled) && !errors.Is(pumpErr, session.ErrClosed) && !errors.Is(pumpErr, net.ErrClosed) && !errors.Is(pumpErr, io.ErrClosedPipe) && !errors.Is(pumpErr, io.EOF) {
			t.Fatal(pumpErr)
		}
	case <-time.After(time.Second):
		t.Fatal("recovered carrier pump did not stop")
	}
}

func completeLiveFirstHopProvisionedSession(t testing.TB, ctx context.Context, issuer *httptest.Server, provisioning auroraclient.NativeProvisioning) (*auroraclient.ProvisionedSession, *handshake.EstablishedSession) {
	t.Helper()
	provisioned, work, err := auroraclient.BeginProvisionedSession(ctx, provisioning, auroraclient.ProvisionedSessionOptions{})
	zeroLiveFirstHopNativeProvisioning(&provisioning)
	if err != nil {
		t.Fatal(err)
	}
	issuerResponse := liveFirstHopIssueResponse(t, issuer, work)
	work.Zero()
	defer zeroLiveFirstHopBytes(issuerResponse)
	established, err := provisioned.Complete(ctx, issuerResponse)
	if err != nil {
		_ = provisioned.Close()
		t.Fatal(err)
	}
	return provisioned, established
}

func TestLiveFirstHopEgressPolicyDenialPreventsDial(t *testing.T) {
	dialer := &rejectingLiveFirstHopDialer{}
	sessionFactory, err := NewFirstHopProxySessionFactory(FirstHopProxySessionOptions{
		Dialer:   dialer,
		Resolver: net.DefaultResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := newLiveFirstHopFixture(t, time.Now())
	harness := startLiveFirstHopHarnessWithSessionFactory(t, fixture, fixture.newRelayDriver(t), nil, sessionFactory)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	established, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	defer established.Close()
	select {
	case <-harness.relayApplications:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			ctx,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(context.Context, protocol.FrameBlock) error { return nil },
			1<<20,
		)
	}()
	proxy := auroraclient.NewLocalProxy()
	open, err := proxy.OpenTCPFrame(1, "127.0.0.1", 9)
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{open}})
	select {
	case pumpErr := <-pumpResult:
		if pumpErr == nil {
			t.Fatal("policy-denied carrier stopped without an error")
		}
	case <-ctx.Done():
		t.Fatalf("policy-denied carrier remained open: %v", ctx.Err())
	}
	if calls := dialer.calls.Load(); calls != 0 {
		t.Fatalf("policy denial invoked dialer %d times", calls)
	}
}

func TestLiveFirstHopShutdownCancelsBlockedEgressDial(t *testing.T) {
	dialer := newBlockingLiveFirstHopDialer()
	sessionFactory, err := NewFirstHopProxySessionFactory(FirstHopProxySessionOptions{
		ExitPolicy: relay.ExitPolicy{AllowPrivate: true},
		Dialer:     dialer,
		Resolver:   net.DefaultResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := newLiveFirstHopFixture(t, time.Now())
	harness := startLiveFirstHopHarnessWithSessionFactory(t, fixture, fixture.newRelayDriver(t), nil, sessionFactory)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	established, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	defer established.Close()
	select {
	case <-harness.relayApplications:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			ctx,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(context.Context, protocol.FrameBlock) error { return nil },
			1<<20,
		)
	}()
	proxy := auroraclient.NewLocalProxy()
	open, err := proxy.OpenTCPFrame(1, "127.0.0.1", 9)
	if err != nil {
		t.Fatal(err)
	}
	queueLiveFirstHopBlock(t, ctx, established.Application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{open}})
	select {
	case <-dialer.started:
	case <-ctx.Done():
		t.Fatalf("blocked dial did not start: %v", ctx.Err())
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := harness.shutdown(shutdownContext); err != nil {
		t.Fatalf("shutdown with blocked egress dial: %v", err)
	}
	select {
	case <-dialer.done:
	case <-time.After(time.Second):
		t.Fatal("blocked egress dial was not canceled")
	}
	select {
	case pumpErr := <-pumpResult:
		if pumpErr == nil {
			t.Fatal("shutdown carrier stopped without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("client pump remained live after shutdown")
	}
}

func TestLiveFirstHopEvidenceReport(t *testing.T) {
	result, err := evidence.RunFirstHop(context.Background(), liveFirstHopEvidenceHarness{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || !result.TLS13 || !result.HTTP2 || !result.FreshConnection || !result.PreludeAuthenticated || !result.AdmissionSpent || !result.ReplayRejected || !result.ApplicationRoundTrip || !result.KeyUpdateRoundTrip || len(result.Findings) != 0 {
		t.Fatalf("incomplete live first-hop evidence: %+v", result)
	}
	if result.HandshakeDuration <= 0 || result.PeakQueuedPackets <= 0 || result.PeakQueuedPackets > 64 || result.PeakQueuedBytes <= 0 || result.PeakQueuedBytes > 512<<10 {
		t.Fatalf("invalid live first-hop evidence metrics: %+v", result)
	}
}

type liveFirstHopEvidenceHarness struct {
	t *testing.T
}

func (h liveFirstHopEvidenceHarness) RunFirstHop(ctx context.Context) (evidence.FirstHopObservation, error) {
	if h.t == nil {
		return evidence.FirstHopObservation{}, errors.New("live first-hop evidence test is missing testing state")
	}
	fixture := newLiveFirstHopFixture(h.t, time.Now())
	relayDriver := fixture.newRelayDriver(h.t)
	coverOrigin := &recordingFirstHopCoverOrigin{}
	harness := startLiveFirstHopHarness(h.t, fixture, relayDriver, coverOrigin)
	clientDriver := fixture.newClientDriver(h.t)
	observation := evidence.FirstHopObservation{}
	handshakeStarted := time.Now()
	established, err := clientDriver.Connect(ctx, harness.opener)
	observation.HandshakeDuration = time.Since(handshakeStarted)
	if err != nil {
		return observation, err
	}
	observation.TLS13 = true
	observation.HTTP2 = true
	observation.FreshConnection = true
	observation.PreludeAuthenticated = true

	var relayApplication *session.Application
	select {
	case relayApplication = <-harness.relayApplications:
		observation.AdmissionSpent = true
	case <-ctx.Done():
		_ = established.Close()
		return observation, ctx.Err()
	}
	clientFrames := make(chan []byte, 4)
	pumpContext, cancelPump := context.WithCancel(ctx)
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			pumpContext,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(_ context.Context, block protocol.FrameBlock) error {
				clientFrames <- append([]byte(nil), block.Frames[0].Payload...)
				return nil
			},
			1<<20,
		)
	}()
	pumpStopped := false
	stopPump := func() error {
		if pumpStopped {
			return nil
		}
		pumpStopped = true
		cancelPump()
		_ = established.Close()
		_ = relayApplication.Close()
		select {
		case pumpErr := <-pumpResult:
			if pumpErr != nil && !errors.Is(pumpErr, context.Canceled) && !errors.Is(pumpErr, session.ErrClosed) && !errors.Is(pumpErr, net.ErrClosed) {
				return pumpErr
			}
			return nil
		case <-time.After(time.Second):
			return errors.New("live first-hop evidence packet pump did not stop")
		}
	}
	defer func() { _ = stopPump() }()

	clientPayload := randomLiveFirstHopBytes(h.t, 128)
	if err := queueLiveFirstHopFrame(ctx, established.Application, clientPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, harness.serverFrames, clientPayload); err != nil {
		return observation, err
	}
	relayPayload := randomLiveFirstHopBytes(h.t, 129)
	if err := queueLiveFirstHopFrame(ctx, relayApplication, relayPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, clientFrames, relayPayload); err != nil {
		return observation, err
	}
	observation.ApplicationRoundTrip = true

	if err := established.Application.InitiateKeyUpdate(ctx, 1); err != nil {
		return observation, err
	}
	clientUpdatedPayload := randomLiveFirstHopBytes(h.t, 130)
	if err := queueLiveFirstHopFrame(ctx, established.Application, clientUpdatedPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, harness.serverFrames, clientUpdatedPayload); err != nil {
		return observation, err
	}
	if err := relayApplication.InitiateKeyUpdate(ctx, 2); err != nil {
		return observation, err
	}
	relayUpdatedPayload := randomLiveFirstHopBytes(h.t, 131)
	if err := queueLiveFirstHopFrame(ctx, relayApplication, relayUpdatedPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, clientFrames, relayUpdatedPayload); err != nil {
		return observation, err
	}
	observation.KeyUpdateRoundTrip = true
	clientStats := established.Application.Stats()
	relayStats := relayApplication.Stats()
	observation.PeakQueuedPackets = clientStats.PeakQueuedPackets + relayStats.PeakQueuedPackets
	observation.PeakQueuedBytes = clientStats.PeakQueuedBytes + relayStats.PeakQueuedBytes
	if err := stopPump(); err != nil {
		return observation, err
	}

	replayed, replayErr := fixture.newClientDriver(h.t).Connect(ctx, harness.opener)
	if replayed != nil {
		_ = replayed.Close()
		return observation, errors.New("live first-hop evidence replay created a client session")
	}
	if replayErr == nil {
		return observation, errors.New("live first-hop evidence replay was accepted")
	}
	method, body := coverOrigin.snapshot()
	if method != http.MethodGet || len(body) != 0 {
		return observation, errors.New("live first-hop evidence replay did not use sanitized cover")
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		return observation, errors.New("live first-hop evidence replay created a relay session")
	default:
	}
	observation.ReplayRejected = true
	return observation, nil
}

func awaitLiveFirstHopPayload(ctx context.Context, received <-chan []byte, expected []byte) error {
	select {
	case payload := <-received:
		if !bytes.Equal(payload, expected) {
			return errors.New("live first-hop evidence payload mismatch")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func queueLiveFirstHopFrame(ctx context.Context, application *session.Application, payload []byte) error {
	return queueLiveFirstHopFrameBlock(ctx, application, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: payload}}})
}

func queueLiveFirstHopFrameBlock(ctx context.Context, application *session.Application, block protocol.FrameBlock) error {
	for {
		err := application.QueueFrames(ctx, block)
		if err == nil || !errors.Is(err, session.ErrBackpressure) {
			return err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func queueLiveFirstHopBlock(t testing.TB, ctx context.Context, application *session.Application, block protocol.FrameBlock) {
	t.Helper()
	if err := queueLiveFirstHopFrameBlock(ctx, application, block); err != nil {
		t.Fatal(err)
	}
}

func assertLiveFirstHopFrame(t testing.TB, ctx context.Context, frames <-chan protocol.AuroraFrame, frameType, flowID uint64, payload []byte) protocol.AuroraFrame {
	t.Helper()
	select {
	case frame, ok := <-frames:
		if !ok {
			t.Fatal("live first-hop frame stream closed")
		}
		if frame.FrameType != frameType || frame.FlowID != flowID || (payload != nil && !bytes.Equal(frame.Payload, payload)) {
			t.Fatalf("unexpected live first-hop frame: type=0x%x flow=%d payload_bytes=%d", frame.FrameType, frame.FlowID, len(frame.Payload))
		}
		return frame
	case <-ctx.Done():
		t.Fatalf("wait for live first-hop frame type=0x%x flow=%d: %v", frameType, flowID, ctx.Err())
		return protocol.AuroraFrame{}
	}
}

func writeLiveFirstHopAll(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

type liveFirstHopManualClient struct {
	carrier               handshake.BootstrapCarrier
	state                 *handshake.ClientSession
	control               handshake.ControlCapsuleContext
	secrets               handshake.HandshakeSecrets
	preludeTranscriptHash []byte
	admissionContextHash  []byte
	capsule1              protocol.CoverCapsule1Plain
}

func startLiveFirstHopManualClient(t testing.TB, fixture liveFirstHopFixture, harness liveFirstHopHarness) *liveFirstHopManualClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	state := handshake.NewClientSession()
	if err := state.MarkDescriptorLoaded(); err != nil {
		t.Fatal(err)
	}
	coverRandom := randomLiveFirstHopBytes(t, 32)
	carrier, err := harness.opener.Open(ctx, coverRandom)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = carrier.Close() })
	binding := carrier.Binding()
	if err := state.MarkCoverOpened(); err != nil {
		t.Fatal(err)
	}
	clientNonce := randomLiveFirstHopBytes(t, 32)
	clientECDH, err := auroracrypto.GenerateECDHForSuite(fixture.deployment.Suite())
	if err != nil {
		t.Fatal(err)
	}
	defer clientECDH.Destroy()
	clientMLKEM, err := auroracrypto.GenerateMLKEMForSuite(fixture.deployment.Suite())
	if err != nil {
		t.Fatal(err)
	}
	defer clientMLKEM.Destroy()
	accessHint, err := admission.ComputeAccessHint(fixture.accessHint, binding.HandshakeBindingContext, clientNonce)
	if err != nil {
		t.Fatal(err)
	}
	template := fixture.deployment.Template()
	requestClass := fixture.deployment.RequestClass()
	prelude0 := protocol.CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{fixture.deployment.Suite()},
		ClientNonce:                 clientNonce,
		ClientClassicalEphPub:       clientECDH.PublicKeyBytes(),
		ClientMLKEMEncapsulationKey: clientMLKEM.EncapsulationKeyBytes(),
		RelayDescriptorHash:         fixture.deployment.DescriptorHash(),
		CoverTemplateHash:           fixture.deployment.TemplateHash(),
		RequestClassID:              requestClass.ClassID,
		HintIssuerID:                append([]byte(nil), fixture.accessHint.HintIssuerID...),
		RelayBucketID:               append([]byte(nil), fixture.accessHint.RelayBucketID...),
		HintEpochID:                 fixture.accessHint.HintEpochID,
		HintSelector:                append([]byte(nil), fixture.accessHint.HintSelector...),
		AccessHint:                  accessHint,
		ClientCoverRandom:           coverRandom,
	}
	prelude0Record := padLiveFirstHopPrelude0(t, &prelude0, template.PreludeEnvelope.MinRequestBodySize, template.PreludeEnvelope.MaxRequestBodySize)
	if err := carrier.WriteRecord(prelude0Record); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkCoverPrelude0Sent(); err != nil {
		t.Fatal(err)
	}
	prelude1Record, err := carrier.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	if size := uint64(len(prelude1Record)); size < template.PreludeEnvelope.MinResponseBodySize || size > template.PreludeEnvelope.MaxResponseBodySize {
		t.Fatalf("live Prelude1 size %d outside envelope", size)
	}
	reader := wire.NewReader(prelude1Record)
	prelude1 := protocol.DecodeCoverPrelude1(reader)
	if reader.Err() != nil || !reader.EOF() {
		t.Fatalf("decode live Prelude1: %v", reader.Err())
	}
	preludeTranscriptHash, err := state.VerifyCoverPrelude1(handshake.CoverPreludeVerificationInput{
		Suite:              fixture.deployment.Suite(),
		CoverStreamBinding: binding.CoverStreamBinding,
		Prelude0:           prelude0,
		Prelude1:           prelude1,
		Descriptor:         fixture.deployment.Descriptor(),
		RequirePQ:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sharedClassical, err := clientECDH.SharedSecret(prelude1.ServerClassicalEphPub)
	if err != nil {
		t.Fatal(err)
	}
	sharedPQ, err := clientMLKEM.Decapsulate(prelude1.ServerMLKEMCiphertextToClient)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := handshake.DeriveHandshakeSecrets(fixture.deployment.Suite(), sharedPQ, sharedClassical, binding.HandshakeBindingContext, preludeTranscriptHash)
	zeroFirstHopBytes(sharedPQ)
	zeroFirstHopBytes(sharedClassical)
	if err != nil {
		t.Fatal(err)
	}
	routeInstanceID, err := auroracrypto.FirstHopRouteInstanceID(fixture.deployment.Suite(), preludeTranscriptHash, fixture.deployment.DescriptorHash(), binding.HandshakeBindingContext, clientNonce)
	if err != nil {
		t.Fatal(err)
	}
	policyOffer := liveFirstHopPolicyOffer(fixture.deployment)
	transportHints := liveFirstHopTransportHints(t)
	admissionContextHash, err := admission.AdmissionContextHash(admission.ContextInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   fixture.deployment.Suite(),
		RelayDescriptorHash:             fixture.deployment.DescriptorHash(),
		CoverTemplateHash:               fixture.deployment.TemplateHash(),
		RouteInstanceID:                 routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         binding.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: preludeTranscriptHash,
		PolicyOffer:                     policyOffer,
		ClientTransportHints:            transportHints,
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fixture.deployment.Descriptor()
	proofProvider := &liveFirstHopProofProvider{
		issuerID:      fixture.accessHint.HintIssuerID,
		relayBucketID: fixture.accessHint.RelayBucketID,
		privateKey:    fixture.tokenPrivate,
		publicKeyDER:  fixture.tokenPublicDER,
	}
	proof, replayProof, err := proofProvider.BuildProofs(ctx, handshake.ClientProofRequest{
		AdmissionContextHash:    admissionContextHash,
		HandshakeBindingContext: binding.HandshakeBindingContext,
		RouteInstanceID:         routeInstanceID,
		HopIndex:                0,
		ReplayEpochID:           descriptor.ReplayEpochID,
		ReplayEpochValidUntil:   descriptor.ReplayEpochValidUntilUnix,
		ReplayWindowID:          descriptor.ReplayWindowID,
	})
	if err != nil {
		t.Fatal(err)
	}
	capsule1, err := state.BuildCoverCapsule1(protocol.CoverCapsule1Plain{
		MsgType:              registry.MsgCoverCapsule1,
		RouteInstanceID:      routeInstanceID,
		AdmissionProof:       proof,
		ReplayProof:          replayProof,
		PolicyOffer:          policyOffer,
		ClientTransportHints: transportHints,
		ClientFinished:       make([]byte, 48),
	})
	if err != nil {
		t.Fatal(err)
	}
	control := handshake.ControlCapsuleContext{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   fixture.deployment.Suite(),
		RouteInstanceID:                 routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         binding.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: preludeTranscriptHash,
		ClientHSKey:                     secrets.ClientHSKey,
		ClientHSIV:                      secrets.ClientHSIV,
		ServerHSKey:                     secrets.ServerHSKey,
		ServerHSIV:                      secrets.ServerHSIV,
	}
	sealed, err := handshake.SealCoverCapsule1(control, capsule1)
	if err != nil {
		t.Fatal(err)
	}
	if size := uint64(len(sealed)); size < template.CapsuleEnvelope.MinCapsuleBodySize {
		capsule1.Padding = randomLiveFirstHopBytes(t, int(template.CapsuleEnvelope.MinCapsuleBodySize-size))
	}
	capsule1.ClientFinished = nil
	capsule1.ClientFinished, err = handshake.ComputeClientFinished(fixture.deployment.Suite(), secrets.ClientFinishedKey, preludeTranscriptHash, capsule1)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = handshake.SealCoverCapsule1(control, capsule1)
	if err != nil {
		t.Fatal(err)
	}
	if size := uint64(len(sealed)); size < template.CapsuleEnvelope.MinCapsuleBodySize || size > template.CapsuleEnvelope.MaxCapsuleBodySize {
		t.Fatalf("live Capsule1 size %d outside envelope", size)
	}
	return &liveFirstHopManualClient{
		carrier:               carrier,
		state:                 state,
		control:               control,
		secrets:               secrets,
		preludeTranscriptHash: preludeTranscriptHash,
		admissionContextHash:  admissionContextHash,
		capsule1:              capsule1,
	}
}

func (c *liveFirstHopManualClient) close() {
	if c == nil {
		return
	}
	if c.carrier != nil {
		_ = c.carrier.Close()
	}
	for _, secret := range [][]byte{
		c.secrets.EarlySecret,
		c.secrets.DerivedSecret,
		c.secrets.HandshakeSecret,
		c.secrets.ClientHandshakeSecret,
		c.secrets.ServerHandshakeSecret,
		c.secrets.ClientFinishedKey,
		c.secrets.ServerFinishedKey,
		c.secrets.ClientHSKey,
		c.secrets.ClientHSIV,
		c.secrets.ServerHSKey,
		c.secrets.ServerHSIV,
		c.preludeTranscriptHash,
		c.admissionContextHash,
	} {
		zeroFirstHopBytes(secret)
	}
}

func padLiveFirstHopPrelude0(t testing.TB, prelude *protocol.CoverPrelude0, minimum, maximum uint64) []byte {
	t.Helper()
	encoded, err := protocol.Encode(*prelude)
	if err != nil {
		t.Fatal(err)
	}
	if size := uint64(len(encoded)); size < minimum {
		prelude.Padding = randomLiveFirstHopBytes(t, int(minimum-size))
		encoded, err = protocol.Encode(*prelude)
		if err != nil {
			t.Fatal(err)
		}
	}
	if size := uint64(len(encoded)); size < minimum || size > maximum {
		t.Fatalf("live Prelude0 size %d outside envelope", size)
	}
	return encoded
}

func TestLiveFirstHopRelayFailureBoundaries(t *testing.T) {
	tests := []struct {
		name                string
		mutateRecord        func(int, []byte) ([]byte, error)
		mutateProofProvider func(*liveFirstHopProofProvider)
		relayOptions        func() liveFirstHopRelayOptions
		preHeaderCover      bool
	}{
		{
			name: "wrong request class",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.RequestClassID++
			}),
			preHeaderCover: true,
		},
		{
			name: "wrong live binding",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.ClientCoverRandom[0] ^= 0xff
			}),
			preHeaderCover: true,
		},
		{
			name: "malformed hybrid share",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.ClientClassicalEphPub[0] = 0x05
			}),
			preHeaderCover: true,
		},
		{
			name: "bad access hint",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.AccessHint[0] ^= 0xff
			}),
			preHeaderCover: true,
		},
		{
			name: "duplicate access hint",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{hintCache: &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache(), duplicate: true}}
			},
			preHeaderCover: true,
		},
		{
			name: "access hint store error",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{hintCache: &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache(), err: errors.New("store unavailable")}}
			},
			preHeaderCover: true,
		},
		{
			name: "malformed Capsule1",
			mutateRecord: func(index int, record []byte) ([]byte, error) {
				if index == 1 {
					record[0] ^= 0xff
				}
				return record, nil
			},
		},
		{
			name: "admission verifier error",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{admissionVerifier: liveFirstHopAdmissionVerifier{err: errors.New("verification unavailable")}}
			},
		},
		{
			name: "invalid admission authenticator",
			mutateProofProvider: func(provider *liveFirstHopProofProvider) {
				provider.tamperAuthenticator = true
			},
		},
		{
			name: "replayed token",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{tokenCache: &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache(), duplicate: true}}
			},
		},
		{
			name: "policy failure",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{policySelector: liveFirstHopPolicySelector{err: errors.New("policy unavailable")}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLiveFirstHopFixture(t, time.Now())
			options := liveFirstHopRelayOptions{}
			if test.relayOptions != nil {
				options = test.relayOptions()
			}
			relayDriver := fixture.newRelayDriver(t, options)
			clientDriver, proofProvider := fixture.newClientDriverWithProofProvider(t)
			if test.mutateProofProvider != nil {
				test.mutateProofProvider(proofProvider)
			}
			coverOrigin := &recordingFirstHopCoverOrigin{}
			harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
			opener := harness.opener
			if test.mutateRecord != nil {
				opener = &liveFirstHopMutatingOpener{base: opener, mutate: test.mutateRecord}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			established, err := clientDriver.Connect(ctx, opener)
			if err == nil || established != nil {
				if established != nil {
					_ = established.Close()
				}
				t.Fatal("live first-hop failure established an application session")
			}
			select {
			case application := <-harness.relayApplications:
				_ = application.Close()
				t.Fatal("relay created an application on failed live handshake")
			default:
			}
			method, body := coverOrigin.snapshot()
			if test.preHeaderCover {
				if method != http.MethodGet || len(body) != 0 {
					t.Fatalf("pre-header failure was not sanitized cover: method=%s body=%x", method, body)
				}
			} else if method != "" || len(body) != 0 {
				t.Fatalf("post-header failure invoked cover origin: method=%s body=%x", method, body)
			}
		})
	}
}

func TestLiveFirstHopRejectsMismatchedClientBindingMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*handshake.HTTP2BindingMetadata)
	}{
		{
			name: "authority hash",
			mutate: func(metadata *handshake.HTTP2BindingMetadata) {
				metadata.NormalizedAuthorityHash[0] ^= 0xff
			},
		},
		{
			name: "path template ID",
			mutate: func(metadata *handshake.HTTP2BindingMetadata) {
				metadata.PathTemplateID[0] ^= 0xff
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLiveFirstHopFixture(t, time.Now())
			relayDriver := fixture.newRelayDriver(t)
			coverOrigin := &recordingFirstHopCoverOrigin{}
			harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
			opener := &liveFirstHopBindingMetadataOpener{base: harness.opener, metadata: harness.bindingMetadata, mutate: test.mutate}
			clientDriver := fixture.newClientDriver(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if established, err := clientDriver.Connect(ctx, opener); err == nil || established != nil {
				if established != nil {
					_ = established.Close()
				}
				t.Fatal("mismatched live binding metadata established a session")
			}
			method, body := coverOrigin.snapshot()
			if (method != "" && method != http.MethodGet) || len(body) != 0 {
				t.Fatalf("locally rejected binding mismatch reached unsanitized cover: method=%s body=%x", method, body)
			}
			select {
			case application := <-harness.relayApplications:
				_ = application.Close()
				t.Fatal("binding mismatch created a relay application")
			default:
			}
		})
	}
}

func TestLiveFirstHopRejectsBadPreludeSignatureBeforeProofs(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	clientDriver, proofProvider := fixture.newClientDriverWithProofProvider(t)
	opener := &liveFirstHopReadMutatingOpener{base: harness.opener, mutate: mutateLiveFirstHopPrelude1Signature}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if established, err := clientDriver.Connect(ctx, opener); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("bad Prelude1 signature established a session")
	}
	if calls := proofProvider.calls.Load(); calls != 0 {
		t.Fatalf("proof provider called %d times before Prelude1 authentication", calls)
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		t.Fatal("bad Prelude1 signature created a relay application")
	default:
	}
}

func TestLiveFirstHopRejectsCorruptedCapsule2(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	clientDriver, proofProvider := fixture.newClientDriverWithProofProvider(t)
	opener := &liveFirstHopReadMutatingOpener{
		base: harness.opener,
		mutate: func(index int, record []byte) ([]byte, error) {
			if index == 1 {
				record[len(record)-1] ^= 0xff
			}
			return record, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if established, err := clientDriver.Connect(ctx, opener); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("corrupted Capsule2 established a client session")
	}
	if calls := proofProvider.calls.Load(); calls != 1 {
		t.Fatalf("proof provider calls = %d, want 1", calls)
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
	case <-ctx.Done():
		t.Fatal("relay did not reach committed admission before Capsule2 corruption")
	}
}

func TestLiveFirstHopRejectsWrongClientFinished(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	coverOrigin := &recordingFirstHopCoverOrigin{}
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
	manual := startLiveFirstHopManualClient(t, fixture, harness)
	defer manual.close()
	manual.capsule1.ClientFinished[0] ^= 0xff
	sealed, err := handshake.SealCoverCapsule1(manual.control, manual.capsule1)
	if err != nil {
		t.Fatal(err)
	}
	if err := manual.carrier.WriteRecord(sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := manual.carrier.ReadRecord(); err == nil {
		t.Fatal("wrong ClientFinished produced Capsule2")
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		t.Fatal("wrong ClientFinished created a relay application")
	default:
	}
	method, body := coverOrigin.snapshot()
	if method != "" || len(body) != 0 {
		t.Fatalf("post-header ClientFinished failure invoked cover origin: method=%s body=%x", method, body)
	}
}

func TestLiveFirstHopRejectsWrongServerFinished(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	manual := startLiveFirstHopManualClient(t, fixture, harness)
	defer manual.close()
	sealedCapsule1, err := handshake.SealCoverCapsule1(manual.control, manual.capsule1)
	if err != nil {
		t.Fatal(err)
	}
	if err := manual.carrier.WriteRecord(sealedCapsule1); err != nil {
		t.Fatal(err)
	}
	sealedCapsule2, err := manual.carrier.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	capsule2, err := handshake.OpenCoverCapsule2(manual.control, sealedCapsule2)
	if err != nil {
		t.Fatal(err)
	}
	expected, _, _, err := handshake.ComputeServerFinished(
		fixture.deployment.Suite(),
		manual.secrets.ServerFinishedKey,
		manual.preludeTranscriptHash,
		manual.capsule1,
		capsule2.PolicyAccept,
	)
	if err != nil {
		t.Fatal(err)
	}
	capsule2.ServerFinished[0] ^= 0xff
	tampered, err := handshake.SealCoverCapsule2(manual.control, capsule2)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedTamper, err := handshake.OpenCoverCapsule2(manual.control, tampered)
	if err != nil {
		t.Fatalf("AEAD-valid wrong ServerFinished did not reopen: %v", err)
	}
	if err := manual.state.VerifyCoverCapsule2(authenticatedTamper, expected); err == nil {
		t.Fatal("wrong ServerFinished was accepted")
	}
	if manual.state.State() == handshake.StateApplicationReady {
		t.Fatal("wrong ServerFinished advanced the client to application state")
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
	case <-time.After(time.Second):
		t.Fatal("relay did not commit the source Capsule2")
	}
}

func TestLiveFirstHopRejectsSpentAccessHintOnFreshConnection(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	coverOrigin := &recordingFirstHopCoverOrigin{}
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	firstApplication := <-harness.relayApplications
	_ = firstApplication.Close()

	second, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err == nil || second != nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("spent access hint established a second session")
	}
	method, body := coverOrigin.snapshot()
	if method != http.MethodGet || len(body) != 0 {
		t.Fatalf("spent access hint was not sanitized cover: method=%s body=%x", method, body)
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		t.Fatal("spent access hint created a second relay application")
	default:
	}
}

func TestLiveFirstHopRejectsSpentAdmissionWithFreshReplayProof(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	tokenCache := &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	relayDriver := fixture.newRelayDriver(t, liveFirstHopRelayOptions{tokenCache: tokenCache})
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	manual := startLiveFirstHopManualClient(t, fixture, harness)
	defer manual.close()

	redemptionHash, err := admission.TokenRedemptionHash(manual.capsule1.AdmissionProof)
	if err != nil {
		t.Fatal(err)
	}
	spentKey, err := admission.TokenSpentKey(redemptionHash)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := tokenCache.InsertIfAbsent(spentKey)
	if err != nil || !inserted {
		t.Fatalf("pre-spend admission token: inserted=%t err=%v", inserted, err)
	}
	manual.capsule1.ReplayProof.ClientReplayNonce = randomLiveFirstHopBytes(t, 32)
	manual.capsule1.ReplayProof.ReplayContextHash, err = admission.ReplayContextHash(
		redemptionHash,
		manual.capsule1.ReplayProof,
		manual.control.RouteInstanceID,
		manual.control.HopIndex,
		manual.control.HandshakeBindingContext,
		manual.admissionContextHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	manual.capsule1.ClientFinished = nil
	manual.capsule1.ClientFinished, err = handshake.ComputeClientFinished(
		fixture.deployment.Suite(),
		manual.secrets.ClientFinishedKey,
		manual.preludeTranscriptHash,
		manual.capsule1,
	)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := handshake.SealCoverCapsule1(manual.control, manual.capsule1)
	if err != nil {
		t.Fatal(err)
	}
	if err := manual.carrier.WriteRecord(sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := manual.carrier.ReadRecord(); err == nil {
		t.Fatal("spent admission token with fresh replay proof produced Capsule2")
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		t.Fatal("spent admission token with fresh replay proof created an application")
	default:
	}
}

func TestLiveFirstHopConcurrentIndependentConnections(t *testing.T) {
	const connectionCount = 32
	fixture := newLiveFirstHopFixture(t, time.Now())
	credentials := make([]admission.AccessHintCredential, connectionCount)
	clients := make([]*handshake.ClientDriver, connectionCount)
	for i := range credentials {
		credential := fixture.accessHint
		credential.HintIssuerID = append([]byte(nil), fixture.accessHint.HintIssuerID...)
		credential.RelayBucketID = append([]byte(nil), fixture.accessHint.RelayBucketID...)
		credential.HintSelector = randomLiveFirstHopBytes(t, 16)
		credential.HintSecret = randomLiveFirstHopBytes(t, 32)
		credentials[i] = credential
		clientFixture := fixture
		clientFixture.accessHint = credential
		clients[i] = clientFixture.newClientDriver(t)
	}
	relayDriver := fixture.newRelayDriver(t, liveFirstHopRelayOptions{
		hintResolver: liveFirstHopMultiHintResolver{credentials: credentials},
	})
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, connectionCount)
	var wait sync.WaitGroup
	for _, clientDriver := range clients {
		wait.Add(1)
		go func(driver *handshake.ClientDriver) {
			defer wait.Done()
			<-start
			established, err := driver.Connect(ctx, harness.opener)
			if established != nil {
				_ = established.Close()
			}
			results <- err
		}(clientDriver)
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("independent live connection failed: %v", err)
		}
	}
	for i := 0; i < connectionCount; i++ {
		select {
		case application := <-harness.relayApplications:
			_ = application.Close()
		case <-ctx.Done():
			t.Fatalf("received %d of %d relay applications", i, connectionCount)
		}
	}
	if got := harness.connections.Load(); got != connectionCount {
		t.Fatalf("accepted connections = %d, want %d", got, connectionCount)
	}
}

func TestLiveFirstHopDisconnectsAtHandshakeBoundaries(t *testing.T) {
	tests := []struct {
		name                 string
		closeOnOpen          bool
		closeAfterWrite      int
		closeAfterRead       int
		mayCreateApplication bool
	}{
		{name: "after TLS open", closeOnOpen: true, closeAfterWrite: -1, closeAfterRead: -1},
		{name: "after Prelude0", closeAfterWrite: 0, closeAfterRead: -1},
		{name: "after Prelude1", closeAfterWrite: -1, closeAfterRead: 0},
		{name: "after Capsule1", closeAfterWrite: 1, closeAfterRead: -1, mayCreateApplication: true},
		{name: "after Capsule2", closeAfterWrite: -1, closeAfterRead: 1, mayCreateApplication: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLiveFirstHopFixture(t, time.Now())
			relayDriver := fixture.newRelayDriver(t)
			harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
			opener := &liveFirstHopDisconnectingOpener{
				base:            harness.opener,
				closeOnOpen:     test.closeOnOpen,
				closeAfterWrite: test.closeAfterWrite,
				closeAfterRead:  test.closeAfterRead,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			established, err := fixture.newClientDriver(t).Connect(ctx, opener)
			if established != nil {
				_ = established.Close()
			}
			if err == nil || established != nil {
				t.Fatal("disconnected live handshake established a client session")
			}
			if test.mayCreateApplication {
				select {
				case application := <-harness.relayApplications:
					_ = application.Close()
				case <-time.After(100 * time.Millisecond):
				}
			} else {
				select {
				case application := <-harness.relayApplications:
					_ = application.Close()
					t.Fatal("pre-Capsule1 disconnect created a relay application")
				default:
				}
			}
			if got := harness.connections.Load(); got != 1 {
				t.Fatalf("disconnect case accepted %d connections, want 1", got)
			}
		})
	}
}

func TestLiveFirstHopMalformedRecordFramingUsesSanitizedCover(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "empty record", body: []byte{0, 0, 0}},
		{name: "truncated record", body: []byte{0, 0, 8, 1, 2}},
		{name: "oversized record", body: []byte{0x10, 0, 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLiveFirstHopFixture(t, time.Now())
			relayDriver := fixture.newRelayDriver(t)
			coverOrigin := &recordingFirstHopCoverOrigin{}
			harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
			protocols := new(http.Protocols)
			protocols.SetHTTP2(true)
			clientTransport := &http.Transport{
				TLSClientConfig:   harness.clientTLS.Clone(),
				Protocols:         protocols,
				ForceAttemptHTTP2: true,
				DisableKeepAlives: true,
			}
			t.Cleanup(clientTransport.CloseIdleConnections)
			client := &http.Client{Transport: clientTransport, Timeout: 3 * time.Second}
			request, err := http.NewRequest(http.MethodPost, "https://"+harness.authority+harness.path, bytes.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			result := readFirstHopHTTPResult(response, nil)
			if result.err != nil || result.status != http.StatusTeapot || string(result.body) != "cover-body" {
				t.Fatalf("malformed live record did not receive cover: %+v", result)
			}
			method, body := coverOrigin.snapshot()
			if method != http.MethodGet || len(body) != 0 {
				t.Fatalf("malformed live record reached cover origin: method=%s body=%x", method, body)
			}
			select {
			case application := <-harness.relayApplications:
				_ = application.Close()
				t.Fatal("malformed live record created a relay application")
			default:
			}
		})
	}
}

func TestLiveFirstHopGracefulShutdownCancelsRelayDependency(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	resolver := &liveFirstHopBlockingHintResolver{started: make(chan struct{})}
	relayDriver := fixture.newRelayDriver(t, liveFirstHopRelayOptions{hintResolver: resolver})
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	clientDriver := fixture.newClientDriver(t)
	connectContext, cancelConnect := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelConnect()
	connectResult := make(chan error, 1)
	go func() {
		established, err := clientDriver.Connect(connectContext, harness.opener)
		if established != nil {
			_ = established.Close()
		}
		connectResult <- err
	}()
	select {
	case <-resolver.started:
	case <-connectContext.Done():
		t.Fatal("live relay dependency did not start")
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := harness.shutdown(shutdownContext); err != nil {
		t.Fatalf("graceful live shutdown: %v", err)
	}
	select {
	case err := <-connectResult:
		if err == nil {
			t.Fatal("shutdown relay dependency established a client session")
		}
	case <-time.After(time.Second):
		t.Fatal("graceful shutdown did not join the client handshake")
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		t.Fatal("shutdown relay dependency created an application")
	default:
	}
}

func BenchmarkLiveFirstHopBootstrap(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fixture := newLiveFirstHopFixture(b, time.Now())
		relayDriver := fixture.newRelayDriver(b)
		harness := startLiveFirstHopHarness(b, fixture, relayDriver, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		established, err := fixture.newClientDriver(b).Connect(ctx, harness.opener)
		if err != nil {
			cancel()
			_ = harness.close()
			b.Fatal(err)
		}
		select {
		case application := <-harness.relayApplications:
			_ = application.Close()
		case <-ctx.Done():
			_ = established.Close()
			cancel()
			_ = harness.close()
			b.Fatal(ctx.Err())
		}
		_ = established.Close()
		cancel()
		if err := harness.close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLiveFirstHopBootstrapParallel64(b *testing.B) {
	const connectionCount = 64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fixture := newLiveFirstHopFixture(b, time.Now())
		credentials := make([]admission.AccessHintCredential, connectionCount)
		clients := make([]*handshake.ClientDriver, connectionCount)
		for j := range credentials {
			credential := cloneLiveFirstHopHintCredential(fixture.accessHint)
			credential.HintSelector = randomLiveFirstHopBytes(b, 16)
			credential.HintSecret = randomLiveFirstHopBytes(b, 32)
			credentials[j] = credential
			clientFixture := fixture
			clientFixture.accessHint = credential
			clients[j] = clientFixture.newClientDriver(b)
		}
		relayDriver := fixture.newRelayDriver(b, liveFirstHopRelayOptions{
			hintResolver: liveFirstHopMultiHintResolver{credentials: credentials},
		})
		harness := startLiveFirstHopHarness(b, fixture, relayDriver, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := make(chan struct{})
		results := make(chan error, connectionCount)
		var wait sync.WaitGroup
		for _, clientDriver := range clients {
			wait.Add(1)
			go func(driver *handshake.ClientDriver) {
				defer wait.Done()
				<-start
				established, err := driver.Connect(ctx, harness.opener)
				if established != nil {
					_ = established.Close()
				}
				results <- err
			}(clientDriver)
		}
		close(start)
		wait.Wait()
		close(results)
		var runErr error
		for err := range results {
			if err != nil && runErr == nil {
				runErr = err
			}
		}
		for j := 0; j < connectionCount && runErr == nil; j++ {
			select {
			case application := <-harness.relayApplications:
				_ = application.Close()
			case <-ctx.Done():
				runErr = ctx.Err()
			}
		}
		if got := harness.connections.Load(); runErr == nil && got != connectionCount {
			runErr = fmt.Errorf("parallel benchmark accepted %d connections, want %d", got, connectionCount)
		}
		cancel()
		if err := harness.close(); runErr == nil && err != nil {
			runErr = err
		}
		if runErr != nil {
			b.Fatal(runErr)
		}
	}
}

type liveFirstHopHarness struct {
	opener            handshake.ClientCarrierOpener
	authority         string
	path              string
	clientTLS         *tls.Config
	certificateRaw    []byte
	bindingMetadata   handshake.HTTP2BindingMetadata
	serverFrames      chan []byte
	relayApplications chan *session.Application
	connections       *atomic.Int32
	shutdown          func(context.Context) error
	close             func() error
}

type liveFirstHopTLSMaterial struct {
	certificate tls.Certificate
	clientTLS   *tls.Config
}

func startLiveFirstHopHarness(t testing.TB, fixture liveFirstHopFixture, relayDriver *handshake.RelayDriver, coverOrigin http.Handler) liveFirstHopHarness {
	return startLiveFirstHopHarnessWithSessionFactory(t, fixture, relayDriver, coverOrigin, nil)
}

func startLiveFirstHopHarnessWithSessionFactory(t testing.TB, fixture liveFirstHopFixture, relayDriver *handshake.RelayDriver, coverOrigin http.Handler, sessionFactory FirstHopSessionFactory) liveFirstHopHarness {
	return startLiveFirstHopHarnessWithSessionFactoryAndTLS(t, fixture, relayDriver, coverOrigin, sessionFactory, liveFirstHopTLSMaterial{})
}

func startLiveFirstHopHarnessWithSessionFactoryAndTLS(t testing.TB, fixture liveFirstHopFixture, relayDriver *handshake.RelayDriver, coverOrigin http.Handler, sessionFactory FirstHopSessionFactory, tlsMaterial liveFirstHopTLSMaterial) liveFirstHopHarness {
	t.Helper()
	if len(tlsMaterial.certificate.Certificate) == 0 || tlsMaterial.clientTLS == nil {
		tlsMaterial = newLiveFirstHopTLSMaterial(t)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := listener.Addr().String()
	const path = "/assets/upload/42"
	serverFrames := make(chan []byte, 8)
	relayApplications := make(chan *session.Application, 64)
	connections := &atomic.Int32{}
	template := fixture.deployment.Template()
	requestClass := fixture.deployment.RequestClass()
	bindingMetadata := handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), template.PublicNameHash...),
		PathTemplateID:          append([]byte(nil), requestClass.PathTemplateID...),
		RequestClassID:          requestClass.ClassID,
		MethodFamilyID:          fixture.deployment.Method(),
	}
	options := FirstHopOptions{
		Driver:             relayDriver,
		Authority:          authority,
		Path:               path,
		BindingMetadata:    bindingMetadata,
		CoverStatus:        http.StatusCreated,
		CoverHeader:        http.Header{"Content-Type": {"application/octet-stream"}, "X-Cover-Mode": {"ordinary"}},
		Origin:             relay.StaticOrigin{Status: http.StatusNotFound, Body: []byte("not found")},
		CoverOrigin:        coverOrigin,
		MaxRecordBodyBytes: 1 << 20,
		PostHeaderTimeout:  5 * time.Second,
	}
	if sessionFactory == nil {
		options.FrameHandler = func(_ context.Context, block protocol.FrameBlock) error {
			serverFrames <- append([]byte(nil), block.Frames[0].Payload...)
			return nil
		}
	} else {
		options.SessionFactory = sessionFactory
	}
	handler, err := NewFirstHopHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	productionFinish := handler.finish
	handler.finish = func(ctx context.Context, state *handshake.RelayHandshake, capsule1 []byte, nowUnix uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		capsule2, endpoint, policy, finishErr := productionFinish(ctx, state, capsule1, nowUnix)
		if finishErr == nil {
			application, ok := endpoint.(*session.Application)
			if !ok {
				return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("live relay endpoint type %T", endpoint)
			}
			relayApplications <- application
		}
		return capsule2, endpoint, policy, finishErr
	}
	clientTLS := tlsMaterial.clientTLS.Clone()
	httpServer, err := NewFirstHopHTTPServer(authority, handler, &tls.Config{Certificates: []tls.Certificate{tlsMaterial.certificate}})
	if err != nil {
		t.Fatal(err)
	}
	httpServer.ConnContext = func(ctx context.Context, connection net.Conn) context.Context {
		connections.Add(1)
		return handler.ConnContext(ctx, connection)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- httpServer.Serve(tls.NewListener(listener, httpServer.TLSConfig)) }()
	var closeOnce sync.Once
	var closeErr error
	closeHarness := func() error {
		closeOnce.Do(func() {
			closeErr = httpServer.Close()
			select {
			case serveErr := <-serveResult:
				if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
					closeErr = errors.Join(closeErr, serveErr)
				}
			case <-time.After(time.Second):
				closeErr = errors.Join(closeErr, errors.New("live first-hop server did not stop"))
			}
		})
		return closeErr
	}
	t.Cleanup(func() {
		if err := closeHarness(); err != nil {
			t.Errorf("close live first-hop server: %v", err)
		}
	})
	built, err := transport.BuildStreamingH2CarrierRequest(transport.CarrierRequestInput{
		Plan: transport.CarrierPlan{
			Carrier: transport.Carrier{MethodID: registry.MethodWebH2Stream},
			UDPMode: transport.UDPOverStreamFallback,
		},
		Template:       template,
		RequestClassID: requestClass.ClassID,
		Scheme:         "https",
		Authority:      authority,
		Path:           path,
		Header:         http.Header{"Accept": {"application/octet-stream"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.MaxVersion = tls.VersionTLS13
	clientTLS.NextProtos = []string{"h2"}
	clientTLS.ClientSessionCache = nil
	opener, err := transport.NewHTTP2ClientCarrierOpener(transport.HTTP2ClientCarrierConfig{
		Request:            built.Request,
		TLSConfig:          clientTLS,
		BindingMetadata:    bindingMetadata,
		ExpectedStatus:     http.StatusCreated,
		ExpectedHeader:     http.Header{"Content-Type": {"application/octet-stream"}, "X-Cover-Mode": {"ordinary"}},
		MaxRecordBodyBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return liveFirstHopHarness{
		opener:            opener,
		authority:         authority,
		path:              path,
		clientTLS:         clientTLS.Clone(),
		certificateRaw:    append([]byte(nil), tlsMaterial.certificate.Certificate[0]...),
		bindingMetadata:   bindingMetadata,
		serverFrames:      serverFrames,
		relayApplications: relayApplications,
		connections:       connections,
		shutdown:          httpServer.Shutdown,
		close:             closeHarness,
	}
}

func newLiveFirstHopTLSMaterial(t testing.TB) liveFirstHopTLSMaterial {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	return liveFirstHopTLSMaterial{
		certificate: server.TLS.Certificates[0],
		clientTLS:   server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
	}
}

func startLiveFirstHopIssuer(t testing.TB, fixture liveFirstHopFixture) *httptest.Server {
	t.Helper()
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/assets/issue/42" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
		if err != nil || len(body) == 0 || len(body) > 1<<20 {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		carrierType, payload, err := DecodeCarrier(body)
		if err != nil || carrierType != CarrierBlindRSAIssueReq {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, redemptionContext, expiry, err := DecodeCarrierIssueRequest(payload)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		proofProvider := &liveFirstHopProofProvider{
			issuerID:      fixture.accessHint.HintIssuerID,
			relayBucketID: fixture.accessHint.RelayBucketID,
			privateKey:    fixture.tokenPrivate,
			publicKeyDER:  fixture.tokenPublicDER,
		}
		proof, _, err := proofProvider.BuildProofs(request.Context(), handshake.ClientProofRequest{
			AdmissionContextHash:    redemptionContext,
			HandshakeBindingContext: bytes.Repeat([]byte{0x51}, 48),
			RouteInstanceID:         1,
			ReplayEpochID:           1,
			ReplayEpochValidUntil:   expiry + 1,
			ReplayWindowID:          bytes.Repeat([]byte{0x52}, 16),
		})
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		encoded, err := protocol.Encode(proof)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(EncodeCarrier(CarrierBlindRSAIssueResp, encoded))
	}))
	t.Cleanup(issuer.Close)
	return issuer
}

func liveFirstHopIssueResponse(t testing.TB, issuer *httptest.Server, work auroraclient.IssuerWork) []byte {
	t.Helper()
	if issuer == nil || work.IssuerURL != issuer.URL || work.IssuerCarrierPath != "/assets/issue/42" {
		t.Fatal("live first-hop issuer work is not pinned to the test issuer")
	}
	request, err := http.NewRequest(http.MethodPost, issuer.URL+work.IssuerCarrierPath, bytes.NewReader(work.RequestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := issuer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("live first-hop issuer response = status=%d content_type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(encoded) == 0 || len(encoded) > 1<<20 {
		t.Fatalf("read live first-hop issuer response: len=%d err=%v", len(encoded), err)
	}
	return encoded
}

func (f liveFirstHopFixture) nativeProvisioningForHarness(t testing.TB, harness liveFirstHopHarness, issuerURL string) auroraclient.NativeProvisioning {
	t.Helper()
	descriptor, err := protocol.Encode(f.deployment.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	template, err := protocol.Encode(f.deployment.Template())
	if err != nil {
		t.Fatal(err)
	}
	templateAuthority, err := protocol.Encode(f.templateAuthority)
	if err != nil {
		t.Fatal(err)
	}
	accessHint, err := admission.EncodeAccessHintCredential(f.accessHint)
	if err != nil {
		t.Fatal(err)
	}
	policyOffer, err := protocol.Encode(liveFirstHopPolicyOffer(f.deployment))
	if err != nil {
		t.Fatal(err)
	}
	transportHints, err := protocol.Encode(liveFirstHopTransportHints(t))
	if err != nil {
		t.Fatal(err)
	}
	requestHeaders, err := auroraclient.EncodeNativeHeaders(http.Header{"Accept": {"application/octet-stream"}})
	if err != nil {
		t.Fatal(err)
	}
	responseHeaders, err := auroraclient.EncodeNativeHeaders(http.Header{"Content-Type": {"application/octet-stream"}, "X-Cover-Mode": {"ordinary"}})
	if err != nil {
		t.Fatal(err)
	}
	trustRoots, err := auroraclient.EncodeNativeTrustRoots([][]byte{harness.certificateRaw})
	if err != nil {
		t.Fatal(err)
	}
	return auroraclient.NativeProvisioning{
		RelayURL:              "https://" + harness.authority + harness.path,
		IssuerURL:             issuerURL,
		IssuerCarrierPath:     "/assets/issue/42",
		Descriptor:            descriptor,
		TrustedDescriptorHash: f.deployment.DescriptorHash(),
		Template:              template,
		TemplateAuthorityKey:  templateAuthority,
		RequestClassID:        f.deployment.RequestClass().ClassID,
		Suite:                 f.deployment.Suite(),
		AccessHint:            accessHint,
		PolicyOffer:           policyOffer,
		TransportHints:        transportHints,
		RelayExpectedStatus:   http.StatusCreated,
		RelayRequestHeaders:   requestHeaders,
		RelayResponseHeaders:  responseHeaders,
		RelayTrustRoots:       trustRoots,
	}
}

func zeroLiveFirstHopBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func zeroLiveFirstHopNativeProvisioning(provisioning *auroraclient.NativeProvisioning) {
	if provisioning == nil {
		return
	}
	for _, field := range [][]byte{
		provisioning.Descriptor,
		provisioning.TrustedDescriptorHash,
		provisioning.Template,
		provisioning.TemplateAuthorityKey,
		provisioning.AccessHint,
		provisioning.PolicyOffer,
		provisioning.TransportHints,
		provisioning.RelayRequestHeaders,
		provisioning.RelayResponseHeaders,
		provisioning.RelayTrustRoots,
	} {
		zeroLiveFirstHopBytes(field)
	}
	*provisioning = auroraclient.NativeProvisioning{}
}

type liveFirstHopMutatingOpener struct {
	base   handshake.ClientCarrierOpener
	mutate func(int, []byte) ([]byte, error)
}

type liveFirstHopDisconnectingOpener struct {
	base            handshake.ClientCarrierOpener
	closeOnOpen     bool
	closeAfterWrite int
	closeAfterRead  int
}

type rejectingLiveFirstHopDialer struct {
	calls atomic.Int32
}

func (d *rejectingLiveFirstHopDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("unexpected test dial")
}

type blockingLiveFirstHopDialer struct {
	started chan struct{}
	done    chan struct{}
	start   sync.Once
	finish  sync.Once
}

func newBlockingLiveFirstHopDialer() *blockingLiveFirstHopDialer {
	return &blockingLiveFirstHopDialer{started: make(chan struct{}), done: make(chan struct{})}
}

func (d *blockingLiveFirstHopDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.start.Do(func() { close(d.started) })
	<-ctx.Done()
	d.finish.Do(func() { close(d.done) })
	return nil, ctx.Err()
}

func (o *liveFirstHopDisconnectingOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	wrapped := &liveFirstHopDisconnectingCarrier{
		BootstrapCarrier: carrier,
		closeAfterWrite:  o.closeAfterWrite,
		closeAfterRead:   o.closeAfterRead,
	}
	if o.closeOnOpen {
		_ = carrier.Close()
	}
	return wrapped, nil
}

type liveFirstHopDisconnectingCarrier struct {
	handshake.BootstrapCarrier
	mu              sync.Mutex
	writes          int
	reads           int
	closeAfterWrite int
	closeAfterRead  int
}

func (c *liveFirstHopDisconnectingCarrier) WriteRecord(record []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.writes
	c.writes++
	err := c.BootstrapCarrier.WriteRecord(record)
	if err == nil && index == c.closeAfterWrite {
		_ = c.BootstrapCarrier.Close()
	}
	return err
}

func (c *liveFirstHopDisconnectingCarrier) ReadRecord() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.reads
	c.reads++
	record, err := c.BootstrapCarrier.ReadRecord()
	if err == nil && index == c.closeAfterRead {
		_ = c.BootstrapCarrier.Close()
	}
	return record, err
}

type liveFirstHopBindingMetadataOpener struct {
	base     handshake.ClientCarrierOpener
	metadata handshake.HTTP2BindingMetadata
	mutate   func(*handshake.HTTP2BindingMetadata)
}

func (o *liveFirstHopBindingMetadataOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	metadata := handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), o.metadata.NormalizedAuthorityHash...),
		PathTemplateID:          append([]byte(nil), o.metadata.PathTemplateID...),
		RequestClassID:          o.metadata.RequestClassID,
		MethodFamilyID:          o.metadata.MethodFamilyID,
	}
	o.mutate(&metadata)
	binding := carrier.Binding()
	streamBinding, err := handshake.CoverStreamBinding(handshake.CoverStreamBindingInput{
		OuterExporterValue:       binding.OuterExporterValue,
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         binding.ConnectionIDHash,
		StreamIDOrRequestID:      1,
		MethodFamilyID:           metadata.MethodFamilyID,
		NormalizedAuthorityHash:  metadata.NormalizedAuthorityHash,
		NormalizedPathTemplateID: metadata.PathTemplateID,
		RequestClassID:           metadata.RequestClassID,
		ClientCoverRandom:        coverRandom,
	})
	if err != nil {
		_ = carrier.Close()
		return nil, err
	}
	bindingContext, err := handshake.FirstHopBindingContext(binding.OuterExporterValue, streamBinding)
	if err != nil {
		_ = carrier.Close()
		return nil, err
	}
	binding.CoverStreamBinding = streamBinding
	binding.HandshakeBindingContext = bindingContext
	return &liveFirstHopBindingCarrier{BootstrapCarrier: carrier, binding: binding}, nil
}

type liveFirstHopBindingCarrier struct {
	handshake.BootstrapCarrier
	binding handshake.FirstHopBinding
}

func (c *liveFirstHopBindingCarrier) Binding() handshake.FirstHopBinding {
	return handshake.FirstHopBinding{
		OuterExporterValue:      append([]byte(nil), c.binding.OuterExporterValue...),
		TLSExporterChannelID:    append([]byte(nil), c.binding.TLSExporterChannelID...),
		ConnectionIDHash:        append([]byte(nil), c.binding.ConnectionIDHash...),
		CoverStreamBinding:      append([]byte(nil), c.binding.CoverStreamBinding...),
		HandshakeBindingContext: append([]byte(nil), c.binding.HandshakeBindingContext...),
	}
}

type liveFirstHopReadMutatingOpener struct {
	base   handshake.ClientCarrierOpener
	mutate func(int, []byte) ([]byte, error)
}

func (o *liveFirstHopReadMutatingOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	return &liveFirstHopReadMutatingCarrier{BootstrapCarrier: carrier, mutate: o.mutate}, nil
}

type liveFirstHopReadMutatingCarrier struct {
	handshake.BootstrapCarrier
	mu     sync.Mutex
	reads  int
	mutate func(int, []byte) ([]byte, error)
}

func (c *liveFirstHopReadMutatingCarrier) ReadRecord() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	record, err := c.BootstrapCarrier.ReadRecord()
	if err != nil {
		return nil, err
	}
	mutated, err := c.mutate(c.reads, append([]byte(nil), record...))
	c.reads++
	return mutated, err
}

func (o *liveFirstHopMutatingOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	return &liveFirstHopMutatingCarrier{BootstrapCarrier: carrier, mutate: o.mutate}, nil
}

type liveFirstHopMutatingCarrier struct {
	handshake.BootstrapCarrier
	mu     sync.Mutex
	writes int
	mutate func(int, []byte) ([]byte, error)
}

func (c *liveFirstHopMutatingCarrier) WriteRecord(record []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	owned := append([]byte(nil), record...)
	mutated, err := c.mutate(c.writes, owned)
	c.writes++
	if err != nil {
		return err
	}
	return c.BootstrapCarrier.WriteRecord(mutated)
}

func mutateLiveFirstHopPrelude(mutate func(*protocol.CoverPrelude0)) func(int, []byte) ([]byte, error) {
	return func(index int, record []byte) ([]byte, error) {
		if index != 0 {
			return record, nil
		}
		prelude, err := decodeFirstHopPrelude0(record)
		if err != nil {
			return nil, err
		}
		mutate(&prelude)
		return protocol.Encode(prelude)
	}
}

func mutateLiveFirstHopPrelude1Signature(index int, record []byte) ([]byte, error) {
	if index != 0 {
		return record, nil
	}
	reader := wire.NewReader(record)
	prelude := protocol.DecodeCoverPrelude1(reader)
	if reader.Err() != nil {
		return nil, reader.Err()
	}
	if !reader.EOF() || len(prelude.ServerPreludeSignatureClassical) == 0 {
		return nil, errors.New("live first-hop Prelude1 signature is unavailable")
	}
	prelude.ServerPreludeSignatureClassical[0] ^= 0xff
	return protocol.Encode(prelude)
}

type liveFirstHopFixture struct {
	deployment        trust.VerifiedRelayDeployment
	accessHint        admission.AccessHintCredential
	templateAuthority protocol.PublicKeyRecord
	epochClassical    *ecdsa.PrivateKey
	epochPQ           *mldsa65.PrivateKey
	tokenPrivate      *rsa.PrivateKey
	tokenPublicDER    []byte
}

func newLiveFirstHopFixture(t testing.TB, now time.Time) liveFirstHopFixture {
	return newLiveFirstHopFixtureWithOriginSPKI(t, now, randomLiveFirstHopBytes(t, 48))
}

func newLiveFirstHopFixtureWithOriginSPKI(t testing.TB, now time.Time, originSPKIHash []byte) liveFirstHopFixture {
	t.Helper()
	if len(originSPKIHash) != 48 {
		t.Fatal("live first-hop origin SPKI hash length is invalid")
	}
	longtermClassical := generateLiveFirstHopECDSA(t)
	epochClassical := generateLiveFirstHopECDSA(t)
	templateAuthority := generateLiveFirstHopECDSA(t)
	longtermPQPublic, longtermPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochPQPublic, epochPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tokenPublicDER, err := marshalLiveFirstHopRSAPSSPublicKey(&tokenPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nowUnix := uint64(now.Unix())
	template := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       randomLiveFirstHopBytes(t, 16),
		TemplateFamilyID: randomLiveFirstHopBytes(t, 16),
		ValidFromUnix:    nowUnix - 60,
		ValidUntilUnix:   nowUnix + 3600,
		OriginSPKIHash:   append([]byte(nil), originSPKIHash...),
		PublicNameHash:   randomLiveFirstHopBytes(t, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             7,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      randomLiveFirstHopBytes(t, 16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{randomLiveFirstHopBytes(t, 48)},
		OriginPassThroughSlotCommitments: [][]byte{randomLiveFirstHopBytes(t, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  randomLiveFirstHopBytes(t, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: randomLiveFirstHopBytes(t, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               randomLiveFirstHopBytes(t, 16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   randomLiveFirstHopBytes(t, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile:         protocol.H2CoverProfile{ProfileID: 1, RecordSizeDistributionID: randomLiveFirstHopBytes(t, 16)},
		H3Profile:         protocol.H3CoverProfile{ProfileID: 2, DatagramSizeDistributionID: randomLiveFirstHopBytes(t, 16), DatagramRateDistributionID: randomLiveFirstHopBytes(t, 16)},
		WebSocketProfile:  protocol.WebSocketCoverProfile{ProfileID: 3, FrameSizeDistributionID: randomLiveFirstHopBytes(t, 16)},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: randomLiveFirstHopBytes(t, 16)},
	}
	template.CoverOriginCommitment, err = trust.CoverOriginCommitment(template)
	if err != nil {
		t.Fatal(err)
	}
	templateHash, err := trust.CoverTemplateHash(template)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      randomLiveFirstHopBytes(t, 32),
		RoleFlags:                    1,
		ValidFromUnix:                nowUnix - 60,
		ValidUntilUnix:               nowUnix + 3600,
		RelayLongtermClassicalKey:    liveFirstHopECDSAPublicRecord(t, longtermClassical),
		RelayLongtermPQKey:           protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: longtermPQPublic.Bytes()},
		EpochID:                      9,
		EpochAuthClassicalKey:        liveFirstHopECDSAPublicRecord(t, epochClassical),
		EpochAuthPQKey:               protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: epochPQPublic.Bytes()},
		EpochValidFromUnix:           nowUnix - 60,
		EpochValidUntilUnix:          nowUnix + 3600,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    nowUnix + 3600,
		ReplayWindowID:               randomLiveFirstHopBytes(t, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: randomLiveFirstHopBytes(t, 48),
		SupportedShapeIDsCommitment:  randomLiveFirstHopBytes(t, 48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         randomLiveFirstHopBytes(t, 48),
		AbusePolicyCommitment:        randomLiveFirstHopBytes(t, 48),
	}
	descriptorInput, err := trust.RelayDescriptorSignatureInput(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermClassical, err = ecdsa.SignASN1(rand.Reader, longtermClassical, descriptorInput)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermPQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(longtermPQPrivate, descriptorInput, nil, false, descriptor.SignatureByLongtermPQ); err != nil {
		t.Fatal(err)
	}
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	familyInput, err := trust.CoverTemplateFamilySignatureInput(template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthority, familyInput)
	if err != nil {
		t.Fatal(err)
	}
	instanceInput, err := trust.CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, instanceInput)
	if err != nil {
		t.Fatal(err)
	}
	templateAuthorityRecord := liveFirstHopECDSAPublicRecord(t, templateAuthority)
	deployment, err := trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    descriptorHash,
		Template:                 template,
		TemplateAuthorityKey:     templateAuthorityRecord,
		RequestClassID:           7,
		Suite:                    registry.SuiteHybrid768P256AESGCM,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  nowUnix,
		MaxTemplateFutureSkew:    120,
		RequirePQDescriptorProof: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return liveFirstHopFixture{
		deployment: deployment,
		accessHint: admission.AccessHintCredential{
			HintIssuerID:  randomLiveFirstHopBytes(t, 16),
			RelayBucketID: randomLiveFirstHopBytes(t, 16),
			HintEpochID:   3,
			HintSelector:  randomLiveFirstHopBytes(t, 16),
			HintSecret:    randomLiveFirstHopBytes(t, 32),
			ExpiryUnix:    nowUnix + 1800,
			MaxUses:       1,
		},
		templateAuthority: templateAuthorityRecord,
		epochClassical:    epochClassical,
		epochPQ:           epochPQPrivate,
		tokenPrivate:      tokenPrivate,
		tokenPublicDER:    tokenPublicDER,
	}
}

func (f liveFirstHopFixture) newClientDriver(t testing.TB) *handshake.ClientDriver {
	t.Helper()
	driver, _ := f.newClientDriverWithProofProvider(t)
	return driver
}

func (f liveFirstHopFixture) newClientDriverWithProofProvider(t testing.TB) (*handshake.ClientDriver, *liveFirstHopProofProvider) {
	t.Helper()
	proofProvider := &liveFirstHopProofProvider{
		issuerID:      f.accessHint.HintIssuerID,
		relayBucketID: f.accessHint.RelayBucketID,
		privateKey:    f.tokenPrivate,
		publicKeyDER:  f.tokenPublicDER,
	}
	driver, err := handshake.NewClientDriver(handshake.ClientDriverConfig{
		Deployment:     f.deployment,
		Suite:          f.deployment.Suite(),
		AccessHint:     f.accessHint,
		PolicyOffer:    liveFirstHopPolicyOffer(f.deployment),
		TransportHints: liveFirstHopTransportHints(t),
		ProofProvider:  proofProvider,
		RequirePQ:      true,
		SessionLimits:  liveFirstHopSessionLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return driver, proofProvider
}

func liveFirstHopPolicyOffer(deployment trust.VerifiedRelayDeployment) protocol.PolicyOffer {
	return protocol.PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{deployment.Suite()},
		OfferedMethods:          []uint64{deployment.Method()},
		MinimumPolicyID:         registry.PolicyFastWeb,
		RequestedPolicyID:       registry.PolicyBalancedWeb,
		RequestedRouteModeID:    registry.RouteFast1,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
	}
}

func liveFirstHopTransportHints(t testing.TB) protocol.ClientTransportHints {
	t.Helper()
	return protocol.ClientTransportHints{Padding: randomLiveFirstHopBytes(t, 8)}
}

type liveFirstHopRelayOptions struct {
	hintResolver      handshake.HintCredentialResolver
	hintCache         handshake.DurableReplayCache
	admissionVerifier handshake.AdmissionVerifier
	tokenCache        handshake.DurableReplayCache
	bootstrapCache    handshake.DurableReplayCache
	policySelector    handshake.PolicySelector
}

func (f liveFirstHopFixture) newRelayDriver(t testing.TB, supplied ...liveFirstHopRelayOptions) *handshake.RelayDriver {
	t.Helper()
	options := liveFirstHopRelayOptions{}
	if len(supplied) > 0 {
		options = supplied[0]
	}
	if options.hintCache == nil {
		options.hintCache = &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	}
	if options.admissionVerifier == nil {
		options.admissionVerifier = liveFirstHopAdmissionVerifier{tokenPublicKeyDER: f.tokenPublicDER}
	}
	if options.tokenCache == nil {
		options.tokenCache = &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	}
	if options.bootstrapCache == nil {
		options.bootstrapCache = &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	}
	if options.policySelector == nil {
		options.policySelector = liveFirstHopPolicySelector{}
	}
	if options.hintResolver == nil {
		options.hintResolver = liveFirstHopHintResolver{credential: f.accessHint}
	}
	descriptor := f.deployment.Descriptor()
	driver, err := handshake.NewRelayDriver(handshake.RelayDriverConfig{
		Deployment:        f.deployment,
		HintResolver:      options.hintResolver,
		HintSpentCache:    options.hintCache,
		AdmissionVerifier: options.admissionVerifier,
		TokenSpentCache:   options.tokenCache,
		BootstrapCache:    options.bootstrapCache,
		ClassicalSigner:   liveFirstHopSigner{publicKey: descriptor.EpochAuthClassicalKey, classical: f.epochClassical},
		PQSigner:          liveFirstHopSigner{publicKey: descriptor.EpochAuthPQKey, pq: f.epochPQ},
		PolicySelector:    options.policySelector,
		RequirePQ:         true,
		SessionLimits:     liveFirstHopSessionLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

type liveFirstHopProofProvider struct {
	issuerID            []byte
	relayBucketID       []byte
	privateKey          *rsa.PrivateKey
	publicKeyDER        []byte
	tamperAuthenticator bool
	calls               atomic.Int32
}

func (p *liveFirstHopProofProvider) BuildProofs(ctx context.Context, request handshake.ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	p.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	if p.privateKey == nil || len(p.publicKeyDER) == 0 {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, errors.New("live first-hop proof provider is missing its RSA key")
	}
	keyID := sha256.Sum256(p.publicKeyDER)
	tokenScope, err := randomLiveFirstHopBytesResult(16)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	tokenNonce, err := randomLiveFirstHopBytesResult(32)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              append([]byte(nil), p.issuerID...),
		TokenKeyID:            keyID[:],
		RelayBucketID:         append([]byte(nil), p.relayBucketID...),
		TokenScopeID:          tokenScope,
		ExpiryUnix:            request.ReplayEpochValidUntil - 1,
		TokenNonce:            tokenNonce,
		RedemptionContextHash: append([]byte(nil), request.AdmissionContextHash...),
	}
	issuerName := []byte("issuer.invalid")
	originInfo := []byte("origin.invalid")
	challengeDigest, err := admission.RFC9577TokenChallengeDigest(proof.ProofType, issuerName, originInfo, proof.RedemptionContextHash)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	issuerMetadataHash, err := randomLiveFirstHopBytesResult(48)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	metadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: challengeDigest,
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             issuerName,
		OriginInfo:             originInfo,
		IssuerMetadataHash:     issuerMetadataHash,
	}
	proof.TokenPublicMetadata, err = protocol.Encode(metadata)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	authenticatorInput, err := admission.RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	digest := sha512.Sum384(authenticatorInput)
	proof.TokenAuthenticator, err = rsa.SignPSS(rand.Reader, p.privateKey, crypto.SHA384, digest[:], &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       crypto.SHA384,
	})
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	if p.tamperAuthenticator {
		proof.TokenAuthenticator[0] ^= 0xff
	}
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	replayNonce, err := randomLiveFirstHopBytesResult(32)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	replay := protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       request.ReplayEpochID,
		TokenRedemptionHash: redemption,
		ClientReplayNonce:   replayNonce,
		ReplayWindowID:      append([]byte(nil), request.ReplayWindowID...),
	}
	replay.ReplayContextHash, err = admission.ReplayContextHash(redemption, replay, request.RouteInstanceID, request.HopIndex, request.HandshakeBindingContext, request.AdmissionContextHash)
	return proof, replay, err
}

type liveFirstHopHintResolver struct {
	credential admission.AccessHintCredential
}

func (r liveFirstHopHintResolver) ResolveAccessHint(_ context.Context, issuerID, relayBucketID []byte, hintEpochID uint64, hintSelector []byte) (admission.AccessHintCredential, error) {
	credential := r.credential
	if !bytes.Equal(issuerID, credential.HintIssuerID) || !bytes.Equal(relayBucketID, credential.RelayBucketID) || hintEpochID != credential.HintEpochID || !bytes.Equal(hintSelector, credential.HintSelector) {
		return admission.AccessHintCredential{}, errors.New("live first-hop hint tuple mismatch")
	}
	return cloneLiveFirstHopHintCredential(credential), nil
}

type liveFirstHopMultiHintResolver struct {
	credentials []admission.AccessHintCredential
}

type liveFirstHopBlockingHintResolver struct {
	started chan struct{}
	once    sync.Once
}

func (r *liveFirstHopBlockingHintResolver) ResolveAccessHint(ctx context.Context, _, _ []byte, _ uint64, _ []byte) (admission.AccessHintCredential, error) {
	r.once.Do(func() { close(r.started) })
	<-ctx.Done()
	return admission.AccessHintCredential{}, ctx.Err()
}

func (r liveFirstHopMultiHintResolver) ResolveAccessHint(_ context.Context, issuerID, relayBucketID []byte, hintEpochID uint64, hintSelector []byte) (admission.AccessHintCredential, error) {
	for _, credential := range r.credentials {
		if bytes.Equal(issuerID, credential.HintIssuerID) && bytes.Equal(relayBucketID, credential.RelayBucketID) && hintEpochID == credential.HintEpochID && bytes.Equal(hintSelector, credential.HintSelector) {
			return cloneLiveFirstHopHintCredential(credential), nil
		}
	}
	return admission.AccessHintCredential{}, errors.New("live first-hop hint tuple mismatch")
}

func cloneLiveFirstHopHintCredential(credential admission.AccessHintCredential) admission.AccessHintCredential {
	credential.HintIssuerID = append([]byte(nil), credential.HintIssuerID...)
	credential.RelayBucketID = append([]byte(nil), credential.RelayBucketID...)
	credential.HintSelector = append([]byte(nil), credential.HintSelector...)
	credential.HintSecret = append([]byte(nil), credential.HintSecret...)
	return credential
}

type liveFirstHopDurableReplayCache struct {
	*admission.MemoryReplayCache
	err       error
	duplicate bool
}

func (*liveFirstHopDurableReplayCache) Durable() bool { return true }

func (c *liveFirstHopDurableReplayCache) InsertIfAbsent(key []byte) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	if c.duplicate {
		return false, nil
	}
	return c.MemoryReplayCache.InsertIfAbsent(key)
}

type liveFirstHopAdmissionVerifier struct {
	tokenPublicKeyDER []byte
	err               error
}

func (v liveFirstHopAdmissionVerifier) VerifyAdmission(ctx context.Context, proof protocol.AdmissionProof, _ uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.err != nil {
		return v.err
	}
	return admission.VerifyBlindRSA2048(proof, v.tokenPublicKeyDER)
}

type liveFirstHopSigner struct {
	publicKey protocol.PublicKeyRecord
	classical *ecdsa.PrivateKey
	pq        *mldsa65.PrivateKey
}

func (s liveFirstHopSigner) PublicKey() protocol.PublicKeyRecord { return s.publicKey }

func (s liveFirstHopSigner) SignTranscript(ctx context.Context, transcript []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.classical != nil {
		return ecdsa.SignASN1(rand.Reader, s.classical, transcript)
	}
	if s.pq != nil {
		signature := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(s.pq, transcript, nil, false, signature); err != nil {
			return nil, err
		}
		return signature, nil
	}
	return nil, errors.New("live first-hop signer has no key")
}

type liveFirstHopPolicySelector struct{ err error }

func (s liveFirstHopPolicySelector) SelectPolicy(ctx context.Context, offer protocol.PolicyOffer, _ protocol.ClientTransportHints) (protocol.PolicyAccept, error) {
	if err := ctx.Err(); err != nil {
		return protocol.PolicyAccept{}, err
	}
	if s.err != nil {
		return protocol.PolicyAccept{}, s.err
	}
	return protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             offer.OfferedSuites[0],
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            offer.RequestedPolicyID,
		SelectedRouteModeID:       offer.RequestedRouteModeID,
		SelectedShape:             offer.RequestedShapeID,
		SelectedTunnelPersonality: offer.TunnelPersonalityOffers[0],
	}, nil
}

func liveFirstHopSessionLimits() session.Limits {
	return session.Limits{MaxQueuedPackets: 32, MaxQueuedBytes: 256 << 10, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 1024}
}

func generateLiveFirstHopECDSA(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func liveFirstHopECDSAPublicRecord(t testing.TB, key *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	t.Helper()
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA384DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: encoded}
}

func marshalLiveFirstHopRSAPSSPublicKey(key *rsa.PublicKey) ([]byte, error) {
	rsaKey, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
		},
		SubjectPublicKey: asn1.BitString{Bytes: rsaKey, BitLength: len(rsaKey) * 8},
	})
}

func randomLiveFirstHopBytes(t testing.TB, length int) []byte {
	t.Helper()
	value, err := randomLiveFirstHopBytesResult(length)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func randomLiveFirstHopBytesResult(length int) ([]byte, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}
