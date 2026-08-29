package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
)

func TestPacketTUNRuntimeWritesSyntheticAndRelayPackets(t *testing.T) {
	runtime, clientApplication, relayApplication, device := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()

	result := make(chan error, 1)
	go func() {
		result <- runtime.Serve(context.Background())
	}()

	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	device.Inject(syn)

	encrypted := nextPacketTUNRuntime(t, clientApplication)
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen {
		t.Fatalf("captured SYN frames = %+v", blocks)
	}
	synthetic := device.NextWrite(t)
	syntheticTCP := packetAdapterParseTCPv4(t, synthetic)
	if syntheticTCP.flags != tcpFlagSYN|tcpFlagACK || syntheticTCP.destinationPort != 50000 || syntheticTCP.sourcePort != 443 {
		t.Fatalf("synthetic local packet = %+v", syntheticTCP)
	}
	if extra := device.TryWrite(); extra != nil {
		t.Fatalf("unexpected extra local packet: %x", extra)
	}

	flowID := blocks[0].Frames[0].FlowID
	relayPayload := bytes.Repeat([]byte{0x72}, 2000)
	frame, err := protocol.NewStreamDataFrame(flowID, relayPayload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	var reassembled []byte
	for segmentIndex := 0; segmentIndex < 2; segmentIndex++ {
		encoded := device.NextWrite(t)
		if len(encoded) > 1500 {
			t.Fatalf("relay segment %d length = %d, want at most 1500", segmentIndex, len(encoded))
		}
		response := packetAdapterParseTCPv4(t, encoded)
		if response.flags != tcpFlagACK|tcpFlagPSH {
			t.Fatalf("relay segment %d TCP state = %+v", segmentIndex, response)
		}
		reassembled = append(reassembled, response.payload...)
	}
	if !bytes.Equal(reassembled, relayPayload) {
		t.Fatalf("reassembled relay payload length = %d, want %d", len(reassembled), len(relayPayload))
	}
	if extra := device.TryWrite(); extra != nil {
		t.Fatalf("unexpected extra relay segment: %x", extra)
	}

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("packet TUN runtime stopped without a terminal device error")
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not stop after close")
	}
}

func TestPacketTUNRuntimeRejectsShortDeviceWrites(t *testing.T) {
	runtime, clientApplication, relayApplication, device := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	device.shortWrites = true

	result := make(chan error, 1)
	go func() {
		result <- runtime.Serve(context.Background())
	}()
	device.Inject(packetAdapterTCPv4(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil))

	select {
	case err := <-result:
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short device write error = %v, want %v", err, io.ErrShortWrite)
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not fail on a short device write")
	}
}

func TestPacketTUNRuntimeCloseUnblocksRead(t *testing.T) {
	runtime, clientApplication, relayApplication, device := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()

	result := make(chan error, 1)
	go func() {
		result <- runtime.Serve(context.Background())
	}()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("packet TUN runtime stopped without a terminal device error")
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not stop after close")
	}
	if !device.Closed() {
		t.Fatal("packet device remained open after runtime close")
	}
}

func TestPacketTUNRuntimeCloseClearsAdapterPacketBuffers(t *testing.T) {
	runtime, clientApplication, relayApplication, _ := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()

	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := runtime.adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("ingress TCP SYN: %v", err)
	}
	if len(runtime.adapter.localPackets) != 1 {
		t.Fatalf("queued local packets = %d, want 1", len(runtime.adapter.localPackets))
	}
	queued := runtime.adapter.localPackets[0]

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runtime.adapter.localPackets) != 0 || !bytes.Equal(queued, make([]byte, len(queued))) {
		t.Fatal("runtime close did not clear adapter packet buffers")
	}
	if err := runtime.adapter.Ingress(context.Background(), syn, now); !errors.Is(err, ErrPacketAdapterClosed) {
		t.Fatalf("adapter ingress after runtime close = %v, want %v", err, ErrPacketAdapterClosed)
	}
}

func TestPacketTUNRuntimeCloseUnblocksWrite(t *testing.T) {
	runtime, clientApplication, relayApplication, device := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	device.writeStarted = make(chan struct{}, 1)
	device.allowWrite = make(chan struct{})

	result := make(chan error, 1)
	go func() {
		result <- runtime.Serve(context.Background())
	}()
	device.Inject(packetAdapterTCPv4(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil))
	select {
	case <-device.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not begin a device write")
	}

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- runtime.Close()
	}()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("close packet TUN runtime: %v", err)
		}
	case <-time.After(time.Second):
		close(device.allowWrite)
		<-closeResult
		t.Fatal("packet TUN runtime close did not unblock a device write")
	}
	if !device.Closed() {
		t.Fatal("packet device remained open while a device write was blocked")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("packet TUN runtime stopped without a terminal device error")
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not stop after closing a blocked device write")
	}
}

func TestPacketTUNRuntimeCanceledFrameHandlingClosesBlockedDeviceWrite(t *testing.T) {
	runtime, clientApplication, relayApplication, device := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	defer runtime.Close()

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- runtime.Serve(context.Background())
	}()
	device.Inject(packetAdapterTCPv4(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil))

	blocks, err := relayApplication.HandlePacket(context.Background(), time.Unix(1_700_000_000, 0), nextPacketTUNRuntime(t, clientApplication))
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen {
		t.Fatalf("captured SYN frames = %+v", blocks)
	}
	_ = device.NextWrite(t)

	frame, err := protocol.NewStreamDataFrame(blocks[0].Frames[0].FlowID, []byte("response"), 0)
	if err != nil {
		t.Fatal(err)
	}
	device.writeStarted = make(chan struct{}, 1)
	device.allowWrite = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handleResult := make(chan error, 1)
	go func() {
		handleResult <- runtime.HandleFrameBlock(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
	}()
	select {
	case <-device.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not begin a relay device write")
	}

	cancel()
	select {
	case err := <-handleResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HandleFrameBlock cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		_ = runtime.Close()
		<-handleResult
		t.Fatal("packet TUN frame handling did not stop after cancellation")
	}
	if !device.Closed() {
		t.Fatal("packet device remained open after canceled frame handling")
	}
	select {
	case err := <-serveResult:
		if err == nil {
			t.Fatal("packet TUN runtime stopped without a terminal device error")
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not stop after canceled frame handling")
	}
}

func TestPacketTUNRuntimeDropsUnsupportedProtocolPackets(t *testing.T) {
	runtime, clientApplication, relayApplication, device := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()

	result := make(chan error, 1)
	go func() {
		result <- runtime.Serve(context.Background())
	}()

	// A well-formed ICMP echo must be dropped without terminating the read loop.
	device.Inject(packetAdapterICMPv4Echo(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}))
	// Prove the loop survived by capturing a TCP SYN opened afterwards.
	device.Inject(packetAdapterTCPv4(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil))

	encrypted := nextPacketTUNRuntime(t, clientApplication)
	blocks, err := relayApplication.HandlePacket(context.Background(), time.Unix(1_700_000_000, 0), encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen {
		t.Fatalf("SYN after dropped ICMP frames = %+v, want one flow open", blocks)
	}
	synthetic := packetAdapterParseTCPv4(t, device.NextWrite(t))
	if synthetic.flags != tcpFlagSYN|tcpFlagACK {
		t.Fatalf("synthetic local packet after dropped ICMP = %+v, want SYN/ACK", synthetic)
	}
	select {
	case err := <-result:
		t.Fatalf("packet TUN runtime terminated on an unsupported-protocol packet: %v", err)
	default:
	}

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("packet TUN runtime stopped without a terminal device error")
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not stop after close")
	}
}

func TestPacketTUNRuntimeTerminatesOnMalformedPacket(t *testing.T) {
	runtime, clientApplication, relayApplication, device := packetTUNRuntimeFixture(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	defer runtime.Close()

	result := make(chan error, 1)
	go func() {
		result <- runtime.Serve(context.Background())
	}()
	malformed := packetAdapterICMPv4Echo(t, [4]byte{10, 77, 0, 2}, [4]byte{93, 184, 216, 34})
	malformed[10] ^= 0xff // corrupt the IPv4 header checksum
	device.Inject(malformed)

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("packet TUN runtime survived a malformed local packet")
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not fail on a malformed local packet")
	}
}

func TestPacketTUNRuntimeSurvivesQueueBackpressure(t *testing.T) {
	// Custom fixture: the shared one seeds only 32 random bytes, too few for
	// seven synthetic server sequences.
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(make([]byte, 512)),
	})
	if err != nil {
		t.Fatal(err)
	}
	device := newPacketTUNRuntimeDevice()
	runtime, err := NewPacketTUNRuntime(adapter, device, PacketTUNRuntimeOptions{
		ReadBufferBytes: 1500,
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		result <- runtime.Serve(context.Background())
	}()

	// Fill the session's bounded outbound queue (six data packets: MaxQueuedPackets
	// 8 minus ControlReservedPackets 2). Each SYN/ACK device write proves the loop
	// finished processing that packet.
	source := [4]byte{10, 77, 0, 2}
	target := [4]byte{93, 184, 216, 34}
	for port := uint16(50000); port < 50006; port++ {
		device.Inject(packetAdapterTCPv4(t, source, target, port, 443, 100, 0, tcpFlagSYN, nil))
		device.NextWrite(t)
	}
	// The seventh SYN hits session.ErrBackpressure: it must be dropped, not
	// terminate the read loop. The queue is still full at this point (nothing
	// has drained it), so the drop is deterministic; the negative wait gives the
	// loop a chance to report a pre-fix terminal error.
	device.Inject(packetAdapterTCPv4(t, source, target, 50006, 443, 100, 0, tcpFlagSYN, nil))
	select {
	case err := <-result:
		t.Fatalf("packet TUN runtime terminated on transient queue backpressure: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Drain the queue, then prove the loop survived: a retransmitted SYN is
	// captured and answered.
	for drained := 0; drained < 6; drained++ {
		nextPacketTUNRuntime(t, clientApplication)
	}
	device.Inject(packetAdapterTCPv4(t, source, target, 50006, 443, 100, 0, tcpFlagSYN, nil))
	synthetic := packetAdapterParseTCPv4(t, device.NextWrite(t))
	if synthetic.flags != tcpFlagSYN|tcpFlagACK {
		t.Fatalf("synthetic packet after backpressure = %+v, want SYN/ACK", synthetic)
	}
	nextPacketTUNRuntime(t, clientApplication)

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("packet TUN runtime stopped without a terminal device error")
		}
	case <-time.After(time.Second):
		t.Fatal("packet TUN runtime did not stop after close")
	}
}

func TestPacketTUNRuntimeRejectsInvalidConfiguration(t *testing.T) {
	application, relayApplication := packetAdapterApplications(t)
	defer application.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{
		MaxFlows:       1,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x75}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	device := newPacketTUNRuntimeDevice()
	for name, options := range map[string]PacketTUNRuntimeOptions{
		"small buffer": {ReadBufferBytes: 127},
		"large buffer": {ReadBufferBytes: 65536},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPacketTUNRuntime(adapter, device, options); err == nil {
				t.Fatal("invalid packet TUN runtime configuration was accepted")
			}
		})
	}
	if _, err := NewPacketTUNRuntime(nil, device, PacketTUNRuntimeOptions{ReadBufferBytes: 1500}); err == nil {
		t.Fatal("nil packet adapter was accepted")
	}
	if _, err := NewPacketTUNRuntime(adapter, nil, PacketTUNRuntimeOptions{ReadBufferBytes: 1500}); err == nil {
		t.Fatal("nil packet device was accepted")
	}
}

func packetTUNRuntimeFixture(t *testing.T) (*PacketTUNRuntime, *session.Application, *session.Application, *packetTUNRuntimeDevice) {
	t.Helper()
	clientApplication, relayApplication := packetAdapterApplications(t)
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x74}, 32)),
	})
	if err != nil {
		clientApplication.Close()
		relayApplication.Close()
		t.Fatal(err)
	}
	device := newPacketTUNRuntimeDevice()
	runtime, err := NewPacketTUNRuntime(adapter, device, PacketTUNRuntimeOptions{
		ReadBufferBytes: 1500,
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		clientApplication.Close()
		relayApplication.Close()
		t.Fatal(err)
	}
	return runtime, clientApplication, relayApplication, device
}

func nextPacketTUNRuntime(t *testing.T, application *session.Application) []byte {
	t.Helper()
	result := make(chan struct {
		packet []byte
		err    error
	}, 1)
	go func() {
		packet, err := application.NextPacket(context.Background())
		result <- struct {
			packet []byte
			err    error
		}{packet: packet, err: err}
	}()
	select {
	case received := <-result:
		if received.err != nil {
			t.Fatal(received.err)
		}
		return received.packet
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet adapter output")
		return nil
	}
}

type packetTUNRuntimeDevice struct {
	reads        chan []byte
	writes       chan []byte
	closed       chan struct{}
	closeOnce    sync.Once
	shortWrites  bool
	writeStarted chan struct{}
	allowWrite   chan struct{}
}

func newPacketTUNRuntimeDevice() *packetTUNRuntimeDevice {
	return &packetTUNRuntimeDevice{
		reads:  make(chan []byte, 1),
		writes: make(chan []byte, 8),
		closed: make(chan struct{}),
	}
}

func (d *packetTUNRuntimeDevice) Read(packet []byte) (int, error) {
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

func (d *packetTUNRuntimeDevice) Write(packet []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	copied := append([]byte(nil), packet...)
	if d.shortWrites {
		if len(copied) == 0 {
			return 0, nil
		}
		return len(copied) - 1, nil
	}
	if d.writeStarted != nil {
		select {
		case d.writeStarted <- struct{}{}:
		default:
		}
		select {
		case <-d.allowWrite:
			return len(copied), nil
		case <-d.closed:
			return 0, io.ErrClosedPipe
		}
	}
	select {
	case d.writes <- copied:
		return len(copied), nil
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *packetTUNRuntimeDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}

func (d *packetTUNRuntimeDevice) Inject(packet []byte) {
	d.reads <- append([]byte(nil), packet...)
}

func (d *packetTUNRuntimeDevice) NextWrite(t *testing.T) []byte {
	t.Helper()
	select {
	case packet := <-d.writes:
		return packet
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet device write")
		return nil
	}
}

func (d *packetTUNRuntimeDevice) TryWrite() []byte {
	select {
	case packet := <-d.writes:
		return packet
	default:
		return nil
	}
}

func (d *packetTUNRuntimeDevice) Closed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

var _ io.ReadWriteCloser = (*packetTUNRuntimeDevice)(nil)
