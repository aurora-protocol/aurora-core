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
	frame, err := protocol.NewStreamDataFrame(flowID, []byte("response"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	response := packetAdapterParseTCPv4(t, device.NextWrite(t))
	if response.flags != tcpFlagACK|tcpFlagPSH || !bytes.Equal(response.payload, []byte("response")) {
		t.Fatalf("relay local packet = %+v", response)
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
	reads       chan []byte
	writes      chan []byte
	closed      chan struct{}
	closeOnce   sync.Once
	shortWrites bool
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
