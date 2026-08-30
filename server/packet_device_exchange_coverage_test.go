package server

// Adversarial coverage for the deterministic error/edge branches of the
// device packet exchanger (server/packet_device_exchange.go).
//
// NewDevicePacketExchanger spawns a background readDevice goroutine, so most
// of the file's branches run on or against that goroutine and need an io.Pipe
// harness to exercise safely. THIS file deliberately covers only the branches
// reachable WITHOUT spawning the read goroutine — the constructor validation
// (which returns before the goroutine is started), the nil-receiver guards,
// and the two pure helpers. That keeps the coverage deterministic (no
// goroutine, no channel, no io.Pipe, no race surface) so it cannot flake the
// production-evidence race/fuzz gate.
//
// Targets covered here:
//   - NewDevicePacketExchanger 35: nil-device guard.
//   - NewDevicePacketExchanger 42: MTU-out-of-range guard (returns before the
//     goroutine is started, so the device is never read).
//   - NewDevicePacketExchanger 49: queue-size-out-of-range guard (likewise
//     returns before the goroutine; MTU must be valid so the queue check is
//     the one that fires).
//   - ExchangePacketBatch 65: nil-receiver guard.
//   - Close 103: nil-receiver guard.
//   - writeFullPacket 249: a writer that returns (0, nil) surfaces as
//     io.ErrShortWrite (n==0 with no error).
//   - packetProtocolNumber 257: an empty packet maps to protocol 0.
//
// Out-of-scope (deferred to a dedicated concurrency-coverage PR, NOT
// dead-by-design): 39, 46, 69, 73, 83, 87, 91, 139, 147, 158, 178, 191, 196,
// 217 — these require a live readDevice goroutine plus an io.Pipe-style
// blocking device (the closed-exchanger guards, the MTU-exceeds path, the
// read-error propagation, and the outbound-queue eviction paths). The
// exchanger is mutex-guarded so the race risk is low, but it is kept separate
// so this PR stays reliably green.
//
// No dead-by-design blocks in the seven targets. Coverage is re-measured per
// target to confirm the intended branch moved (no wrong-branch bugs). The
// two local fakes (noopReadWriteCloser, shortWriteWriter) carry compile-time
// interface assertions plus test usage, so there is nothing for staticcheck
// U1000 to flag. No context.Context, no goroutines, no real network or
// filesystem.

import (
	"io"
	"strings"
	"testing"
)

// noopReadWriteCloser is a benign device used only in constructor-validation
// cases that return before the read goroutine starts, so its Read/Write/Close
// are never invoked. It is nonetheless well-formed so a future caller could
// not mistake it for the cause of a failure.
type noopReadWriteCloser struct{}

func (noopReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (noopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (noopReadWriteCloser) Close() error                { return nil }

var _ io.ReadWriteCloser = noopReadWriteCloser{}

// shortWriteWriter returns (0, nil) from every Write, driving writeFullPacket
// into its n==0 short-write branch.
type shortWriteWriter struct{}

func (shortWriteWriter) Write([]byte) (int, error) { return 0, nil }

var _ io.Writer = shortWriteWriter{}

func TestNewDevicePacketExchangerValidation(t *testing.T) {
	cases := []struct {
		name   string
		device io.ReadWriteCloser
		opts   DevicePacketExchangerOptions
		want   string
	}{
		{"nil device", nil, DevicePacketExchangerOptions{}, "packet device is required"},
		{"mtu exceeds max", noopReadWriteCloser{}, DevicePacketExchangerOptions{MTU: maxPacketBytes + 1}, "MTU"},
		{"queue exceeds max", noopReadWriteCloser{}, DevicePacketExchangerOptions{MTU: defaultDevicePacketMTU, QueuePackets: maxPacketBatchPackets + 1}, "queue size"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ex, err := NewDevicePacketExchanger(c.device, c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("NewDevicePacketExchanger err = %v, want substring %q", err, c.want)
			}
			if ex != nil {
				// A validation failure must not return a half-built exchanger
				// (which would leak a goroutine). nil is the only safe result.
				t.Fatalf("NewDevicePacketExchanger returned non-nil exchanger on validation failure")
			}
		})
	}
}

func TestDevicePacketExchangerNilReceivers(t *testing.T) {
	// ExchangePacketBatch on a nil receiver short-circuits at 65.
	var ex *DevicePacketExchanger
	if _, err := ex.ExchangePacketBatch(PacketBatch{}); err == nil || !strings.Contains(err.Error(), "packet exchanger is nil") {
		t.Fatalf("nil ExchangePacketBatch err = %v, want packet exchanger is nil", err)
	}
	// Close on a nil receiver is a no-op returning nil (103).
	if err := ex.Close(); err != nil {
		t.Fatalf("nil Close err = %v, want nil", err)
	}
}

func TestWriteFullPacketShortWrite(t *testing.T) {
	// A writer returning (0, nil) must surface as io.ErrShortWrite at the
	// n==0 branch (249), not as a silent zero-length "success".
	if err := writeFullPacket(shortWriteWriter{}, []byte{0x45, 0x01}); err != io.ErrShortWrite {
		t.Fatalf("writeFullPacket(shortWriteWriter) err = %v, want io.ErrShortWrite", err)
	}
	// Anchor: a writer that accepts all bytes returns nil, proving 249 fires
	// because of the zero-length write and not because of the packet shape.
	if err := writeFullPacket(io.Discard, []byte{0x45, 0x01}); err != nil {
		t.Fatalf("writeFullPacket(io.Discard) err = %v, want nil", err)
	}
}

func TestPacketProtocolNumberEmpty(t *testing.T) {
	// An empty packet maps to protocol 0 at the len==0 guard (257).
	if packetFamilyIPv4 != 2 || packetFamilyIPv6 != 30 {
		t.Fatalf("packet family constants = %d/%d, want 2/30", packetFamilyIPv4, packetFamilyIPv6)
	}
	if got := packetProtocolNumber([]byte{}); got != 0 {
		t.Fatalf("packetProtocolNumber([]) = %d, want 0", got)
	}
	// Anchors: the IPv4/IPv6/default branches still classify correctly, so
	// the empty case above is the len==0 guard and not a misread nibble.
	cases := []struct {
		packet []byte
		want   uint16
	}{
		{[]byte{0x45, 0x00}, packetFamilyIPv4},
		{[]byte{0x60, 0x00}, packetFamilyIPv6},
		{[]byte{0x10, 0x00}, 0}, // nibble 1 -> default
	}
	for _, c := range cases {
		if got := packetProtocolNumber(c.packet); got != c.want {
			t.Fatalf("packetProtocolNumber(% x) = %d, want %d", c.packet, got, c.want)
		}
	}
}
