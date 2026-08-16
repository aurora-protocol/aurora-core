package server

// Adversarial coverage for the concurrent code paths of the device packet
// exchanger (server/packet_device_exchange.go) that the deterministic
// coverage file (#79) could not reach because they require a live readDevice
// goroutine.
//
// This file uses a blocking-device harness: Read blocks until Close, so the
// readDevice goroutine parks without ever delivering a read or setting a read
// error. That keeps ExchangePacketBatch's readError() checks returning nil and
// lets the test drive the batch path deterministically while the goroutine is
// parked — no racing, no timing, no flake surface.
//
// Targets covered here (all reached with the goroutine parked):
//   - NewDevicePacketExchanger 39, 46: the MTU and queue-size default
//     assignments, reached by constructing with zero-valued options. The
//     test asserts the defaults actually took effect (mtu == 1280,
//     outbound cap == 64) so the lines are exercised, not just bypassed.
//   - ExchangePacketBatch 69: the closed-exchanger guard in the first select,
//     reached by closing the exchanger before calling ExchangePacketBatch.
//   - ExchangePacketBatch 73: the validate-FAILS return (validatePacketBatch
//     returns an error), reached by an invalid batch on a live, non-closed
//     exchanger. A valid batch takes the false branch and does not cover this
//     block; only a batch that fails validation returns here.
//   - ExchangePacketBatch 91: the per-packet MTU-exceeds guard, reached by a
//     packet that passes wire validation (correct IPv4 nibble, matching
//     protocol number, length <= maxPacketBytes) but is longer than the
//     device MTU.
//
// Out of scope / not deterministically coverable (documented, NOT claimed):
//   - 147: setReadError's `if err == nil { return }` is dead-by-design — every
//     production call site (readDevice 123/131/135) passes a non-nil error.
//   - 83, 87: ExchangePacketBatch's second done-select (83) and second
//     readError-non-nil return (87). Both require `done` to close, or a read
//     error to land, during the sub-microsecond window between the first and
//     second checks inside a single ExchangePacketBatch call — if either
//     condition already held at the first check, the call returns there and
//     never reaches the second. Genuine race-window lines.
//   - 139, 158, 178: reachable only when `done` closes during a narrow
//     same-goroutine window — between readDevice's Read-return and its
//     done-select (139), setReadError's second done-select (158), or
//     queueOutbound's start and its done-select (178). Close runs in a
//     different goroutine and the window is sub-microsecond, so these are
//     race-window lines a deterministic test cannot hit without a fragile
//     racing harness; deferred.
//   - 191, 196: queueOutbound eviction-default / post-eviction send-default,
//     reachable only via concurrent drain/produce interleaving; race-window.
//   - 217: drainOutbound's cap-return needs >= maxPacketBatchPackets packets
//     pre-queued with cross-goroutine synchronization; deferred to keep this
//     PR deterministic.
//
// No new goroutines are spawned by the test (only the exchanger's own
// readDevice goroutine, which is the SUT). The single local fake
// (blockingDevice) carries a compile-time interface assertion plus test usage,
// so nothing trips staticcheck U1000. No context.Context, no real network or
// filesystem.

import (
	"io"
	"strings"
	"sync"
	"testing"
)

// blockingDevice parks its Read until Close, so a readDevice goroutine started
// against it never delivers a read (and never sets a read error) while the
// test drives ExchangePacketBatch. Write is non-blocking and counted so a
// success-path anchor can confirm a packet was actually written.
type blockingDevice struct {
	closeCh   chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex
	writes    int
}

func newBlockingDevice() *blockingDevice {
	return &blockingDevice{closeCh: make(chan struct{})}
}

func (d *blockingDevice) Read([]byte) (int, error) {
	<-d.closeCh
	return 0, io.EOF
}

func (d *blockingDevice) Write(p []byte) (int, error) {
	d.writeMu.Lock()
	d.writes++
	d.writeMu.Unlock()
	return len(p), nil
}

func (d *blockingDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closeCh) })
	return nil
}

var _ io.ReadWriteCloser = (*blockingDevice)(nil)

func TestNewDevicePacketExchangerDefaults(t *testing.T) {
	// Constructing with zero-valued options exercises the MTU (39) and
	// queue-size (46) default assignments. Assert the defaults took effect so
	// the lines are exercised, not merely bypassed. The goroutine spawns and
	// parks in Read; Close unblocks and cleans it up.
	dev := newBlockingDevice()
	e, err := NewDevicePacketExchanger(dev, DevicePacketExchangerOptions{})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger err = %v, want nil", err)
	}
	if e == nil {
		t.Fatal("NewDevicePacketExchanger returned nil exchanger on success")
	}
	if e.mtu != defaultDevicePacketMTU {
		t.Fatalf("default mtu = %d, want %d", e.mtu, defaultDevicePacketMTU)
	}
	if cap(e.outbound) != defaultDevicePacketQueuePackets {
		t.Fatalf("default queue cap = %d, want %d", cap(e.outbound), defaultDevicePacketQueuePackets)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close err = %v, want nil", err)
	}
}

func TestExchangePacketBatchMTUExceeds(t *testing.T) {
	// A packet that passes wire validation (length <= maxPacketBytes, valid
	// IPv4 first nibble, matching protocol number) but exceeds the device MTU
	// reaches the readError check (76), the write loop (90), and the per-packet
	// MTU guard (91), which returns before any write. validatePacketBatch
	// itself returns nil here (the packet is wire-valid); the validate-FAILS
	// return is covered separately below.
	dev := newBlockingDevice()
	e, err := NewDevicePacketExchanger(dev, DevicePacketExchangerOptions{MTU: 8, QueuePackets: 4})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger err = %v, want nil", err)
	}
	defer e.Close()

	big := make([]byte, 16)
	big[0] = 0x45 // IPv4 first nibble -> protocol 2
	_, err = e.ExchangePacketBatch(PacketBatch{Packets: [][]byte{big}, ProtocolNumbers: []uint16{2}})
	if err == nil || !strings.Contains(err.Error(), "exceeds device MTU") {
		t.Fatalf("ExchangePacketBatch(big) err = %v, want substring \"exceeds device MTU\"", err)
	}
}

func TestExchangePacketBatchInvalidBatch(t *testing.T) {
	// A batch that fails wire validation (here a packet/protocol count
	// mismatch) reaches validatePacketBatch and returns from its error branch
	// (73) before the readError check, the write loop, or any device I/O.
	dev := newBlockingDevice()
	e, err := NewDevicePacketExchanger(dev, DevicePacketExchangerOptions{MTU: 8, QueuePackets: 4})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger err = %v, want nil", err)
	}
	defer e.Close()

	_, err = e.ExchangePacketBatch(PacketBatch{Packets: [][]byte{{0x45}}, ProtocolNumbers: nil})
	if err == nil || !strings.Contains(err.Error(), "count mismatch") {
		t.Fatalf("ExchangePacketBatch(mismatch) err = %v, want substring \"count mismatch\"", err)
	}
	// No packet should have been written to the device: validation fails first.
	dev.writeMu.Lock()
	writes := dev.writes
	dev.writeMu.Unlock()
	if writes != 0 {
		t.Fatalf("device writes = %d, want 0 (validation must fail before writing)", writes)
	}
}

func TestExchangePacketBatchSuccessAnchor(t *testing.T) {
	// A packet within the MTU exercises the write path (94) and drainOutbound
	// (99). The drained batch is empty because the read goroutine is parked
	// and queued nothing. This anchors the harness so the MTU-exceeds failure
	// above is attributable to the packet length, not the device.
	dev := newBlockingDevice()
	e, err := NewDevicePacketExchanger(dev, DevicePacketExchangerOptions{MTU: 8, QueuePackets: 4})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger err = %v, want nil", err)
	}
	defer e.Close()

	small := []byte{0x45, 0x00} // IPv4, length 2 <= MTU 8, protocol 2
	out, err := e.ExchangePacketBatch(PacketBatch{Packets: [][]byte{small}, ProtocolNumbers: []uint16{2}})
	if err != nil {
		t.Fatalf("ExchangePacketBatch(small) err = %v, want nil", err)
	}
	if len(out.Packets) != 0 {
		t.Fatalf("drained packets = %d, want 0 (read goroutine parked)", len(out.Packets))
	}
	dev.writeMu.Lock()
	writes := dev.writes
	dev.writeMu.Unlock()
	if writes != 1 {
		t.Fatalf("device writes = %d, want 1", writes)
	}
}

func TestExchangePacketBatchClosed(t *testing.T) {
	// After Close, the first select in ExchangePacketBatch sees `done` closed
	// and returns the closed error before validation (69).
	dev := newBlockingDevice()
	e, err := NewDevicePacketExchanger(dev, DevicePacketExchangerOptions{MTU: 8, QueuePackets: 4})
	if err != nil {
		t.Fatalf("NewDevicePacketExchanger err = %v, want nil", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close err = %v, want nil", err)
	}

	_, err = e.ExchangePacketBatch(PacketBatch{})
	if err == nil || !strings.Contains(err.Error(), "packet exchanger is closed") {
		t.Fatalf("ExchangePacketBatch(closed) err = %v, want substring \"packet exchanger is closed\"", err)
	}
}
