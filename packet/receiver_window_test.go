package packet

import (
	"math/rand"
	"strings"
	"testing"
)

// referenceReplayWindow is the unbounded map model the ring bitmap replaces. It
// exists so the bitmap can be proven to accept and reject exactly the same
// packet numbers.
type referenceReplayWindow struct {
	windowSize uint64
	seen       map[uint64]struct{}
	highest    uint64
	have       bool
}

func newReferenceReplayWindow(windowSize uint64) *referenceReplayWindow {
	return &referenceReplayWindow{windowSize: windowSize, seen: make(map[uint64]struct{})}
}

func (m *referenceReplayWindow) verdict(packetNumber uint64) string {
	if _, ok := m.seen[packetNumber]; ok {
		return "duplicate"
	}
	if m.have && m.highest >= m.windowSize && packetNumber < m.highest-m.windowSize {
		return "outside"
	}
	return "accept"
}

func (m *referenceReplayWindow) mark(packetNumber uint64) {
	m.seen[packetNumber] = struct{}{}
	if !m.have || packetNumber > m.highest {
		m.highest = packetNumber
		m.have = true
	}
	if m.highest < m.windowSize {
		return
	}
	cutoff := m.highest - m.windowSize
	for seen := range m.seen {
		if seen < cutoff {
			delete(m.seen, seen)
		}
	}
}

func receiverVerdict(t *testing.T, r *Receiver, space receiverPacketNumberSpace, packetNumber uint64) string {
	t.Helper()
	key := receiverPacketNumberKey{Space: space, PacketNumber: packetNumber}
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.checkPacketNumberKeyLocked(key)
	switch {
	case err == nil:
		r.markPacketNumberKeyLocked(key)
		return "accept"
	case strings.Contains(err.Error(), "duplicate"):
		return "duplicate"
	case strings.Contains(err.Error(), "outside receiver window"):
		return "outside"
	default:
		t.Fatalf("unexpected replay verdict error: %v", err)
		return ""
	}
}

func TestReceiverReplayWindowMatchesUnboundedModel(t *testing.T) {
	for _, windowSize := range []uint64{1, 2, 63, 64, 65, 127, 128, 1024} {
		receiver := NewReceiver(ReceiverConfig{WindowSize: windowSize})
		model := newReferenceReplayWindow(windowSize)
		space := receiverPacketNumberSpace{RouteInstanceID: 9, HopLayer: 1}
		random := rand.New(rand.NewSource(int64(windowSize) + 1))

		highest := uint64(0)
		for step := 0; step < 20000; step++ {
			var packetNumber uint64
			switch random.Intn(10) {
			case 0, 1, 2, 3, 4:
				// Sequential arrival.
				packetNumber = highest + 1
			case 5, 6:
				// Reordered arrival inside or just outside the window.
				back := uint64(random.Int63n(int64(windowSize) + 3))
				if back <= highest {
					packetNumber = highest - back
				}
			case 7:
				// Exact window edges.
				if highest >= windowSize {
					packetNumber = highest - windowSize
				}
			case 8:
				// Forward gap smaller than the window.
				packetNumber = highest + 1 + uint64(random.Int63n(int64(windowSize)+1))
			default:
				// Forward jump past the whole window.
				packetNumber = highest + windowSize + 1 + uint64(random.Int63n(1000))
			}

			want := model.verdict(packetNumber)
			got := receiverVerdict(t, receiver, space, packetNumber)
			if got != want {
				t.Fatalf("window=%d step=%d packet=%d highest=%d: verdict %q, want %q",
					windowSize, step, packetNumber, highest, got, want)
			}
			if want == "accept" {
				model.mark(packetNumber)
				if packetNumber > highest {
					highest = packetNumber
				}
			}
			if stats := receiver.Stats(); stats.SeenPackets != len(model.seen) {
				t.Fatalf("window=%d step=%d: tracked %d packets, model tracks %d",
					windowSize, step, stats.SeenPackets, len(model.seen))
			}
		}
	}
}

func TestReceiverReplayWindowRejectsRingAliasedPacketNumber(t *testing.T) {
	const windowSize = 64
	receiver := NewReceiver(ReceiverConfig{WindowSize: windowSize})
	space := receiverPacketNumberSpace{RouteInstanceID: 3, HopLayer: 1}

	if got := receiverVerdict(t, receiver, space, 5); got != "accept" {
		t.Fatalf("first packet verdict %q", got)
	}
	// 5 and 5+windowSize+1 share a ring slot; the older number must be reported
	// as outside the window rather than as a duplicate or a fresh packet.
	if got := receiverVerdict(t, receiver, space, 5+windowSize+1); got != "accept" {
		t.Fatalf("advancing packet verdict %q", got)
	}
	if got := receiverVerdict(t, receiver, space, 5); got != "outside" {
		t.Fatalf("ring-aliased packet verdict %q, want outside", got)
	}
	if got := receiverVerdict(t, receiver, space, 6); got != "accept" {
		t.Fatalf("in-window packet verdict %q", got)
	}
}

func TestReceiverReplayWindowForwardJumpClearsHistory(t *testing.T) {
	const windowSize = 128
	receiver := NewReceiver(ReceiverConfig{WindowSize: windowSize})
	space := receiverPacketNumberSpace{RouteInstanceID: 4, HopLayer: 1}

	for packetNumber := uint64(0); packetNumber < 64; packetNumber++ {
		if got := receiverVerdict(t, receiver, space, packetNumber); got != "accept" {
			t.Fatalf("packet %d verdict %q", packetNumber, got)
		}
	}
	if got := receiverVerdict(t, receiver, space, 1_000_000); got != "accept" {
		t.Fatalf("jump verdict %q", got)
	}
	if stats := receiver.Stats(); stats.SeenPackets != 1 {
		t.Fatalf("jump retained %d packets, want 1", stats.SeenPackets)
	}
	for packetNumber := uint64(0); packetNumber < 64; packetNumber++ {
		if got := receiverVerdict(t, receiver, space, packetNumber); got != "outside" {
			t.Fatalf("stale packet %d verdict %q, want outside", packetNumber, got)
		}
	}
	if got := receiverVerdict(t, receiver, space, 1_000_000-windowSize); got != "accept" {
		t.Fatalf("window-edge packet verdict %q", got)
	}
	if got := receiverVerdict(t, receiver, space, 1_000_000-windowSize-1); got != "outside" {
		t.Fatalf("packet past window edge verdict %q, want outside", got)
	}
}

func TestReceiverReplayWindowIsBoundedPerPacketNumberSpace(t *testing.T) {
	receiver := NewReceiver(ReceiverConfig{WindowSize: 1024})
	space := receiverPacketNumberSpace{RouteInstanceID: 5, HopLayer: 1}
	for packetNumber := uint64(0); packetNumber < 100_000; packetNumber++ {
		if got := receiverVerdict(t, receiver, space, packetNumber); got != "accept" {
			t.Fatalf("packet %d verdict %q", packetNumber, got)
		}
	}
	receiver.mu.Lock()
	words := len(receiver.windows[space].bits)
	receiver.mu.Unlock()
	if want := (1024 + 1 + 63) / 64; words != want {
		t.Fatalf("replay window uses %d words, want %d", words, want)
	}
	if stats := receiver.Stats(); stats.SeenPackets != 1025 {
		t.Fatalf("replay window tracks %d packets, want 1025", stats.SeenPackets)
	}
}

func TestReceiverClampsOversizedWindow(t *testing.T) {
	receiver := NewReceiver(ReceiverConfig{WindowSize: MaxReceiverWindowSize + 1})
	if receiver.windowSize != MaxReceiverWindowSize {
		t.Fatalf("window size %d, want %d", receiver.windowSize, MaxReceiverWindowSize)
	}
	space := receiverPacketNumberSpace{RouteInstanceID: 6, HopLayer: 1}
	if got := receiverVerdict(t, receiver, space, MaxReceiverWindowSize+10); got != "accept" {
		t.Fatalf("first packet verdict %q", got)
	}
	if got := receiverVerdict(t, receiver, space, 9); got != "outside" {
		t.Fatalf("packet outside clamped window verdict %q, want outside", got)
	}
}

func TestReceiverForgetPacketNumberSpaceKeepsOtherSpaces(t *testing.T) {
	receiver := NewReceiver(ReceiverConfig{WindowSize: 64})
	kept := receiverPacketNumberSpace{RouteInstanceID: 7, HopLayer: 1, KeyPhase: 0}
	dropped := receiverPacketNumberSpace{RouteInstanceID: 7, HopLayer: 1, KeyPhase: 1}
	for _, space := range []receiverPacketNumberSpace{kept, dropped} {
		for packetNumber := uint64(0); packetNumber < 4; packetNumber++ {
			if got := receiverVerdict(t, receiver, space, packetNumber); got != "accept" {
				t.Fatalf("packet %d verdict %q", packetNumber, got)
			}
		}
	}
	if stats := receiver.Stats(); stats.PacketNumberSpaces != 2 || stats.SeenPackets != 8 {
		t.Fatalf("stats %+v, want 2 spaces and 8 packets", stats)
	}
	receiver.ForgetPacketNumberSpace(dropped.RouteInstanceID, dropped.HopLayer, dropped.Direction, dropped.KeyPhase)
	if stats := receiver.Stats(); stats.PacketNumberSpaces != 1 || stats.SeenPackets != 4 {
		t.Fatalf("stats after forget %+v, want 1 space and 4 packets", stats)
	}
	if got := receiverVerdict(t, receiver, kept, 0); got != "duplicate" {
		t.Fatalf("retained space verdict %q, want duplicate", got)
	}
	if got := receiverVerdict(t, receiver, dropped, 0); got != "accept" {
		t.Fatalf("forgotten space verdict %q, want accept", got)
	}
}

func TestReceiverFailsClosedAfterDestroy(t *testing.T) {
	receiver := NewReceiver(ReceiverConfig{WindowSize: 64})
	space := receiverPacketNumberSpace{RouteInstanceID: 8, HopLayer: 1}
	if got := receiverVerdict(t, receiver, space, 1); got != "accept" {
		t.Fatalf("first packet verdict %q", got)
	}
	receiver.Destroy()
	if stats := receiver.Stats(); stats.PacketNumberSpaces != 0 || stats.SeenPackets != 0 {
		t.Fatalf("destroyed receiver stats %+v, want zero", stats)
	}
	receiver.mu.Lock()
	err := receiver.checkPacketNumberKeyLocked(receiverPacketNumberKey{Space: space, PacketNumber: 2})
	receiver.mu.Unlock()
	if err == nil {
		t.Fatalf("destroyed receiver accepted a packet number")
	}
	prepared := PreparedOpen{owner: receiver, valid: true}
	if err := receiver.CommitPreparedOpen(&prepared); err == nil {
		t.Fatalf("destroyed receiver committed a prepared open")
	}
	// A forgotten space on a destroyed receiver must not panic.
	receiver.ForgetPacketNumberSpace(space.RouteInstanceID, space.HopLayer, space.Direction, space.KeyPhase)
}

func BenchmarkReceiverReplayWindowSequential1024(b *testing.B) {
	benchmarkReceiverReplayWindow(b, 1024)
}

func BenchmarkReceiverReplayWindowSequentialMax(b *testing.B) {
	benchmarkReceiverReplayWindow(b, MaxReceiverWindowSize)
}

func benchmarkReceiverReplayWindow(b *testing.B, windowSize uint64) {
	b.Helper()
	receiver := NewReceiver(ReceiverConfig{WindowSize: windowSize})
	space := receiverPacketNumberSpace{RouteInstanceID: 0x42, HopLayer: 1}
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	for packetNumber := uint64(0); packetNumber <= windowSize; packetNumber++ {
		receiver.markPacketNumberKeyLocked(receiverPacketNumberKey{Space: space, PacketNumber: packetNumber})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := receiverPacketNumberKey{Space: space, PacketNumber: windowSize + 1 + uint64(i)}
		if err := receiver.checkPacketNumberKeyLocked(key); err != nil {
			b.Fatal(err)
		}
		receiver.markPacketNumberKeyLocked(key)
	}
}
