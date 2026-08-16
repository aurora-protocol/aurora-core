package server

// Adversarial coverage for server/packet_exchange.go.
//
// The happy paths (EncodePacketBatch/DecodePacketBatch round trip, the
// loopback exchanger cloning a valid batch, validatePacketBatch accepting a
// valid IPv4 batch, the empty-packet and bad-length decode guards, and
// zeroPacketBatch zeroing a populated batch) are already covered by
// server_test.go, packet_exchange_fuzz_test.go, and benchmark_test.go, and
// are not re-asserted here except as anchors.
//
// This file covers the residual count-0 blocks, perturbing exactly one input
// per case so the branch under test is the one that fires:
//
//   - LoopbackPacketExchanger.ExchangePacketBatch 29: validatePacketBatch
//     error propagation (an invalid batch is rejected before the clone).
//   - DecodePacketBatch 68: a crafted buffer whose embedded count exceeds
//     maxPacketBatchPackets (the decoder reads caller-supplied bytes, so the
//     cap is enforceable here, unlike the encoder path).
//   - validatePacketBatchEncoding 94: a packet entry truncated below the
//     6-byte header (protocol + length).
//   - validatePacketBatchEncoding 111: a packet whose first nibble is neither
//     4 nor 6 (packetProtocolNumber returns 0, "not IPv4 or IPv6").
//   - validatePacketBatchEncoding 119: trailing bytes after the final entry
//     (offset != len(data)).
//   - validatePacketBatch 133: Packets/ProtocolNumbers length mismatch.
//   - validatePacketBatch 136: more than maxPacketBatchPackets packets.
//   - validatePacketBatch 140: an empty (zero-length) packet.
//   - validatePacketBatch 143: a packet longer than maxPacketBytes.
//   - zeroPacketBatch 169: the nil-receiver guard.
//
// Dead-by-design (2 blocks, documented not covered):
//   - EncodePacketBatch 39 and 44: the >maxPackets and >maxBytes guards are
//     unreachable because EncodePacketBatch calls validatePacketBatch first
//     (36-38), and validatePacketBatch already enforces both (136, 143). With
//     validatePacketBatch passing, len(batch.Packets) <= maxPacketBatchPackets
//     and every packet <= maxPacketBytes, so both re-checks are always false.
//     They are defense-in-depth against a future change to validatePacketBatch.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). No new package-level helpers are introduced: the test
// reuses the in-package benchmarkPacketBatch fixture and inlines all other
// constructs, so there is nothing for staticcheck U1000 to flag. No
// context.Context, no goroutines, no deprecated APIs.

import (
	"strings"
	"testing"
)

func TestLoopbackPacketExchangerValidation(t *testing.T) {
	// An invalid batch (count mismatch) makes validatePacketBatch return at
	// 133, so the loopback exchanger propagates the error at 29 before cloning.
	ex := LoopbackPacketExchanger{}
	_, err := ex.ExchangePacketBatch(PacketBatch{
		Packets:         [][]byte{nil},
		ProtocolNumbers: []uint16{2, 30},
	})
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("ExchangePacketBatch err = %v, want count mismatch", err)
	}

	// Anchor: a valid batch is cloned without error.
	out, err := ex.ExchangePacketBatch(benchmarkPacketBatch())
	if err != nil {
		t.Fatalf("ExchangePacketBatch valid: %v", err)
	}
	if len(out.Packets) != 1 || len(out.Packets[0]) != len(benchmarkPacketBatch().Packets[0]) {
		t.Fatalf("cloned batch = %+v, want one cloned packet", out)
	}
}

func TestDecodePacketBatchErrorBranches(t *testing.T) {
	// "trailing bytes" needs a validly-encoded batch plus a trailing byte.
	valid, err := EncodePacketBatch(benchmarkPacketBatch())
	if err != nil {
		t.Fatalf("encode anchor batch: %v", err)
	}

	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"count exceeds max", []byte{0x00, 0x41}, "max"},
		{"truncated entry", []byte{0x00, 0x01, 0x00}, "truncated"},
		{"not ipv4 or ipv6", []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00}, "not IPv4 or IPv6"},
		{"trailing bytes", append(append([]byte(nil), valid...), 0xFF), "trailing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodePacketBatch(c.data)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("DecodePacketBatch err = %v, want substring %q", err, c.want)
			}
		})
	}
}

func TestValidatePacketBatchErrorBranches(t *testing.T) {
	cases := []struct {
		name  string
		batch PacketBatch
		want  string
	}{
		{
			"count mismatch",
			PacketBatch{Packets: [][]byte{nil}, ProtocolNumbers: []uint16{2, 30}},
			"mismatch",
		},
		{
			"too many packets",
			PacketBatch{Packets: make([][]byte, maxPacketBatchPackets+1), ProtocolNumbers: make([]uint16, maxPacketBatchPackets+1)},
			"max",
		},
		{
			"empty packet",
			PacketBatch{Packets: [][]byte{{}}, ProtocolNumbers: []uint16{2}},
			"empty",
		},
		{
			"packet exceeds max bytes",
			PacketBatch{Packets: [][]byte{make([]byte, maxPacketBytes+1)}, ProtocolNumbers: []uint16{2}},
			"exceeds",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validatePacketBatch(c.batch)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("validatePacketBatch err = %v, want substring %q", err, c.want)
			}
		})
	}
}

func TestZeroPacketBatchNilGuard(t *testing.T) {
	// zeroPacketBatch(nil) must return without panicking (169-171).
	zeroPacketBatch(nil)

	// Anchor: a populated batch is zeroed in place (Packets/ProtocolNumbers
	// become nil), proving the nil case above is the guard, not a no-op.
	batch := benchmarkPacketBatch()
	zeroPacketBatch(&batch)
	if batch.Packets != nil || batch.ProtocolNumbers != nil {
		t.Fatalf("batch = %+v, want zeroed (nil slices)", batch)
	}
}
