package client

// Adversarial white-box coverage for the count-0 unknown-flow guard of
// PacketAdapter.ingressTCPLocked (client/packet_adapter.go:534). After the
// SYN-handling block (:482-532), a non-SYN TCP packet looks up its tuple in
// flowsByTuple (:481); if there is no mapping (no prior SYN opened a flow for
// that tuple), the :534 guard rejects it as "TCP data for an unknown flow". The
// :534 body is COUNT 0 because the existing adapter tests only ever send non-SYN
// data packets AFTER a SYN has established a flow (mapping != nil, correct kind,
// not closed), so the condition is true-checked but the body never taken.
//
// Coverage target (baseline measured on main; the body was COUNT 0 while its
// condition was already evaluated 2x):
//   - packet_adapter.go:534.85,536.3 1 0  — mapping==nil (|| wrong-kind || closed)
//     -> "received TCP data for an unknown flow"
//
// Reuses the existing adapter harness — packetAdapterApplications +
// NewPacketAdapter + packetAdapterTCPv4 (the same builder
// TestPacketAdapterOpensTCPAndForwardsStreamData uses) — and injects a lone non-SYN
// (ACK-only, flags 0x10) TCP packet for a fresh tuple with NO prior SYN, so
// flowsByTuple[tuple] is nil and the :534 guard fires. The Ingress -> ingressTCPLocked
// path skips the entire SYN block (flags & SYN == 0) and reaches :534 directly.
//
// In-package (package client) because ingressTCPLocked and the packetAdapter*
// helpers are unexported. No real network: the adapter is wired only to a
// clientApplication (the relay side is unused on this early-return path). This test
// file adds only a TestXxx entry point and references existing in-package helpers
// + stdlib bytes/context/strings/testing/time and the transport package already
// imported by packet_adapter_test.go, so it adds no U1000 surface.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/transport"
)

func TestPacketAdapterRejectsTCPDataForUnknownFlow(t *testing.T) {
	// :534 mapping == nil: a non-SYN TCP packet (ACK-only) for a tuple with no prior
	// SYN. flowsByTuple[tuple] is nil, the SYN block is skipped (flags & SYN == 0),
	// and the :534 guard rejects before any flow-allocation / frame-queue work.
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x41}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	// ACK-only (flags 0x10), fresh tuple, no prior SYN -> mapping == nil -> :534.
	ack := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 200, 0x10, nil)
	if err := adapter.Ingress(context.Background(), ack, now); err == nil {
		t.Fatal("Ingress(ACK, no prior flow) err = nil, want non-nil (:534 should reject)")
	} else if !strings.Contains(err.Error(), "unknown flow") {
		t.Fatalf("ack-no-flow err = %q, want substring \"unknown flow\" (:535)", err.Error())
	}
}
