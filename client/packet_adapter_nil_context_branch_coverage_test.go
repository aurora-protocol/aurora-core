package client

// Adversarial white-box coverage for the count-0 nil-context guards of the
// three public entry points of PacketAdapter (client/packet_adapter.go):
//
//   - :292 Ingress                -> error "client: packet adapter context is nil"
//   - :404 HandleEncryptedPacket  -> (nil, "client: packet adapter context is nil")
//   - :438 HandleFrameBlocks      -> (nil, "client: packet adapter context is nil")
//
// Each guard sits immediately after the `if a == nil` receiver guard
// (:289/:401/:435) and rejects a nil context BEFORE ctx.Err() (:295/:441) or any
// struct field is read, so a bare non-nil *PacketAdapter suffices (no flow, no
// application, no harness). The :298/:407/:444 now-validity checks are also
// after the ctx guard, so the now argument is irrelevant to these guards.
//
// Coverage targets (baseline measured on main; bodies COUNT 0 while the :292 /
// :404 / :438 conditions were already evaluated — every existing test passes a
// real context.Background(), so the ctx==nil body is never taken):
//   - packet_adapter.go:292.16,294.3 0  — Ingress nil-context body
//   - packet_adapter.go:404.16,406.3 0  — HandleEncryptedPacket nil-context body
//   - packet_adapter.go:438.16,440.3 0  — HandleFrameBlocks nil-context body
//
// SA1012 (nil Context literal) is suppressed for the three intentional
// nil-context calls via the established codebase convention
// (//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
// — see provisioned_session_nil_safety_branch_coverage_test.go, CI-proven on
// #264 and many successors). The directive precedes each nil-context call.
//
// In-package (package client) because the PacketAdapter methods are unexported
// receivers of an exported type but the guards are reachable via the exported
// methods. No real network, no harness. This file adds one TestXxx entry point
// and references stdlib strings/testing/time only -> no U1000 surface.

import (
	"strings"
	"testing"
	"time"
)

func TestPacketAdapterRejectsNilContext(t *testing.T) {
	// A bare non-nil *PacketAdapter is enough: each ctx==nil guard is the second
	// statement (after the a==nil receiver guard) and returns before any field
	// read, so no flow/application/harness is needed.
	adapter := &PacketAdapter{}
	now := time.Unix(1_700_000_000, 0)

	// :292 Ingress rejects a nil context before ctx.Err / field reads.
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	if err := adapter.Ingress(nil, nil, now); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("Ingress(nil ctx) err = %v, want non-nil containing \"context is nil\" (:292)", err)
	}

	// :404 HandleEncryptedPacket rejects a nil context, returning (nil, err).
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	if out, err := adapter.HandleEncryptedPacket(nil, nil, now); err == nil || !strings.Contains(err.Error(), "context is nil") || out != nil {
		t.Fatalf("HandleEncryptedPacket(nil ctx) out=%v err=%v, want nil out + non-nil err containing \"context is nil\" (:404)", out, err)
	}

	// :438 HandleFrameBlocks rejects a nil context, returning (nil, err).
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	if out, err := adapter.HandleFrameBlocks(nil, nil, now); err == nil || !strings.Contains(err.Error(), "context is nil") || out != nil {
		t.Fatalf("HandleFrameBlocks(nil ctx) out=%v err=%v, want nil out + non-nil err containing \"context is nil\" (:438)", out, err)
	}
}
