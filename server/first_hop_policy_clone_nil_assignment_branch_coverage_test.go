package server

// Adversarial white-box coverage for the count-0 nil-field deep-copy guard in
// cloneFirstHopPolicyAccept. cloneFirstHopPolicyAccept deep-copies a
// protocol.PolicyAccept so the caller cannot mutate the cloned policy's
// interior; when VirtualAddressAssignment is non-nil it dereferences the
// assignment and deep-copies its slice fields before reassigning the clone.
//
//   - first_hop.go:711 cloneFirstHopPolicyAccept
//     policy.VirtualAddressAssignment != nil -> assignment := *policy.VirtualAddressAssignment;
//     deep-copy LeaseID / ClientAddress / DNSServerHint at :713-:715;
//     policy.VirtualAddressAssignment = &assignment at :716 (fires after the
//     FallbackMethods append at :710, before the Extensions clone at :718).
//
// The existing server tests drive cloneFirstHopPolicyAccept only with a
// PolicyAccept whose VirtualAddressAssignment is nil (the :711 condition is
// evaluated 12 times but the body never ran), so :711 stayed count-0 even
// though it is plainly reachable with a non-nil VirtualAddressAssignment.
//
// Proof technique (nil-field deep copy): pass a PolicyAccept with a non-nil
// VirtualAddressAssignment carrying a non-empty LeaseID. cloneFirstHopPolicyAccept
// takes the :711 branch, dereferences the assignment at :712, deep-copies the
// three slice fields at :713-:715, and reassigns the clone at :716. The proof
// that the branch ran is that cloned.VirtualAddressAssignment is non-nil
// (:716 assigned it). The proof that :713 (the LeaseID deep copy) ran is that
// mutating the original's LeaseID[0] AFTER the clone does not affect the
// clone's LeaseID[0]: :713 wrote the clone's LeaseID to a fresh backing array
// (append([]byte(nil), ...)), so the original and the clone no longer share
// storage. Pure (no IO; it only copies struct and slice values).
//
// No context is involved, so there is no SA1012 surface. In-package
// (package server) because cloneFirstHopPolicyAccept is unexported.
//
// This test file adds only a TestXxx entry point and references existing
// unexported in-package (cloneFirstHopPolicyAccept) and exported
// (protocol.PolicyAccept, protocol.VirtualAddressAssignment) symbols, so it
// adds no U1000 surface.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestCloneFirstHopPolicyAcceptVirtualAddressAssignmentDeepCopyGuard(t *testing.T) {
	// 711: a non-nil VirtualAddressAssignment takes the :711 branch; the clone's
	// VirtualAddressAssignment is non-nil (:716) and its LeaseID is an independent
	// copy (:713 wrote it to a fresh backing array), so mutating the original's
	// LeaseID[0] after the clone does not affect the clone.
	orig := protocol.PolicyAccept{
		VirtualAddressAssignment: &protocol.VirtualAddressAssignment{
			LeaseID:       []byte{0x01, 0x02, 0x03},
			ClientAddress: []byte{0x10},
			DNSServerHint: []byte{0x20},
		},
	}
	cloned := cloneFirstHopPolicyAccept(orig)
	if cloned.VirtualAddressAssignment == nil {
		t.Fatal("cloneFirstHopPolicyAccept left VirtualAddressAssignment = nil, want non-nil (:711 branch taken + :716 clone assignment)")
	}
	orig.VirtualAddressAssignment.LeaseID[0] = 0xFF
	if cloned.VirtualAddressAssignment.LeaseID[0] != 0x01 {
		t.Fatalf("clone LeaseID[0] = %#x, want 0x01 (:713 deep copy should be independent of the original backing array)", cloned.VirtualAddressAssignment.LeaseID[0])
	}
}
