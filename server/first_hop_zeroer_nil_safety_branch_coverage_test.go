package server

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards on the three unexported first-hop zeroers in server/first_hop.go. Each
// guard exists so a caller that passes a nil binding / prelude pointer does not
// panic or proceed into the field-erase loop: the function returns at its very
// first statement, before any field is dereferenced (binding.OuterExporterValue,
// prelude.ClientNonce, prelude.ServerNonce) or any helper is called
// (zeroFirstHopBytes, zeroFirstHopExtensions). The existing server tests only
// ever drive populated bindings / preludes along the live first-hop path, so
// the nil guards stayed count-0 even though each is plainly reachable.
//
// These are nil-ARGUMENT guards on unexported void helpers, so the test is
// in-package. No method takes a context, so there is no SA1012 surface. No
// network, no goroutine, no crypto — each call returns at the first statement.
// The proof is that each call completes without panicking (a panic surfaces as
// a test failure), matching the established zeroer-nil-argument pattern (see
// client/provisioned_session_nil_safety_branch_coverage_test.go).
//
//   - :1021 zeroFirstHopBinding(binding *handshake.FirstHopBinding)
//     binding == nil -> no-op return
//   - :1033 zeroFirstHopPrelude0(prelude *protocol.CoverPrelude0)
//     prelude == nil -> no-op return
//   - :1052 zeroFirstHopPrelude1(prelude *protocol.CoverPrelude1)
//     prelude == nil -> no-op return
//
// This test file adds only a TestXxx entry point and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import "testing"

func TestFirstHopZeroerNilArgumentGuards(t *testing.T) {
	// 1021/1033/1052: the three unexported zeroers return at their first
	// statement when given a nil pointer, before iterating the value's fields.
	// Each is void; the proof is that the call completes without panicking (a
	// panic surfaces as a test failure).
	zeroFirstHopBinding(nil)
	zeroFirstHopPrelude0(nil)
	zeroFirstHopPrelude1(nil)
}
