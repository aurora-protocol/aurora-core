package transport

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guard on the unexported first-hop binding zeroer in
// transport/http2_client.go. The guard exists so a caller that passes a nil
// binding pointer does not panic or proceed into the field-erase loop: the
// function returns at its very first statement, before any field is
// dereferenced (binding.OuterExporterValue, binding.TLSExporterChannelID,
// binding.ConnectionIDHash, binding.CoverStreamBinding,
// binding.HandshakeBindingContext) or the zero-struct assignment runs
// (*binding = handshake.FirstHopBinding{}). The existing transport tests only
// ever drive a populated binding along the live HTTP/2 first-hop path, so the
// nil guard stayed count-0 even though it is plainly reachable.
//
// This is a nil-ARGUMENT guard on an unexported void helper, so the test is
// in-package (package transport). No context is involved, so there is no
// SA1012 surface. No network, no goroutine, no crypto — the call returns at the
// first statement and only ever zeroes in-memory byte slices when given a
// non-nil binding. The proof is that the call completes without panicking (a
// panic surfaces as a test failure), matching the established
// zeroer-nil-argument pattern across the codebase (see
// handshake/client_zeroer_nil_safety_branch_coverage_test.go,
// server/first_hop_zeroer_nil_safety_branch_coverage_test.go,
// mobile/auroracore/session_zeroer_nil_safety_branch_coverage_test.go).
//
//   - :460 zeroFirstHopBinding(binding *handshake.FirstHopBinding)
//     binding == nil -> no-op return
//
// This test file adds only a TestXxx entry point and uses an existing
// unexported in-package symbol, so it adds no U1000 surface.

import "testing"

func TestZeroFirstHopBindingNilArgumentGuard(t *testing.T) {
	// 460: zeroFirstHopBinding(nil) returns at its first statement before
	// iterating the binding's fields or assigning the zero struct. It is void;
	// the proof is that the call completes without panicking (a panic surfaces
	// as a test failure).
	zeroFirstHopBinding(nil)
}
