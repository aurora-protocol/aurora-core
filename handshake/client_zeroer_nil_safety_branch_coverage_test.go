package handshake

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards on the unexported zeroers in handshake/client.go. Each guard exists so
// a caller that passes a nil binding / request / proof / capsule / secrets
// pointer does not panic or proceed into the field-erase loop: the function
// returns at its very first statement, before any field is dereferenced
// (binding.OuterExporterValue, request.AdmissionContextHash,
// value.ClientNonce, value.IssuerID, value.TokenRedemptionHash,
// value.AdmissionProof, value.ServerFinished, value.ApplicationSecret) or any helper
// is called (zeroBindingBytes, zeroExtensions). The existing handshake tests
// only ever drive populated values along the live handshake path, so the nil
// guards stayed count-0 even though each is plainly reachable.
//
// These are nil-ARGUMENT guards on unexported void helpers, so the test is
// in-package (package handshake). None take a context, so there is no SA1012
// surface. No network, no goroutine, no crypto — each call returns at the first
// statement and only ever zeroes in-memory byte slices. The proof is that each
// call completes without panicking (a panic surfaces as a test failure),
// matching the established zeroer-nil-argument pattern (see
// server/first_hop_zeroer_nil_safety_branch_coverage_test.go and
// client/provisioned_session_nil_safety_branch_coverage_test.go).
//
//   - :694 zeroFirstHopBinding(binding *FirstHopBinding)
//     binding == nil -> no-op return
//   - :705 zeroClientProofRequest(request *ClientProofRequest)
//     request == nil -> no-op return
//   - :714 zeroCoverPrelude0(value *protocol.CoverPrelude0)
//     value == nil -> no-op return
//   - :728 zeroAdmissionProof(value *protocol.AdmissionProof)
//     value == nil -> no-op return
//   - :742 zeroReplayProof(value *protocol.ReplayProof)
//     value == nil -> no-op return
//   - :754 zeroCoverCapsule1(value *protocol.CoverCapsule1Plain)
//     value == nil -> no-op return
//   - :769 zeroCoverCapsule2(value *protocol.CoverCapsule2Plain)
//     value == nil -> no-op return
//   - :804 zeroApplicationSecrets(value *ApplicationSecrets)
//     value == nil -> no-op return
//
// This test file adds only a TestXxx entry point and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import "testing"

func TestClientZeroerNilArgumentGuards(t *testing.T) {
	// 694/705/714/728/742/754/769/804: the eight unexported zeroers return at
	// their first statement when given a nil pointer, before iterating the
	// value's fields. Each is void; the proof is that the call completes
	// without panicking (a panic surfaces as a test failure).
	zeroFirstHopBinding(nil)
	zeroClientProofRequest(nil)
	zeroCoverPrelude0(nil)
	zeroAdmissionProof(nil)
	zeroReplayProof(nil)
	zeroCoverCapsule1(nil)
	zeroCoverCapsule2(nil)
	zeroApplicationSecrets(nil)
}
