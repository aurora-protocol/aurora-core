//go:build cgo

package main

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards on the unexported native zeroers in mobile/auroracore/session.go. Each
// guard exists so a caller that passes a nil proof / admission proof / token
// metadata / replay proof / frame block / issuer work / provisioning pointer
// does not panic or proceed into the field-erase loop: the function returns at
// its very first statement, before any field is dereferenced
// (value.AdmissionContextHash, value.IssuerID, value.RFC9577ChallengeDigest,
// value.TokenRedemptionHash, value.Frames, value.RequestBody,
// value.IssuerMetadata) or any helper is called (zeroNativeBytes). The existing
// mobile tests only ever drive populated values along the live native session
// path, so the nil guards stayed count-0 even though each is plainly reachable.
//
// These are nil-ARGUMENT guards on unexported void helpers, so the test is
// in-package (package main). None take a context, so there is no SA1012
// surface. No network, no goroutine, no crypto, no cgo — each call returns at the
// first statement and only ever zeroes in-memory byte slices via the pure-Go
// zeroNativeBytes helper. The proof is that each call completes without
// panicking (a panic surfaces as a test failure), matching the established
// zeroer-nil-argument pattern (see
// handshake/client_zeroer_nil_safety_branch_coverage_test.go and
// server/first_hop_zeroer_nil_safety_branch_coverage_test.go).
//
// NOTE: this test does NOT touch native (cgo) session handles, so it cannot
// trigger the TestNativeSessionFFIStopsOnCarrierCancellation handle-lifecycle
// flake; it is pure Go memory zeroing.
//
//   - :866 zeroNativeProofRequest(value *handshake.ClientProofRequest)
//     value == nil -> no-op return
//   - :876 zeroNativeAdmissionProof(value *protocol.AdmissionProof)
//     value == nil -> no-op return
//   - :889 zeroNativeTokenMetadata(value *protocol.AuroraTokenMetadata)
//     value == nil -> no-op return
//   - :899 zeroNativeReplayProof(value *protocol.ReplayProof)
//     value == nil -> no-op return
//   - :912 zeroNativeFrameBlock(value *protocol.FrameBlock)
//     value == nil -> no-op return
//   - :946 zeroNativeIssuerWork(value *nativeIssuerWork)
//     value == nil -> no-op return
//   - :954 zeroNativeProvisioning(value *client.NativeProvisioning)
//     value == nil -> no-op return
//
// This test file adds only a TestXxx entry point and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import "testing"

func TestNativeSessionZeroerNilArgumentGuards(t *testing.T) {
	// 866/876/889/899/912/946/954: the seven unexported native zeroers return at
	// their first statement when given a nil pointer, before iterating the
	// value's fields or assigning the zero struct. Each is void; the proof is
	// that the call completes without panicking (a panic surfaces as a test
	// failure). None of these calls touch cgo / native session handles.
	zeroNativeProofRequest(nil)
	zeroNativeAdmissionProof(nil)
	zeroNativeTokenMetadata(nil)
	zeroNativeReplayProof(nil)
	zeroNativeFrameBlock(nil)
	zeroNativeIssuerWork(nil)
	zeroNativeProvisioning(nil)
}
