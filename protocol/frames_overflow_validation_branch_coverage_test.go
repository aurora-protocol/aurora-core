package protocol

// Adversarial white-box coverage for the one reachable count-0 branch in the
// protocol/frames.go frame-length accounting: the integer-overflow guard of
// addEncodedLength (85-89). Every other count-0 line in the protocol package's
// sub-100% functions is dead-by-design; the analysis below records why so a
// future pass does not re-derive it.
//
// addEncodedLength(total, next) is the shared int-overflow guard used by every
// EncodedLen in this package: it returns (0, false) when next is negative or
// when total + next would exceed int(^uint(0)>>1), the platform's max int. Its
// happy path (return total + next, true) is exercised by AuroraFrame.EncodedLen
// and FrameBlock.EncodedLen on every valid frame, so the missing branch is the
// overflow return at :86-88. That branch is reachable by a direct call with
// total at the platform maximum: addEncodedLength(math.MaxInt, 1) crosses the
// `total > int(^uint(0)>>1)-next` threshold (MaxInt > MaxInt-1) and returns
// (0, false) without allocating anything. (The `next < 0` disjunct is the same
// block; the overflow disjunct is the one the overflow guard exists to catch.)
// It is the only reachable way to exercise the guard: every caller bounds total
// far below the limit (see the dead-by-design entries below).
//
// Target covered (previously count-0):
//
//   - addEncodedLength:86-88 — the integer-overflow return. A direct call with
//     total = math.MaxInt and next = 1 crosses the overflow threshold and
//     returns (0, false); asserting ok == false and n == 0 locks the guard.
//
// Dead-by-design (documented, NOT claimed):
//   - AuroraFrame.EncodedLen:32 — the addEncodedLength overflow inside the
//     varint loop. Payload is capped at 0xffffff by the :21 guard and each of
//     the three varints is at most 10 bytes, so length <= 3 + 0xffffff + 30
//     (~16.78M), far below int(^uint(0)>>1) on both 32- and 64-bit platforms.
//     addEncodedLength cannot return false here.
//   - FrameBlock.EncodedLen:61 — the VarintLen(len(b.Frames)) error. VarintLen
//     rejects only values above wire.MaxVarint (1<<62 - 1); a slice of that many
//     frames cannot be allocated, so the error is unreachable.
//   - FrameBlock.EncodedLen:71 — the addEncodedLength overflow accumulating
//     per-frame lengths. MaxFrameBlockFrames is 4096 and each frame is at most
//     ~16.78M, so the running total is at most ~68.7M, far below a 64-bit
//     maxInt; the bytes needed to approach the limit cannot be allocated.
//   - validateFlowOpenDomainTarget:538 — the post-loop `labelLen == 0` check.
//     A trailing dot is rejected at :508 before the loop, and an empty label
//     after a dot is rejected in-loop at :518, so after the loop the running
//     labelLen is always > 0. (The >63 check at :534 is already covered by the
//     existing domain-target table.)
//   - ValidateFlowManagementFrame:673 — the shared ValidateExtensions(extensions,
//     nil) call after the per-type switch. Each per-type arm already runs
//     ValidateExtensions on the same extensions with the same nil known-map
//     before the shared call: ValidateFlowOpen and ValidateUDPTargetConfirm
//     call it directly inside the arm (:644/:651, returning before :673 on a
//     bad extension), and the FlowClose arm runs ValidateFlowClose at :668-671,
//     whose :729 also calls ValidateExtensions(close.Extensions, nil). So by the
//     time the shared :673 call runs, the extensions have already passed an
//     identical ValidateExtensions(extensions, nil) call, and it can never
//     fail — a redundant re-validation. (The existing suite covers the
//     per-type propagation at :644/:651 and the flow_id mismatch at :676.)
//   - NewUDPTargetConfirmFrame:750 / NewFlowOpenFrame:770 / NewFlowCloseFrame:790
//     — the ValidateFlowManagementFrame failure inside each constructor. The
//     constructor builds frame.FlowID from the same object it encodes into the
//     payload (frame.FlowID = X.FlowID, Payload = Encode(X)), and X has already
//     passed its per-type validator, so the decoded payload's flow_id always
//     matches frame.FlowID, the extensions are the already-validated
//     X.Extensions, and the payload is exactly Encode(X) (no decode error or
//     trailing bytes). The frame is self-consistent, so ValidateFlowManagement
//     Frame cannot fail on it.
//   - records.go PublicKeyRecord.ValidateCompatibility:59-62 — the post-switch
//     empty-key check and final success return. validateSignatureKeyEncoding
//     Compatibility rejects every unknown scheme via its default case, and every
//     known scheme matches a switch case (ECDSA P-256/P-384, ML-DSA-65/87,
//     Ed25519-lab), so control never falls through the switch to :59. The
//     post-switch path is unreachable.
//   - issuer.go IssuerVerifierRequest.EncodedLen:648/:659 — the addEncodedLength
//     overflow on the fixed-width byte fields (:648) and bounded varints (:659).
//     The fixed fields are 16/48/32/16 bytes and the varints are at most 10
//     bytes each, so the running total is bounded far below a 64-bit maxInt; a
//     byte slice large enough to overflow int cannot be allocated.
//
// This file adds no new helpers (only one test function), so there is no
// staticcheck U1000 surface. No context.Context (no SA1012 surface), no
// goroutines, no cryptography, no network, no filesystem. addEncodedLength is an
// unexported pure function called directly from this in-package test.

import (
	"math"
	"testing"
)

func TestAddEncodedLengthRejectsIntOverflow(t *testing.T) {
	// 86-88: addEncodedLength guards total + next against exceeding the
	// platform max int. With total at math.MaxInt (== int(^uint(0)>>1)) and
	// next = 1, the threshold `total > int(^uint(0)>>1)-next` becomes
	// MaxInt > MaxInt-1, which is true, so the guard returns (0, false) rather
	// than producing a wrapped/negative length. This is the only reachable way
	// to exercise the overflow return: every caller bounds total well below the
	// limit (see the dead-by-design section), so a direct call is required.
	n, ok := addEncodedLength(math.MaxInt, 1)
	if ok {
		t.Fatalf("addEncodedLength(MaxInt, 1) ok = true, want false (overflow)")
	}
	if n != 0 {
		t.Fatalf("addEncodedLength(MaxInt, 1) n = %d, want 0", n)
	}
}
