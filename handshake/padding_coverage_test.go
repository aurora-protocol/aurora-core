package handshake

// Adversarial coverage for handshake/padding.go.
//
// The happy padding paths (padCoverPrelude0/1, padCoverCapsule1/2 succeeding
// within their envelopes), the generic padBootstrapBody success return (134),
// and the envelope-guard errors (min>max 95, max>record-limit 98, finalize
// failure 113, finalized body exceeds envelope 121-124, ReadFull entropy
// failure 151-155) are already covered by padding_test.go and are not
// re-asserted here except as needed anchors.
//
// This file covers the residual count-0 blocks, perturbing exactly one input
// per case so the branch under test is the one that fires:
//
//   - padCoverPrelude0 24-26 / padCoverPrelude1 42-44 / padCoverCapsule1
//     59-61 / padCoverCapsule2 74-76: clone-error propagation. An input whose
//     MsgType exceeds wire.MaxVarint fails protocol.Encode inside the clone,
//     so the wrapper returns the clone error before touching the random
//     reader. Each wrapper call also exercises the corresponding clone*
//     Encode-error block (170-172 / 183-185 / 196-198 / 209-211).
//   - padCoverPrelude1 38-40 / padCoverCapsule1 55-57 / padCoverCapsule2 70-72:
//     nil-finalizer guard (padCoverPrelude0 takes no finalizer).
//   - cloneCoverPrelude0 170-172 / cloneCoverPrelude1 183-185 /
//     cloneCoverCapsule1 196-198 / cloneCoverCapsule2 209-211: Encode error on
//     an out-of-range varint field (MsgType = math.MaxUint64). Reached via the
//     wrapper clone-error calls above.
//   - padBootstrapBody 100-102: nil random reader (isNilDependency(nil)).
//   - padBootstrapBody 116-120: finalize returns a body that does not grow
//     across attempts (len(body) <= previousBodySize).
//   - padBootstrapBody 127-131: finalize returns a value whose padding differs
//     from the loop-managed padding once the body reaches minBodySize.
//   - padBootstrapBody 145-149: required padding (minBodySize - bodySize)
//     exceeds the opaque16 ceiling (0xffff). Reachable because
//     maxBootstrapRecordBodyBytes = 1<<20 > 0xffff, so a large minBodySize with
//     a small canonical body overflows opaque16 on the first attempt.
//   - padBootstrapBody 164-165: the loop exhausts maxPaddingAttempts without
//     the body ever reaching minBodySize (a finalize that grows the body
//     monotonically but too slowly to converge in four attempts).
//
// Dead-by-design (documented, not covered):
//   - cloneCoverPrelude0 175-177 / cloneCoverPrelude1 188-190 /
//     cloneCoverCapsule1 201-203 / cloneCoverCapsule2 214-216: the
//     `r.Err() != nil || !r.EOF()` decode-mismatch guard. The four Decode*
//     functions only read fields (no validation — ValidateStructural is a
//     separate method), and Encode writes exactly the fields Decode reads in
//     the same order, so for any input that passes Encode the matching Decode
//     consumes the entire buffer with r.Err() nil and r.EOF() true. The guard
//     defends against a future Encode/Decode drift but no current input
//     reaches it.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The covPadValue type is referenced by >=2 subtests, so
// it is not U1000. No context.Context, no goroutines, no deprecated APIs.

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// covPadValue is a minimal T for direct padBootstrapBody calls, exercising the
// generic padding loop without the cover-message clone/encode machinery. It
// only needs a padding slot driven by the set/get closures. Referenced by
// >=2 subtests, so not U1000.
type covPadValue struct {
	Padding []byte
}

func covPadReader() *countingPaddingReader { return &countingPaddingReader{value: 0xa5} }

// covMalformedPrelude0 returns a valid CoverPrelude0 fixture with an
// out-of-range MsgType so protocol.Encode fails inside cloneCoverPrelude0.
func covMalformedPrelude0() protocol.CoverPrelude0 {
	in := paddingPrelude0()
	in.MsgType = math.MaxUint64
	return in
}

func covMalformedPrelude1() protocol.CoverPrelude1 {
	in := paddingPrelude1()
	in.MsgType = math.MaxUint64
	return in
}

func covMalformedCapsule1() protocol.CoverCapsule1Plain {
	in := paddingCapsule1()
	in.MsgType = math.MaxUint64
	return in
}

func covMalformedCapsule2() protocol.CoverCapsule2Plain {
	in := paddingCapsule2()
	in.MsgType = math.MaxUint64
	return in
}

// covIdentityFinalizers are non-nil finalizers used only to pass the nil guard
// so the wrapper reaches the clone call. Their bodies are irrelevant because
// the clone fails first.
func covPrelude1IdentityFinalizer() prelude1Finalizer {
	return func(v protocol.CoverPrelude1) (protocol.CoverPrelude1, []byte, error) {
		return v, []byte{1}, nil
	}
}
func covCapsule1IdentityFinalizer() capsule1Finalizer {
	return func(v protocol.CoverCapsule1Plain) (protocol.CoverCapsule1Plain, []byte, error) {
		return v, []byte{1}, nil
	}
}
func covCapsule2IdentityFinalizer() capsule2Finalizer {
	return func(v protocol.CoverCapsule2Plain) (protocol.CoverCapsule2Plain, []byte, error) {
		return v, []byte{1}, nil
	}
}

func TestPadWrappersRejectNilFinalizer(t *testing.T) {
	cases := []struct {
		name string
		fn   func() error
		want string
	}{
		{"prelude1", func() error {
			_, _, err := padCoverPrelude1(covPadReader(), paddingPrelude1(), 1, 64, nil)
			return err
		}, "missing Prelude1 finalizer"},
		{"capsule1", func() error {
			_, _, err := padCoverCapsule1(covPadReader(), paddingCapsule1(), 1, 64, nil)
			return err
		}, "missing Capsule1 finalizer"},
		{"capsule2", func() error {
			_, _, err := padCoverCapsule2(covPadReader(), paddingCapsule2(), 1, 64, nil)
			return err
		}, "missing Capsule2 finalizer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.fn()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestPadWrappersRejectCloneError(t *testing.T) {
	// Each wrapper's clone fails on the out-of-range MsgType; the wrapper
	// returns the clone error (and the clone's Encode-error block fires).
	cases := []struct {
		name string
		fn   func() error
	}{
		{"prelude0", func() error {
			_, _, err := padCoverPrelude0(covPadReader(), covMalformedPrelude0(), 1, 64)
			return err
		}},
		{"prelude1", func() error {
			_, _, err := padCoverPrelude1(covPadReader(), covMalformedPrelude1(), 1, 64, covPrelude1IdentityFinalizer())
			return err
		}},
		{"capsule1", func() error {
			_, _, err := padCoverCapsule1(covPadReader(), covMalformedCapsule1(), 1, 64, covCapsule1IdentityFinalizer())
			return err
		}},
		{"capsule2", func() error {
			_, _, err := padCoverCapsule2(covPadReader(), covMalformedCapsule2(), 1, 64, covCapsule2IdentityFinalizer())
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.fn()
			if err == nil || !strings.Contains(err.Error(), "varint out of range") {
				t.Fatalf("err = %v, want varint out of range", err)
			}
		})
	}
}

func TestCloneCoverEncodeError(t *testing.T) {
	// Direct clone calls confirm the Encode-error block (the wrappers above
	// exercise it too, but the direct call asserts the error origin).
	cases := []struct {
		name string
		fn   func() error
	}{
		{"prelude0", func() error { _, err := cloneCoverPrelude0(covMalformedPrelude0()); return err }},
		{"prelude1", func() error { _, err := cloneCoverPrelude1(covMalformedPrelude1()); return err }},
		{"capsule1", func() error { _, err := cloneCoverCapsule1(covMalformedCapsule1()); return err }},
		{"capsule2", func() error { _, err := cloneCoverCapsule2(covMalformedCapsule2()); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.fn()
			if err == nil || !strings.Contains(err.Error(), "varint out of range") {
				t.Fatalf("err = %v, want varint out of range", err)
			}
		})
	}
}

func TestPadBootstrapBodyErrorBranches(t *testing.T) {
	set := func(v *covPadValue, p []byte) { v.Padding = p }
	get := func(v covPadValue) []byte { return v.Padding }

	t.Run("nil random reader", func(t *testing.T) {
		// isNilDependency(nil) fires before the loop (100-102).
		fin := func(v covPadValue) (covPadValue, []byte, error) {
			return v, []byte("x"), nil
		}
		_, _, err := padBootstrapBody(nil, covPadValue{}, 1, 64, false, set, get, fin)
		if err == nil || !strings.Contains(err.Error(), "missing padding entropy") {
			t.Fatalf("err = %v, want missing padding entropy", err)
		}
	})

	t.Run("body does not increase", func(t *testing.T) {
		// Finalize returns a constant-size body; on the second attempt
		// len(body) <= previousBodySize fires (116-120).
		fin := func(v covPadValue) (covPadValue, []byte, error) {
			return v, bytes.Repeat([]byte{1}, 10), nil
		}
		_, _, err := padBootstrapBody(covPadReader(), covPadValue{}, 100, 8192, false, set, get, fin)
		if err == nil || !strings.Contains(err.Error(), "did not increase body size") {
			t.Fatalf("err = %v, want did not increase body size", err)
		}
	})

	t.Run("finalizer changed padding", func(t *testing.T) {
		// On the first attempt the body already meets minBodySize, but the
		// finalizer's padding differs from the loop-managed padding (127-131).
		fin := func(v covPadValue) (covPadValue, []byte, error) {
			v.Padding = []byte{0xff}
			return v, bytes.Repeat([]byte{1}, 10), nil
		}
		_, _, err := padBootstrapBody(covPadReader(), covPadValue{}, 1, 8192, false, set, get, fin)
		if err == nil || !strings.Contains(err.Error(), "finalizer changed padding") {
			t.Fatalf("err = %v, want finalizer changed padding", err)
		}
	})

	t.Run("required padding exceeds opaque16", func(t *testing.T) {
		// minBodySize=70000 with a 10-byte canonical body needs 69990 bytes of
		// padding, which exceeds 0xffff (145-149). maxBootstrapRecordBodyBytes
		// = 1<<20, so the envelope guards pass.
		fin := func(v covPadValue) (covPadValue, []byte, error) {
			return v, bytes.Repeat([]byte{1}, 10), nil
		}
		_, _, err := padBootstrapBody(covPadReader(), covPadValue{}, 70000, 100000, false, set, get, fin)
		if err == nil || !strings.Contains(err.Error(), "exceeds opaque16") {
			t.Fatalf("err = %v, want exceeds opaque16", err)
		}
	})

	t.Run("padding does not converge", func(t *testing.T) {
		// The body grows by one byte per attempt (11,12,13,14) but never
		// reaches minBodySize=100 in four attempts, so the loop exhausts and
		// returns the non-convergence error (164-165).
		attempt := 0
		fin := func(v covPadValue) (covPadValue, []byte, error) {
			attempt++
			return v, bytes.Repeat([]byte{1}, 10+attempt), nil
		}
		_, _, err := padBootstrapBody(covPadReader(), covPadValue{}, 100, 8192, false, set, get, fin)
		if err == nil || !strings.Contains(err.Error(), "did not converge") {
			t.Fatalf("err = %v, want did not converge", err)
		}
	})
}
