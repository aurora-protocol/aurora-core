package session

// Adversarial white-box coverage for three count-0 encoded *[]byte nil-safety
// guards across the Application enqueue paths. Each guard short-circuits on
// `encoded == nil` before evaluating `len(*encoded)` (and, for the write-update
// path, before dereferencing `prepared`), so a nil encoded pointer is safe and
// returns ErrBackpressure without panicking.
//
//   - application.go:551 (*Application).enqueueEncodedLocked
//     encoded == nil || !hasCapacityLocked(len(*encoded), control) -> ErrBackpressure
//     (the first clause; short-circuits before len(*encoded), which would deref a
//     nil *[]byte and panic).
//   - application.go:562 (*Application).enqueueControlBeforeWriteUpdateLocked
//     encoded == nil || !hasCapacityLocked(len(*encoded), true) -> ErrBackpressure
//     (same nil-deref short-circuit shape as :551).
//   - key_update.go:156 (*Application).enqueueWriteUpdateLocked
//     encoded == nil || !hasCapacityLocked(len(*encoded), true) -> ErrBackpressure
//     (same shape; short-circuits before len(*encoded) AND before *prepared at
//     :160, so a nil prepared is also safe).
//
// The existing session tests drive these enqueue paths only with a real encoded
// packet on a capacity-limited Application (the backpressure path), so the nil
// clause of each guard stayed count-0 even though each is plainly reachable with
// a nil encoded pointer.
//
// Proof technique:
//   - :551: (&Application{}).enqueueEncodedLocked(nil, false, false) — encoded ==
//     nil short-circuits before len(*encoded); :552 returns ErrBackpressure. No
//     field of a is read on this path.
//   - :562: (&Application{}).enqueueControlBeforeWriteUpdateLocked(nil) — encoded
//     == nil short-circuits before len(*encoded); :563 returns ErrBackpressure.
//   - :156: (&Application{}).enqueueWriteUpdateLocked(nil, nil) — encoded == nil
//     short-circuits before len(*encoded) and before *prepared (:160); :157
//     returns ErrBackpressure. Passing nil for prepared is safe because :159-:160
//     are unreachable when the guard trips.
//
// No context is involved, so there is no SA1012 surface. No network, no goroutine,
// no file IO — each guard returns before any queue / capacity / lock state is
// touched. In-package (package session) because enqueueEncodedLocked,
// enqueueControlBeforeWriteUpdateLocked, and enqueueWriteUpdateLocked are
// unexported. These are "Locked"-suffix methods (the caller conventionally holds
// a.mu), but the nil-encoded path returns before any state is read, so calling
// them on a zero-value Application without holding the lock is safe and does not
// deadlock.
//
// This test file adds only TestXxx entry points and references existing
// in-package (Application, enqueueEncodedLocked,
// enqueueControlBeforeWriteUpdateLocked, enqueueWriteUpdateLocked,
// ErrBackpressure) symbols and the standard library errors / testing packages,
// so it adds no U1000 surface.

import (
	"errors"
	"testing"
)

func TestEnqueueEncodedLockedNilEncodedGuard(t *testing.T) {
	// 551: encoded == nil short-circuits before len(*encoded); :552 returns
	// ErrBackpressure. No field of a is read on this path.
	a := &Application{}
	if err := a.enqueueEncodedLocked(nil, false, false); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("enqueueEncodedLocked(nil) err = %v, want ErrBackpressure (:552)", err)
	}
}

func TestEnqueueControlBeforeWriteUpdateLockedNilEncodedGuard(t *testing.T) {
	// 562: encoded == nil short-circuits before len(*encoded); :563 returns
	// ErrBackpressure.
	a := &Application{}
	if err := a.enqueueControlBeforeWriteUpdateLocked(nil); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("enqueueControlBeforeWriteUpdateLocked(nil) err = %v, want ErrBackpressure (:563)", err)
	}
}

func TestEnqueueWriteUpdateLockedNilEncodedGuard(t *testing.T) {
	// 156: encoded == nil short-circuits before len(*encoded) and before *prepared
	// (:160); :157 returns ErrBackpressure. A nil prepared is safe because
	// :159-:160 are unreachable when the guard trips.
	a := &Application{}
	if err := a.enqueueWriteUpdateLocked(nil, nil); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("enqueueWriteUpdateLocked(nil, nil) err = %v, want ErrBackpressure (:157)", err)
	}
}
