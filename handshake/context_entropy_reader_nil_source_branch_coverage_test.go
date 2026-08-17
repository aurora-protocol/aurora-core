package handshake

// Adversarial white-box coverage for the count-0 nil-field guard in
// contextEntropyReader.Read. contextEntropyReader.Read serves an entropy
// request from a bound source when one is configured, and falls back to
// crypto/rand when it is not.
//
//   - client.go:439 contextEntropyReader.Read
//     r.source != nil -> r.source.ReadContext(r.ctx, p) (fires after the :433
//     contextError guard and the :436 empty-buffer guard, before the :444
//     rand.Read fallback). The :440 inner err != nil branch zeroes the buffer
//     and returns (0, err).
//
// The existing handshake tests drive contextEntropyReader.Read only with a nil
// source (the :444 rand.Read fallback path), so the :439 source-non-nil branch
// body stayed count-0 even though it is plainly reachable with a configured
// source.
//
// Proof technique (nil-field positive branch): inject a stub session.EntropySource
// (a single-method interface, satisfied structurally without importing the
// session package) whose ReadContext returns a sentinel error. A real
// context.Background skips the :433 contextError guard, a 4-byte buffer skips
// the :436 empty guard, and :439 sees source != nil and calls ReadContext at
// :440, which returns the sentinel, so :441 zeroes the buffer and :442 returns
// (0, sentinel). The rand else-branch (:444) would return (4, nil) for a 4-byte
// buffer, so n == 0 + err == sentinel uniquely proves the :439/:440 branch ran.
// Pure (the stub does no real IO; it returns immediately).
//
// No context == nil guard is covered (a real context.Background is passed), so
// there is no SA1012 surface. In-package (package handshake) because
// contextEntropyReader is unexported.
//
// This test file adds only a TestXxx entry point, a tiny unexported stub type,
// and references existing unexported in-package (contextEntropyReader) symbols
// and the standard library context / errors / testing packages, so it adds no
// U1000 surface.

import (
	"context"
	"errors"
	"testing"
)

type stubEntropySource struct{ err error }

func (s stubEntropySource) ReadContext(ctx context.Context, p []byte) error { return s.err }

func TestContextEntropyReaderReadNilSourceGuard(t *testing.T) {
	// 439: a non-nil source takes the :439 branch; ReadContext returns the
	// sentinel at :440, so :441 zeroes the buffer and :442 returns (0, sentinel).
	// The rand else-branch (:444) would return (4, nil) for a 4-byte buffer, so
	// n == 0 + err == sentinel uniquely proves the :439/:440 branch ran.
	sentinel := errors.New("stub entropy failure")
	r := contextEntropyReader{ctx: context.Background(), source: stubEntropySource{err: sentinel}}
	n, err := r.Read(make([]byte, 4))
	if err != sentinel {
		t.Fatalf("Read non-nil-source err = %v, want sentinel %v (:440 returns the source error)", err, sentinel)
	}
	if n != 0 {
		t.Fatalf("Read non-nil-source n = %d, want 0 (:442 returns 0 on the source-error path)", n)
	}
}
