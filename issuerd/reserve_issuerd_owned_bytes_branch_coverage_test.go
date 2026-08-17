package issuerd

// Adversarial white-box branch coverage for reserveIssuerdOwnedBytes
// (issuerd/http.go:593). This low-level byte-buffer reservation helper has
// FOUR count-0 branches in the baseline: the bounds-check error (:594, three
// `||` clauses) and the three buffer-growth strategy branches (:598 / :602 /
// :605). The only production caller (http.go:585, inside the verifier-request
// body append path) always passes a body already capped by
// readVerifierRequestBody's LimitReader and a bounded input, so it never trips
// :594 and only ever hits one growth strategy — leaving the other branches
// COUNT 0. reserveIssuerdOwnedBytes is an unexported pure helper taking a
// []byte and three ints (no crypto, no network, no cgo, no finalizers), so
// every branch is reachable by a direct in-package call with crafted args
// (it is NOT dead-by-design: the helper is its OWN bounds check, not a
// re-validation of an upstream check in the same call path — contrast the
// switch-fallthrough-dominated class, e.g. protocol/records.go:59).
//
// reserveIssuerdOwnedBytes(body []byte, nextLength, maximum int) ([]byte, error):
//   - :594  maximum < 0 || nextLength < len(body) || nextLength > maximum
//            -> zeroIssuerdOwnedBytes(body); return nil, errVerifierRequestTooLarge
//   - :598  nextLength <= cap(body)            -> return body[:nextLength] (in-place)
//   - :601  nextCapacity := cap(body) * 2
//   - :602  nextCapacity < nextLength           -> nextCapacity = nextLength
//   - :605  nextCapacity > maximum              -> nextCapacity = maximum
//   - :608  next := make([]byte, nextLength, nextCapacity); copy; zero; return
//
// The per-line coverage flip (0 -> 1+ per branch body) is the rigorous proof;
// the len/cap assertions confirm WHICH growth strategy fired.

import (
	"errors"
	"testing"
)

func TestReserveIssuerdOwnedBytesBranches(t *testing.T) {
	cases := []struct {
		name    string
		call    func() ([]byte, error)
		wantErr bool
		wantLen int
		wantCap int
	}{
		{
			// :594 (maximum < 0) — first || operand short-circuits.
			name:    "maximum negative",
			call:    func() ([]byte, error) { return reserveIssuerdOwnedBytes(nil, 0, -1) },
			wantErr: true,
		},
		{
			// :594 (nextLength < len(body)) — second || operand; maximum ok,
			// nextLength shrinks below the existing body length.
			name:    "next length below body length",
			call:    func() ([]byte, error) { return reserveIssuerdOwnedBytes([]byte("ab"), 1, 10) },
			wantErr: true,
		},
		{
			// :594 (nextLength > maximum) — third || operand; maximum ok and
			// nextLength >= len(body), but nextLength exceeds maximum.
			name:    "next length exceeds maximum",
			call:    func() ([]byte, error) { return reserveIssuerdOwnedBytes(nil, 10, 5) },
			wantErr: true,
		},
		{
			// :598 (in-place grow) — nextLength <= cap(body): returns body[:5],
			// retaining the original cap (10).
			name:    "in place grow within capacity",
			call:    func() ([]byte, error) { return reserveIssuerdOwnedBytes(make([]byte, 0, 10), 5, 20) },
			wantLen: 5,
			wantCap: 10,
		},
		{
			// :602 (cap*2 < nextLength) — cap=2 -> nextCapacity=4 < nextLength=8,
			// so nextCapacity is raised to nextLength (8); :605 skipped (8 <= 15).
			name:    "double capacity below next length",
			call:    func() ([]byte, error) { return reserveIssuerdOwnedBytes(make([]byte, 0, 2), 8, 15) },
			wantLen: 8,
			wantCap: 8,
		},
		{
			// :605 (cap*2 > maximum) — cap=10 -> nextCapacity=20 > maximum=15, so
			// nextCapacity is clamped to maximum (15); :602 skipped (20 >= 11).
			name:    "double capacity exceeds maximum",
			call:    func() ([]byte, error) { return reserveIssuerdOwnedBytes(make([]byte, 0, 10), 11, 15) },
			wantLen: 11,
			wantCap: 15,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := c.call()
			if c.wantErr {
				if !errors.Is(err, errVerifierRequestTooLarge) {
					t.Fatalf("%s: err = %v, want errVerifierRequestTooLarge", c.name, err)
				}
				if r != nil {
					t.Fatalf("%s: err path returned non-nil buffer %v", c.name, r)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: err = %v, want nil", c.name, err)
			}
			if len(r) != c.wantLen {
				t.Fatalf("%s: len = %d, want %d", c.name, len(r), c.wantLen)
			}
			if cap(r) != c.wantCap {
				t.Fatalf("%s: cap = %d, want %d", c.name, cap(r), c.wantCap)
			}
		})
	}
}
