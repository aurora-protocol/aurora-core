package client

// Adversarial white-box coverage for the count-0 input-validation guards of
// buildProvisionedIssuerWork (client/provisioned_session.go:341/:345/:352/:357).
// This opens the buildProvisionedIssuerWork input-validation vein in the
// client package: buildProvisionedIssuerWork is a PURE function taking only
// primitive args (issuerURL/issuerCarrierPath strings, a ClientProofRequest,
// now time.Time, lifetime time.Duration, random io.Reader) — no
// NativeProvisioning, no crypto, no network — so every guard is reachable
// with crafted primitives plus (for :357) a faulting io.Reader.
//
// buildProvisionedIssuerWork validates its inputs in order and returns on the
// first failure:
//   - :341  issuerURL == "" || issuerCarrierPath == "" ||
//           len(request.AdmissionContextHash) != 48 ||
//           request.ReplayEpochValidUntil == 0
//        -> "client: provisioned issuer work inputs are invalid"
//   - :345  request.ReplayEpochValidUntil <= nowUnix+1
//        -> "client: provisioned replay epoch expires too soon"
//   - :352  expiry <= nowUnix   (expiry = now.Add(lifetime); clamped to
//           ReplayEpochValidUntil-1 at :349 when it would exceed the epoch)
//        -> "client: provisioned issuer proof would be expired"
//   - :357  io.ReadFull(random, tokenNonce) err
//        -> "client: generate provisioned issuer token nonce: <err>"
//
// The only production caller (newProvisionedSession:132) passes a valid
// IssuerURL/IssuerCarrierPath (validated upstream), a request whose
// AdmissionContextHash is 48 bytes and ReplayEpochValidUntil is in the future,
// a normalized positive lifetime, and rand.Reader — so all four guards stayed
// COUNT 0 in the baseline (confirmed: each block count=0 on a clean tree).
//
// Coverage targets (baseline measured on a clean tree; bodies COUNT 0):
//   - provisioned_session.go:341.129,343.3 0 — invalid inputs
//   - provisioned_session.go:345.48,347.3  0 — replay epoch expires too soon
//   - provisioned_session.go:352.23,354.3  0 — issuer proof would be expired
//   - provisioned_session.go:357.59,359.3  0 — token nonce random read fails
//
// Reachability: one table subtest per guard, each crafted to trip exactly one
// guard and pass all earlier ones:
//   - empty issuer URL: issuerURL="" short-circuits :341 (first clause).
//   - replay epoch expires too soon: valid fields + ReplayEpochValidUntil=1
//     with now=Unix(0,0) so 1 <= 0+1 trips :345.
//   - issuer proof would be expired: ReplayEpochValidUntil=200, now=Unix(100),
//     lifetime=0 so expiry=100 (not clamped at :349 since 100<200) and
//     100<=100 trips :352.
//   - token nonce random read fails: ReplayEpochValidUntil=200, now=Unix(100),
//     lifetime=10s so expiry=110 passes :349/:352, then a faulting io.Reader
//     makes io.ReadFull return an error at :357.
//
// Error substring is asserted per subtest (self-validating: a guard that
// failed to fire would return a different/nil error -> Fatalf); the per-line
// coverage flip (0->1 per guard) is the rigorous proof. In-package
// (package client) matches the existing provisioned_session test family.
// Distinct filename + test name, a local failingRandomReader helper (no
// collision with existing client tests), no shared helpers. One TestXxx with
// four t.Run subtests; imports errors/io/strings/testing/time/handshake
// (all used) -> no U1000 surface.

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
)

// failingRandomReader is an io.Reader whose Read always returns an error,
// driving the :357 io.ReadFull guard of buildProvisionedIssuerWork.
type failingRandomReader struct{ err error }

func (r failingRandomReader) Read(p []byte) (int, error) { return 0, r.err }

func TestBuildProvisionedIssuerWorkRejectsInvalidInputs(t *testing.T) {
	// AdmissionContextHash must be exactly 48 bytes to pass the :341 guard.
	validHash := make([]byte, 48)

	cases := []struct {
		name     string
		url      string
		path     string
		request  handshake.ClientProofRequest
		now      time.Time
		lifetime time.Duration
		random   io.Reader
		wantSub  string
	}{
		{
			// :341 — issuerURL == "" short-circuits the first clause; the
			// function returns before touching random.
			name:     "empty issuer URL",
			url:      "",
			path:     "p",
			request:  handshake.ClientProofRequest{AdmissionContextHash: validHash, ReplayEpochValidUntil: 200},
			now:      time.Unix(100, 0),
			lifetime: 10 * time.Second,
			random:   strings.NewReader("unused"),
			wantSub:  "provisioned issuer work inputs are invalid",
		},
		{
			// :345 — ReplayEpochValidUntil=1, now=Unix(0,0): 1 <= 0+1 trips.
			name:     "replay epoch expires too soon",
			url:      "u",
			path:     "p",
			request:  handshake.ClientProofRequest{AdmissionContextHash: validHash, ReplayEpochValidUntil: 1},
			now:      time.Unix(0, 0),
			lifetime: 10 * time.Second,
			random:   strings.NewReader("unused"),
			wantSub:  "provisioned replay epoch expires too soon",
		},
		{
			// :352 — ReplayEpochValidUntil=200, now=Unix(100), lifetime=0:
			// expiry=100, not clamped at :349 (100<200), 100<=100 trips.
			name:     "issuer proof would be expired",
			url:      "u",
			path:     "p",
			request:  handshake.ClientProofRequest{AdmissionContextHash: validHash, ReplayEpochValidUntil: 200},
			now:      time.Unix(100, 0),
			lifetime: 0,
			random:   strings.NewReader("unused"),
			wantSub:  "provisioned issuer proof would be expired",
		},
		{
			// :357 — valid inputs + lifetime=10s (expiry=110 passes :349/:352),
			// then a faulting reader makes io.ReadFull fail.
			name:     "token nonce random read fails",
			url:      "u",
			path:     "p",
			request:  handshake.ClientProofRequest{AdmissionContextHash: validHash, ReplayEpochValidUntil: 200},
			now:      time.Unix(100, 0),
			lifetime: 10 * time.Second,
			random:   failingRandomReader{err: errors.New("boom")},
			wantSub:  "generate provisioned issuer token nonce",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildProvisionedIssuerWork(c.url, c.path, c.request, c.now, c.lifetime, c.random)
			if err == nil || !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("buildProvisionedIssuerWork(%s) err = %v, want non-nil containing %q", c.name, err, c.wantSub)
			}
		})
	}
}
