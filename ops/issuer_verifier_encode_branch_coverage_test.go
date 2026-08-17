package ops

// Adversarial white-box coverage for the three reachable count-0 branches in
// ops/ops.go that share one root cause: protocol.Encode of an
// IssuerVerifierRequest fails when a fixed-width field is nil or the wrong
// length, and the three callers surface that error.
//
//   - 221-223 — IssuerVerifierRequestHash (the root): protocol.Encode(req)
//     returns an error and IssuerVerifierRequestHash propagates it. This is a
//     public function that accepts any IssuerVerifierRequest, so a zero-valued
//     request (all nil slices) fails Encode at the very first fixed-width
//     write — WriteOpaqueFixed(r.ServiceID, 16) (issuer.go:588) records
//     "wire: fixed opaque length 0, want 16" — and IssuerVerifierRequestHash
//     returns that error.
//   - 186-188 — BuildIssuerVerifierRequest: after assembling req from the
//     input (164-184) it calls IssuerVerifierRequestHash(req) at 185 and
//     propagates the error. Two of the fields copied into req are NOT
//     validated by any of the earlier gates (the missing-replay-cache check
//     at 135, AdmissionProof.ValidateStructural at 138, Service.Allows at
//     141, verifierRequestAuthenticatorFields at 144, and
//     admission.VerifyAndSpendReplay at 148 all run BEFORE 164 and none of
//     them inspect these two request-only fields): RelayDescriptorHash
//     (copied at 169, written via WritePreHash at issuer.go:591) and
//     RequestNonce (copied at 182, written via WriteOpaqueFixed at
//     issuer.go:604). A caller that passes a valid AdmissionProof, Service,
//     and replay proof but a nil RelayDescriptorHash (or nil RequestNonce)
//     passes every gate up to 161, builds a req whose Encode then fails on
//     that nil fixed-width field, so :186 fires. That is a genuine guard
//     against unvalidated request input, not a contrived state.
//   - 235-237 — ValidateIssuerVerifierResponse: after the version (228) and
//     service-id (231) checks it recomputes the request hash at 234 via
//     IssuerVerifierRequestHash(req) and propagates the error. In the
//     integrated VerifyIssuerVerifierService path the req comes from
//     BuildIssuerVerifierRequest (123), which already hashed it successfully
//     at 185, so a req reaching ValidateIssuerVerifierResponse that way
//     always Encodes and :235 is dead-by-design there. But
//     ValidateIssuerVerifierResponse is a public function that accepts any
//     req, so a direct caller passing a malformed req (one whose Encode
//     fails) — while still satisfying :228 (ResponseVersion) and :231 (the
//     three ServiceIDs compare equal) — reaches :234 and fires :235. The
//     all-nil case satisfies :231 because bytes.Equal(nil, nil) is true, then
//     :234 fails Encode at WriteOpaqueFixed(ServiceID, 16).
//
// This is the same class of fixed-width length-mismatch error as the
// clientTransportHintsHashForPolicy / trust clone (#235) misclassifications:
// an Encode that looks scalar-bounded still fails on an uncapped-or-zeroed
// fixed-width field, and the guard is reachable because the caller does not
// pre-validate every fixed-width field before hashing. The happy paths of
// all three functions (a fully-populated, correctly-sized request Encodes and
// hashes to a 48-byte digest; BuildIssuerVerifierRequest with all fields
// valid succeeds; the integrated ValidateIssuerVerifierResponse path is
// covered by ops_coverage_test.go / ops_test.go) are locked here or noted as
// covered-elsewhere so each rejection is a meaningful contrast.
//
// The remaining count-0 branches in ops.go (verifierRequestAuthenticatorFields
// 196-198 / 203-205 / 210-212 / 214-215) are dead-by-design and already
// documented in ops_coverage_test.go (DecodeAuroraTokenMetadataBytes,
// RFC9577TokenChallengeDigest, RFC9577AuthenticatorInputHash re-decode/recompute
// after ValidateStructural already validated the same fields; the switch
// default needs a proof type other than VOPRF/BlindRSA, which the registry
// does not define and ValidateStructural rejects). They are NOT claimed here.
//
// This file adds no new helpers: it reuses rb, verifierServiceRecord, and
// verifierProofReplay (each already referenced by multiple tests in
// ops_test.go), and the :221/:235 cases build inline literals. So there is no
// staticcheck U1000 surface. No context.Context (no SA1012 surface), no
// goroutines, no cryptography, no network, no filesystem — IssuerVerifierRequestHash
// is a pure encode + prehash; BuildIssuerVerifierRequest up to :185 and
// ValidateIssuerVerifierResponse up to :234 are pure field-assembly + encode.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestIssuerVerifierRequestHashRejectsZeroStruct(t *testing.T) {
	// 221-223: a zero-valued IssuerVerifierRequest fails protocol.Encode at the
	// first fixed-width write — WriteOpaqueFixed(ServiceID, 16) sees a nil
	// ServiceID and records "wire: fixed opaque length 0, want 16" — so
	// IssuerVerifierRequestHash returns that error rather than a digest.
	_, err := IssuerVerifierRequestHash(protocol.IssuerVerifierRequest{})
	if err == nil {
		t.Fatal("IssuerVerifierRequestHash(zero) err = nil, want non-nil (Encode fixed-width failure)")
	}
	if !strings.Contains(err.Error(), "wire: fixed opaque length 0, want 16") {
		t.Fatalf("IssuerVerifierRequestHash(zero) err = %v, want substring \"wire: fixed opaque length 0, want 16\"", err)
	}
}

func TestIssuerVerifierRequestHashAcceptsValidRequest(t *testing.T) {
	// Happy-path lock so the :221 rejection is a meaningful contrast: a
	// fully-populated, correctly-sized IssuerVerifierRequest Encodes and hashes
	// to a 48-byte digest with no error.
	req := protocol.IssuerVerifierRequest{
		RequestVersion:            registry.Version20,
		ServiceID:                 rb(0x01, 16),
		IssuerID:                  rb(0x02, 16),
		IssuerMetadataHash:        rb(0x03, 48),
		RelayDescriptorHash:       rb(0x04, 48),
		RelayBucketID:             rb(0x05, 16),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ProofType:                 registry.ProofVOPRFP384SHA384,
		TokenKeyID:                rb(0x06, 32),
		TokenNonce:                rb(0x07, 32),
		ChallengeDigest:           rb(0x08, 32),
		AuthenticatorInputHash:    rb(0x09, 48),
		TokenAuthenticator:        []byte("auth"),
		TokenSpentKey:             rb(0x0a, 48),
		ReplayEpochID:             9,
		ReplayEpochValidUntilUnix: 800,
		RequestNonce:              rb(0x0b, 32),
		RequestTimeUnix:           100,
	}
	hash, err := IssuerVerifierRequestHash(req)
	if err != nil {
		t.Fatalf("IssuerVerifierRequestHash(valid) err = %v, want nil", err)
	}
	if len(hash) != 48 {
		t.Fatalf("IssuerVerifierRequestHash(valid) hash len = %d, want 48", len(hash))
	}
}

func TestBuildIssuerVerifierRequestRejectsMalformedFixedWidthField(t *testing.T) {
	// 186-188: two request-only fields copied into req (RelayDescriptorHash at
	// 169, RequestNonce at 182) are NOT inspected by any gate before :185, so a
	// valid AdmissionProof + Service + replay proof with either field nil
	// passes every check up to :161, then :185 IssuerVerifierRequestHash(req)
	// fails Encode on that nil fixed-width field.
	service := verifierServiceRecord()
	proof, replay, admissionContextHash, handshakeBinding := verifierProofReplay(t)

	base := func() IssuerVerifierRequestInput {
		return IssuerVerifierRequestInput{
			Service:                   service,
			AdmissionProof:            proof,
			ReplayProof:               replay,
			IssuerMetadataHash:        rb(0x30, 48),
			RelayDescriptorHash:       rb(0x31, 48),
			RouteInstanceID:           77,
			HopIndex:                  1,
			ReplayEpochValidUntilUnix: 800,
			RelayEpochValidUntilUnix:  900,
			HandshakeBindingContext:   handshakeBinding,
			AdmissionContextHash:      admissionContextHash,
			ChallengeDigest:           rb(0x32, 32),
			AuthenticatorInputHash:    rb(0x33, 48),
			TokenSpentCache:           admission.NewMemoryReplayCache(),
			BootstrapDedupCache:       admission.NewMemoryReplayCache(),
			RequestNonce:              rb(0x34, 32),
			RequestTimeUnix:           100,
			NowUnix:                   100,
			RequestAuthImplemented:    true,
		}
	}

	// Happy-path lock: the fully-populated input builds and hashes cleanly.
	if _, _, err := BuildIssuerVerifierRequest(base()); err != nil {
		t.Fatalf("BuildIssuerVerifierRequest(valid) err = %v, want nil", err)
	}

	t.Run("nilRelayDescriptorHash", func(t *testing.T) {
		in := base()
		in.RelayDescriptorHash = nil // copied at 169; not validated before :185
		_, _, err := BuildIssuerVerifierRequest(in)
		if err == nil {
			t.Fatal("BuildIssuerVerifierRequest(nil RelayDescriptorHash) err = nil, want non-nil (:186 should fire)")
		}
		if !strings.Contains(err.Error(), "wire: fixed opaque length 0, want 48") {
			t.Fatalf("BuildIssuerVerifierRequest(nil RelayDescriptorHash) err = %v, want substring \"wire: fixed opaque length 0, want 48\"", err)
		}
	})

	t.Run("nilRequestNonce", func(t *testing.T) {
		in := base()
		in.RequestNonce = nil // copied at 182; not validated before :185
		_, _, err := BuildIssuerVerifierRequest(in)
		if err == nil {
			t.Fatal("BuildIssuerVerifierRequest(nil RequestNonce) err = nil, want non-nil (:186 should fire)")
		}
		if !strings.Contains(err.Error(), "wire: fixed opaque length 0, want 32") {
			t.Fatalf("BuildIssuerVerifierRequest(nil RequestNonce) err = %v, want substring \"wire: fixed opaque length 0, want 32\"", err)
		}
	})
}

func TestValidateIssuerVerifierResponseRejectsMalformedRequest(t *testing.T) {
	// 235-237: a direct caller passing a malformed (all-nil) req that still
	// satisfies :228 (ResponseVersion == Version20) and :231 (the three
	// ServiceIDs compare equal — bytes.Equal(nil, nil) is true) reaches :234,
	// where IssuerVerifierRequestHash(req) fails Encode at WriteOpaqueFixed(
	// ServiceID, 16), and ValidateIssuerVerifierResponse propagates that error.
	// (In the integrated VerifyIssuerVerifierService path the req comes from
	// BuildIssuerVerifierRequest, which already hashed it successfully at 185,
	// so :235 is dead-by-design there; it is reachable via this public entry
	// point with a malformed req.)
	err := ValidateIssuerVerifierResponse(
		protocol.IssuerVerifierServiceRecord{},                               // ServiceID nil — matches below
		protocol.IssuerVerifierRequest{},                                     // all nil -> Encode fails at :234
		protocol.IssuerVerifierResponse{ResponseVersion: registry.Version20}, // ServiceID nil
		100,
	)
	if err == nil {
		t.Fatal("ValidateIssuerVerifierResponse(malformed req) err = nil, want non-nil (:235 should fire)")
	}
	if !strings.Contains(err.Error(), "wire: fixed opaque length 0, want 16") {
		t.Fatalf("ValidateIssuerVerifierResponse(malformed req) err = %v, want substring \"wire: fixed opaque length 0, want 16\"", err)
	}
}
