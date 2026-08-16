package ops

// Adversarial white-box coverage for two pure helpers of
// ops/verifier_transport.go: issuerVerifierEndpoint (191-208) and
// decodeIssuerVerifierResponse (178-189). Both are deterministic value
// transforms with no live network, no TLS, no x509, and no cryptography:
//
//   - issuerVerifierEndpoint builds an https:// endpoint URL from a verifier
//     service record. It validates the service protocol id, the locator type,
//     and the authority string, then runs the authority through net/url's pure
//     string parser and rejects any parse that smuggles a scheme, userinfo,
//     path, query, or fragment. The three early-return guards (protocol,
//     locator-type, empty-authority) are reached with plain struct literals;
//     the url.Parse constraint branch at :204 is already exercised by the
//     harness and is used here only as a semantic contrast for the
//     empty-authority case.
//   - decodeIssuerVerifierResponse is a thin wire decoder wrapper: it hands the
//     body to a wire.Reader, decodes an IssuerVerifierResponse, and rejects a
//     reader error (:183, already covered) or trailing bytes after a clean
//     decode (:186). A valid IssuerVerifierResponse encodes cleanly even from
//     a zero value (every fixed-width write accepts a nil slice as zero
//     padding), so the trailing-bytes branch is reached by appending one byte
//     to a valid encoding.
//
// Targets covered (previously count-0):
//
//   - issuerVerifierEndpoint:193-194 — the ServiceProtocolID !=
//     registry.IssuerVerifierVOPRFMTLS13 guard. The existing suite drives the
//     helper only with the mTLS13 protocol, so the "not mTLS13" return is
//     unreached. A record with any other protocol id hits it before the locator
//     is inspected.
//   - issuerVerifierEndpoint:196-197 — the ServiceLocator.LocatorType !=
//     registry.LocatorAuthority guard. The existing suite drives the helper
//     only with an authority locator, so the "must be authority" return is
//     unreached. A record with the right protocol but a non-authority locator
//     type hits it.
//   - issuerVerifierEndpoint:200-201 — the empty-authority guard. The existing
//     suite always passes a non-empty authority, so the "empty verifier service
//     authority" return is unreached. A record with the right protocol and
//     locator type but a zero-length LocatorBody hits it. A contrast with a
//     userinfo-bearing authority (which fails the url.Parse constraint at :204,
//     already covered) locks the semantic that :200 fires specifically on
//     emptiness, not on any malformed authority.
//   - decodeIssuerVerifierResponse:186-187 — the trailing-bytes return. The
//     existing suite drives the decoder only with exact-length encodings, so
//     the "trailing verifier response bytes" return is unreached. Appending one
//     byte to a valid encoding makes the full response decode cleanly
//     (reader.Err() nil) while reader.EOF() is still false, so :186 fires. A
//     contrast with a truncated encoding (which fails at :183, already covered)
//     locks the semantic that :186 fires only when the decode itself succeeded.
//
// validVerifierService is referenced by five tests (the three error guards,
// the url.Parse contrast, and the success lock), so there is no staticcheck
// U1000 surface. No context.Context (no SA1012 surface), no goroutines, no
// cryptography, no real network or filesystem.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

// validVerifierService returns an IssuerVerifierServiceRecord whose endpoint
// builds cleanly: the mTLS13 protocol, an authority locator, and a non-empty
// authority host:port. Each endpoint test mutates exactly one of these three
// fields to trip one guard.
func validVerifierService() protocol.IssuerVerifierServiceRecord {
	return protocol.IssuerVerifierServiceRecord{
		ServiceProtocolID: registry.IssuerVerifierVOPRFMTLS13,
		ServiceLocator: protocol.RoutingRecord{
			LocatorType: registry.LocatorAuthority,
			LocatorBody: []byte("verifier.example:443"),
		},
	}
}

func TestIssuerVerifierEndpointRejectsUnsupportedProtocol(t *testing.T) {
	// 193-194: a non-mTLS13 protocol id returns before the locator is
	// inspected, so the locator fields are irrelevant here.
	svc := validVerifierService()
	svc.ServiceProtocolID = 0
	_, err := issuerVerifierEndpoint(svc)
	if err == nil ||
		!strings.Contains(err.Error(), "verifier service protocol 0x0 is not mTLS13") {
		t.Fatalf("issuerVerifierEndpoint(protocol 0) err = %v, want substring \"verifier service protocol 0x0 is not mTLS13\"", err)
	}
}

func TestIssuerVerifierEndpointRejectsNonAuthorityLocator(t *testing.T) {
	// 196-197: the right protocol but a non-authority locator type fails the
	// locator guard.
	svc := validVerifierService()
	svc.ServiceLocator.LocatorType = 0
	_, err := issuerVerifierEndpoint(svc)
	if err == nil ||
		!strings.Contains(err.Error(), "verifier service locator must be authority") {
		t.Fatalf("issuerVerifierEndpoint(locator type 0) err = %v, want substring \"verifier service locator must be authority\"", err)
	}
}

func TestIssuerVerifierEndpointRejectsEmptyAuthority(t *testing.T) {
	// 200-201: the right protocol and locator type but a zero-length authority
	// fails the empty-authority guard.
	svc := validVerifierService()
	svc.ServiceLocator.LocatorBody = nil
	_, err := issuerVerifierEndpoint(svc)
	if err == nil ||
		!strings.Contains(err.Error(), "empty verifier service authority") {
		t.Fatalf("issuerVerifierEndpoint(empty authority) err = %v, want substring \"empty verifier service authority\"", err)
	}

	// Contrast: a non-empty authority that smuggles userinfo fails the url.Parse
	// constraint at :204 (already covered), not the empty-authority guard at
	// :200. This locks the semantic that :200 fires specifically on emptiness.
	userinfo := validVerifierService()
	userinfo.ServiceLocator.LocatorBody = []byte("verifier@example.com")
	_, err = issuerVerifierEndpoint(userinfo)
	if err == nil ||
		!strings.Contains(err.Error(), "verifier service locator must contain only an authority") {
		t.Fatalf("issuerVerifierEndpoint(userinfo authority) err = %v, want substring \"verifier service locator must contain only an authority\"", err)
	}
}

func TestIssuerVerifierEndpointSucceedsAndBuildsHTTPSURL(t *testing.T) {
	// Success lock for the non-error path so the :193/:196/:200 guards are
	// meaningful contrasts, and a lock on the URL construction: an authority
	// host:port becomes an https:// URL with a trailing slash and no userinfo.
	endpoint, err := issuerVerifierEndpoint(validVerifierService())
	if err != nil {
		t.Fatalf("issuerVerifierEndpoint(valid) err = %v, want nil", err)
	}
	if endpoint != "https://verifier.example:443/" {
		t.Fatalf("issuerVerifierEndpoint(valid) = %q, want \"https://verifier.example:443/\"", endpoint)
	}
}

func TestDecodeIssuerVerifierResponseRejectsTrailingBytes(t *testing.T) {
	// A zero-value IssuerVerifierResponse encodes cleanly (every fixed-width
	// write accepts a nil slice as zero padding), so this is a valid encoding to
	// build the trailing-bytes case from. Encode a non-trivial response so the
	// success round-trip below is a real lock, not a zero-over-zero tautology.
	resp := protocol.IssuerVerifierResponse{
		ResponseVersion:  7,
		ServiceID:        bytes.Repeat([]byte{0xAB}, 16),
		RequestHash:      make([]byte, 48),
		Decision:         1,
		DecisionDetail:   2,
		TokenSpentKey:    make([]byte, 48),
		ValidUntilUnix:   9_999_999,
		ResponseNonce:    bytes.Repeat([]byte{0xCD}, 32),
		ServiceSignature: []byte("sig"),
	}
	enc := wire.NewEncoder()
	resp.EncodeTo(enc)
	valid, err := enc.Bytes()
	if err != nil {
		t.Fatalf("encode IssuerVerifierResponse err = %v, want nil", err)
	}

	// Success round-trip lock: an exact-length encoding decodes with no error
	// and the scalar fields survive. This grounds the trailing-bytes case as a
	// contrast (the decode itself succeeds; only extra bytes remain).
	out, err := decodeIssuerVerifierResponse(append([]byte(nil), valid...))
	if err != nil {
		t.Fatalf("decodeIssuerVerifierResponse(valid) err = %v, want nil", err)
	}
	if out.ResponseVersion != 7 || out.Decision != 1 || out.DecisionDetail != 2 ||
		out.ValidUntilUnix != 9_999_999 || len(out.ServiceID) != 16 || len(out.ResponseNonce) != 32 {
		t.Fatalf("decodeIssuerVerifierResponse(valid) round-trip mismatch: %+v", out)
	}
	if !bytes.Equal(out.ServiceID, resp.ServiceID) || !bytes.Equal(out.ResponseNonce, resp.ResponseNonce) {
		t.Fatal("decodeIssuerVerifierResponse(valid) fixed-width slice mismatch")
	}

	// 186-187: appending one byte makes the full response decode cleanly
	// (reader.Err() nil) while reader.EOF() is still false, so :186 fires.
	trailing := append(append([]byte(nil), valid...), 0xEE)
	_, err = decodeIssuerVerifierResponse(trailing)
	if err == nil ||
		!strings.Contains(err.Error(), "trailing verifier response bytes") {
		t.Fatalf("decodeIssuerVerifierResponse(trailing) err = %v, want substring \"trailing verifier response bytes\"", err)
	}

	// Contrast: a truncated encoding fails the decode itself at :183 (already
	// covered), returning a non-nil reader error rather than the trailing-bytes
	// error. This locks the semantic that :186 fires only after a clean decode.
	_, err = decodeIssuerVerifierResponse([]byte{0x01, 0x02})
	if err == nil ||
		strings.Contains(err.Error(), "trailing verifier response bytes") {
		t.Fatalf("decodeIssuerVerifierResponse(truncated) err = %v, want a decode error (not trailing bytes)", err)
	}
}
