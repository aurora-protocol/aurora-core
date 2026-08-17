package issuerd

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across issuerd/http.go. Each guard exists so a caller that passes a
// nil response / request / http.Request — or holds a nil verifier value — does
// not panic or proceed into the encode / decode / field-erase path: the
// function returns at its very first statement, before any field is
// dereferenced (response.ServiceID, request.ServiceID, r.Body, r.ContentLength)
// or any helper / encoder is called (protocol.Encode, zeroIssuerdBytes,
// json.NewDecoder). The existing issuerd tests only ever drive populated
// requests/responses along the live HTTP handler path, so the nil guards
// stayed count-0 even though each is plainly reachable.
//
// These are nil-ARGUMENT guards. None take a context, so there is no SA1012
// surface. No network connection is opened — the nil guards return before any
// http.ResponseWriter / http.Request body is touched, and the two zeroers only
// ever zero in-memory byte slices. The test is in-package (package issuerd)
// because writeIssuerVerifierResponse, decodeVerifierRequest,
// zeroIssuerVerifierRequest, zeroIssuerVerifierResponse, and decodeJSONBody
// are unexported.
//
// Error-returning nil-arg guards (assert on the returned error string):
//   - :491 writeIssuerVerifierResponse(nil, nil)
//     response == nil -> "issuerd: missing verifier response" (fires before
//     the deferred zeroIssuerVerifierResponse / protocol.Encode / w.Write)
//   - :518 decodeVerifierRequest(nil)
//     r == nil || r.Body == nil -> "issuerd: missing verifier request body"
//     (the || short-circuits on the nil-r side; fires before the
//     r.ContentLength / r.Body reads)
//   - :675 decodeJSONBody(nil, nil)
//     r == nil || r.Body == nil -> "issuerd: missing JSON request body"
//     (same short-circuit; fires before r.ContentLength / json.NewDecoder)
//
// Void nil-arg zeroer guards (no-panic proof):
//   - :626 zeroIssuerVerifierRequest(nil)
//     request == nil -> no-op return (fires before the field-erase loop and
//     the *request = protocol.IssuerVerifierRequest{} assignment)
//   - :649 zeroIssuerVerifierResponse(nil)
//     response == nil -> no-op return (fires before the field-erase loop)
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestIssuerdHTTPNilArgumentErrorGuards(t *testing.T) {
	// 491/518/675: the three error-returning helpers return at their first
	// statement when given a nil argument, before touching the response
	// writer / request body / decoder. writeIssuerVerifierResponse takes an
	// http.ResponseWriter first, but the response==nil guard fires before w is
	// ever read, so a nil writer is safe.

	// 491: writeIssuerVerifierResponse(nil, nil) returns "missing verifier
	// response".
	if err := writeIssuerVerifierResponse(nil, nil); err == nil {
		t.Fatal("writeIssuerVerifierResponse(nil,nil) err = nil, want non-nil (:491 should reject)")
	} else if !strings.Contains(err.Error(), "missing verifier response") {
		t.Fatalf("writeIssuerVerifierResponse(nil,nil) err = %q, want substring \"missing verifier response\" (:491)", err.Error())
	}

	// 518: decodeVerifierRequest(nil) returns "missing verifier request body".
	if _, err := decodeVerifierRequest(nil); err == nil {
		t.Fatal("decodeVerifierRequest(nil) err = nil, want non-nil (:518 should reject)")
	} else if !strings.Contains(err.Error(), "missing verifier request body") {
		t.Fatalf("decodeVerifierRequest(nil) err = %q, want substring \"missing verifier request body\" (:518)", err.Error())
	}

	// 675: decodeJSONBody(nil, nil) returns "missing JSON request body".
	if err := decodeJSONBody(nil, nil); err == nil {
		t.Fatal("decodeJSONBody(nil,nil) err = nil, want non-nil (:675 should reject)")
	} else if !strings.Contains(err.Error(), "missing JSON request body") {
		t.Fatalf("decodeJSONBody(nil,nil) err = %q, want substring \"missing JSON request body\" (:675)", err.Error())
	}
}

func TestIssuerdZeroerNilArgumentGuards(t *testing.T) {
	// 626/649: the two unexported zeroers return at their first statement when
	// given a nil pointer, before iterating the value's fields or assigning
	// the zero struct. Each is void; the proof is that the call completes
	// without panicking (a panic surfaces as a test failure).
	zeroIssuerVerifierRequest(nil)
	zeroIssuerVerifierResponse(nil)
}
