package transport

// Adversarial white-box coverage for two count-0 nil-response guards in
// HTTP2ClientCarrier.storeRoundTripResult. storeRoundTripResult records the
// outcome of an HTTP/2 round trip: when the result carries an error it records
// the error (and closes the response body if one is present), and when the
// result carries neither an error nor a response it synthesizes a "no
// response" error.
//
//   - http2_client.go:379 (*HTTP2ClientCarrier).storeRoundTripResult
//     result.err != nil (taken at :377) then result.response != nil ->
//     result.response.Body.Close() + responseClosed = true (the cleanup that
//     guards against calling Body.Close on a nil response). Fires after the
//     :377 err != nil branch and the :378 responseErr record, before the
//     :383 return.
//   - http2_client.go:385 (*HTTP2ClientCarrier).storeRoundTripResult
//     result.response == nil (with result.err == nil, so the :377 branch is
//     skipped) -> c.responseErr = "transport: HTTP/2 round trip returned no
//     response" (the guard that rejects a round trip that produced neither an
//     error nor a response). Fires after the :377 err != nil branch is skipped,
//     before the :387 return.
//
// The existing transport tests exercise storeRoundTripResult only indirectly
// through a real round trip that either succeeds (err == nil, response != nil
// -> :389 validate / :395 store) or fails with an error and no response (err !=
// nil, response == nil -> :378 record, :379 skipped, :383 return). The
// error-with-response path (:379 cleanup) and the no-response-without-error
// path (:385) stayed count-0 even though each is plainly reachable by calling
// storeRoundTripResult directly with a crafted http2RoundTripResult.
//
// Proof technique:
//
//   - :385 (nil-response clean return): call storeRoundTripResult with a
//     zero-value http2RoundTripResult (err == nil, response == nil) on a
//     zero-value HTTP2ClientCarrier (responseErr == nil). The :377 err != nil
//     branch is skipped (err is nil), :385 sees response == nil and sets
//     responseErr = "transport: HTTP/2 round trip returned no response". The
//     non-nil responseErr containing "round trip returned no response"
//     uniquely proves :386 ran: responseErr was nil on input and :386 is the
//     only site on this path that sets it. Pure (no IO; it only assigns a
//     field).
//
//   - :379 (nil-response cleanup): call storeRoundTripResult with a non-nil
//     sentinel err and a real *http.Response{Body: http.NoBody}. The :377 err
//     != nil branch records responseErr = sentinel at :378; :379 sees response
//     != nil and closes the body at :380 (http.NoBody.Close is a safe nil-op)
//     and sets responseClosed = true at :381. responseClosed == true uniquely
//     proves :381 ran: responseClosed was false on input, :381 is the only site
//     on this path that sets it (the :392 site is in the validate-error branch
//     at :389, which is unreachable once :383 returns). errors.Is(responseErr,
//     sentinel) confirms :378. Pure (http.NoBody does no real IO).
//
// Neither guard involves a context at the guard site, so there is no SA1012
// surface. In-package (package transport) because storeRoundTripResult,
// HTTP2ClientCarrier, and http2RoundTripResult are unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (HTTP2ClientCarrier, http2RoundTripResult,
// storeRoundTripResult) symbols and the standard library http / errors /
// strings packages, so it adds no U1000 surface.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestStoreRoundTripResultNilResponseWithoutErrorGuard(t *testing.T) {
	// 385: a zero-value http2RoundTripResult has err == nil (so :377 is skipped)
	// and response == nil (so :385 fires and :386 sets responseErr). responseErr
	// was nil on input and :386 is the only site on this path that sets it.
	c := &HTTP2ClientCarrier{}
	c.storeRoundTripResult(http2RoundTripResult{})
	if c.responseErr == nil {
		t.Fatal("storeRoundTripResult(zero result) left responseErr = nil, want non-nil (:386 sets the no-response error)")
	}
	if !strings.Contains(c.responseErr.Error(), "round trip returned no response") {
		t.Fatalf("responseErr = %q, want it to contain \"round trip returned no response\" (:386)", c.responseErr.Error())
	}
}

func TestStoreRoundTripResultErrorWithResponseCleanupGuard(t *testing.T) {
	// 379: a result with a non-nil err and a real response takes the :377 branch
	// (records responseErr = sentinel at :378), then :379 sees response != nil,
	// closes the body at :380 (http.NoBody.Close is a safe nil-op) and sets
	// responseClosed = true at :381. responseClosed == true uniquely proves :381
	// ran (it was false on input; :392 is unreachable once :383 returns).
	sentinel := errors.New("boom")
	c := &HTTP2ClientCarrier{}
	c.storeRoundTripResult(http2RoundTripResult{err: sentinel, response: &http.Response{Body: http.NoBody}})
	if !errors.Is(c.responseErr, sentinel) {
		t.Fatalf("responseErr = %v, want sentinel %v (:378 records the round-trip error)", c.responseErr, sentinel)
	}
	if !c.responseClosed {
		t.Fatal("responseClosed = false, want true (:381 marks the response body closed after the :379 nil-response guard passed)")
	}
}
