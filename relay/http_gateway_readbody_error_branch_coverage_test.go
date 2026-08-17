package relay

// Adversarial white-box coverage for the count-0 read-error branch of
// HTTPGatewayHandler.readRequestBody in relay/http_gateway.go (61-81):
//
//	func (h HTTPGatewayHandler) readRequestBody(r *http.Request) ([]byte, error) {
//	    maxBodyBytes := h.MaxBodyBytes
//	    if maxBodyBytes <= 0 {
//	        maxBodyBytes = defaultHTTPGatewayMaxBodyBytes
//	    }
//	    defer r.Body.Close()
//	    readLimit := maxBodyBytes
//	    if readLimit < math.MaxInt64 {
//	        readLimit++
//	    }
//	    body, err := io.ReadAll(io.LimitReader(r.Body, readLimit))
//	    if err != nil {                       // 72 — count-0
//	        zeroHTTPGatewayBody(body)          // 73
//	        return nil, err                    // 74-75
//	    }
//	    ...
//	}
//
// readRequestBody reads the cover-request body up to MaxBodyBytes (defaulting to
// defaultHTTPGatewayMaxBodyBytes when h.MaxBodyBytes <= 0). The 72-75 arm
// handles a mid-read failure from the request body: it scrubs any partial bytes
// (zeroHTTPGatewayBody) and returns the error. The existing relay_test.go
// HTTP-gateway tests always feed a complete, well-formed body (strings.NewReader
// / bytes.NewReader never error before EOF), so io.ReadAll returns nil and the
// 72-75 arm stayed count-0 even though it is plainly reachable: a request whose
// body fails mid-read (a truncated stream, a network error surfaced as a Reader
// error) hits it.
//
// The arm is reached WITHOUT any custom helper type by injecting a failing
// body from the standard library: io.NopCloser(iotest.ErrReader(err)) is an
// io.ReadCloser whose Read always returns err (and whose Close is a no-op, so
// the deferred r.Body.Close() is safe). A zero-valued HTTPGatewayHandler
// (MaxBodyBytes == 0 -> the default limit) supplies a positive readLimit, so
// io.LimitReader passes the read through to the failing body and io.ReadAll
// surfaces err. readRequestBody is unexported, so the call is in-package.
//
// The asserted error (errors.Is against the injected sentinel) proves the
// returned error is the body's read failure — the only path by which a
// non-nil err leaves readRequestBody here — so 72-75 ran. No context, no
// network, no goroutine, no new package-level helpers (stdlib only).

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"testing/iotest"
)

func TestHTTPGatewayReadRequestBodyPropagatesBodyReadError(t *testing.T) {
	// 72-75: a request body whose Read fails makes io.ReadAll return that
	// error, so readRequestBody scrubs the partial body and returns it. The
	// injected sentinel is the only error readRequestBody can return on this
	// path (no validation runs before the read), so errors.Is proves 72-75 ran.
	bodyErr := errors.New("simulated cover-request body read failure")
	h := HTTPGatewayHandler{}
	r := &http.Request{Body: io.NopCloser(iotest.ErrReader(bodyErr))}

	got, err := h.readRequestBody(r)
	if err == nil {
		t.Fatal("readRequestBody(failing body) err = nil, want non-nil (:72-75 should propagate the read error)")
	}
	if !errors.Is(err, bodyErr) {
		t.Fatalf("readRequestBody(failing body) err = %v, want errors.Is the injected sentinel (the body's read failure)", err)
	}
	if len(got) != 0 {
		t.Fatalf("readRequestBody(failing body) got = %d bytes, want 0 (partial body should be scrubbed at :73)", len(got))
	}
}
