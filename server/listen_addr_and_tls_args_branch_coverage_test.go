package server

// Adversarial white-box coverage for the three count-0 input-validation guards
// of ListenAndServe and ListenAndServeTLS that the existing
// nil_handler_and_carrier_nil_arg_branch_coverage_test.go deliberately left
// untouched: the empty-addr guards (server.go:169 / :188) and the empty
// certFile/keyFile guard (server.go:194). This is the companion to that file:
// it covers exactly the three guards its sibling skips.
//
// The sibling test passes a NON-EMPTY addr + nil handler so the :172 / :191
// "handler is required" guard fires (and its header comment at :43-45 notes the
// :194 cert/key guard "is never reached because :191 returns first"). So :169
// (addr == ""), :188 (addr == ""), and :194 (certFile == "" || keyFile == "")
// stayed COUNT 0 in the baseline (confirmed: :169 body count=0, :188 body
// count=0, :194 both || operand blocks count=0 on a clean tree; server 87.1%).
//
// ListenAndServe(addr string, handler http.Handler) error (server.go:168):
//   - :169  addr == "" -> "server: listen address is required"  (FIRST guard;
//     returns before :172 handler check and before :175 http.Server construct /
//     :180 server.ListenAndServe -> no socket is ever bound).
// ListenAndServeTLS(addr, handler, certFile, keyFile string) error (:187):
//   - :188  addr == "" -> "server: listen address is required"  (FIRST guard;
//     returns before :191 handler check, :194 cert/key check, :197 http.Server
//     construct / :202 server.ListenAndServeTLS -> no socket bound, no file
//     read).
//   - :194  certFile == "" || keyFile == "" -> "server: TLS certificate and
//     key are required"  (returns before :197 / :202 -> no file read, no socket
//     bound). Two || operand blocks: certFile == "" (first) and keyFile == ""
//     (second, evaluated only when certFile != "").
//
// Coverage targets (baseline measured on a clean tree; bodies COUNT 0):
//   - server.go:169.16,171.3 0  — ListenAndServe addr empty
//   - server.go:188.16,190.3 0  — ListenAndServeTLS addr empty
//   - server.go:194.2,194.37 0  — certFile == "" operand
//   - server.go:194.37,196.3 0  — keyFile == "" operand + return body
//
// Reachability — one subtest per guard, each crafted to trip exactly one guard
// and return before any http.Server is constructed or any socket/file is touched:
//   - :169  ListenAndServe("", h): addr == "" fires at :169 (the handler is
//     non-nil so :172 would pass, but :169 returns first).
//   - :188  ListenAndServeTLS("", h, "cert.pem", "key.pem"): addr == "" fires at
//     :188 (handler non-nil so :191 would pass; cert/key non-empty so :194 would
//     pass; but :188 returns first).
//   - :194 certFile==""  ListenAndServeTLS("127.0.0.1:0", h, "", "key.pem"):
//     addr non-empty (:188 pass), handler non-nil (:191 pass), certFile == ""
//     trips :194 first operand -> body. (keyFile == "" second operand is
//     short-circuited, not evaluated.)
//   - :194 keyFile==""  ListenAndServeTLS("127.0.0.1:0", h, "cert.pem", ""):
//     certFile non-empty so the first operand is false (evaluated), then keyFile
//     == "" makes the second operand true -> :194 body. Covers the second ||
//     operand block.
//
// The non-nil handler is http.HandlerFunc(func(http.ResponseWriter,
// *http.Request){}); every guard returns before the http.Server is constructed,
// so the handler is never invoked and no socket is bound -> the tests are pure.
// The exact fmt.Errorf message is asserted per subtest (self-validating); the
// per-line coverage flip (0 -> 1+ per guard) is the rigorous proof. In-package
// (package server) matches the existing listen-serve test family. Distinct
// filename + test name, no shared helpers, no collision with the sibling
// nil_handler test or any existing server test. One TestXxx with four t.Run
// subtests; imports net/http, strings, testing (all used) -> no U1000 surface.
// No context is involved -> no SA1012 surface.

import (
	"net/http"
	"strings"
	"testing"
)

func TestListenAndServeAndTLSRejectMissingAddrAndCert(t *testing.T) {
	// A non-nil handler that is never invoked: every guard under test returns
	// before the http.Server is constructed, so no socket is ever bound.
	nonNil := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	cases := []struct {
		name    string
		call    func() error
		wantSub string
	}{
		{
			// :169 — addr == "" fires at the first guard of ListenAndServe.
			name:    "listen and serve missing addr",
			call:    func() error { return ListenAndServe("", nonNil) },
			wantSub: "server: listen address is required",
		},
		{
			// :188 — addr == "" fires at the first guard of ListenAndServeTLS,
			// before the :191 handler check and :194 cert/key check.
			name:    "listen and serve tls missing addr",
			call:    func() error { return ListenAndServeTLS("", nonNil, "cert.pem", "key.pem") },
			wantSub: "server: listen address is required",
		},
		{
			// :194 (certFile == "") — addr non-empty + handler non-nil reach
			// :194; the empty certFile trips the first || operand.
			name:    "listen and serve tls missing cert file",
			call:    func() error { return ListenAndServeTLS("127.0.0.1:0", nonNil, "", "key.pem") },
			wantSub: "server: TLS certificate and key are required",
		},
		{
			// :194 (keyFile == "") — certFile non-empty so the first operand is
			// evaluated false, then the empty keyFile trips the second || operand.
			name:    "listen and serve tls missing key file",
			call:    func() error { return ListenAndServeTLS("127.0.0.1:0", nonNil, "cert.pem", "") },
			wantSub: "server: TLS certificate and key are required",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.call()
			if err == nil || !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("%s: err = %v, want non-nil containing %q", c.name, err, c.wantSub)
			}
		})
	}
}
