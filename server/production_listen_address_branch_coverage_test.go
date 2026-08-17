package server

// Adversarial white-box coverage for the two count-0 branches of
// validateProductionListenAddress in server/production.go: the empty/whitespace
// rejection (187-189) and the malformed host:port rejection (191-193).
//
// validateProductionListenAddress is the listen-address validator run by
// validateProductionFirstHopOptions (called from NewProductionFirstHopServer).
// It is a pure function of its string argument — no context, no receiver, no
// I/O — so both arms are reachable by a direct in-package call with a
// hand-picked malformed address:
//
//	func validateProductionListenAddress(address string) error {
//	    if address == "" || strings.TrimSpace(address) != address {  // 187
//	        return fmt.Errorf("server: production first-hop listen address is required")
//	    }
//	    host, portText, err := net.SplitHostPort(address)             // 190
//	    if err != nil || host == "" || portText == "" {                // 191
//	        return fmt.Errorf("server: production first-hop listen address is invalid")
//	    }
//	    ... // 195 port range, 199/203 loopback forbidden — already covered
//	}
//
//   - 187-189 — empty or untrimmed address. "" trips address == ""; " 1.2.3.4:443"
//     trips TrimSpace(address) != address (leading/trailing whitespace). Both
//     return the "required" error before SplitHostPort is ever called.
//   - 191-193 — malformed host:port. "noport" trips err != nil (no colon for
//     SplitHostPort); ":443" trips host == ""; "1.2.3.4:" trips portText == "".
//     All return the "invalid" error. The address is non-empty and trimmed, so
//     187 passes and execution reaches 190/191.
//
// The existing production tests drive validateProductionListenAddress only
// transitively through validateProductionFirstHopOptions with a valid address
// (which returns nil at 206), so the two early-exit arms stayed count-0 even
// though the validator is plainly reachable with a bad address. The
// downstream 195/199/203 branches (port range, localhost name, loopback IP)
// are already covered by production_test.go's address-table cases; only
// 187-189 and 191-193 were count-0.
//
// This is a table-driven pure-logic test: no context, no SA1012 surface, no
// receiver, no goroutine, no network. It adds no package-level helpers.

import (
	"strings"
	"testing"
)

func TestValidateProductionListenAddressRejectsEmptyAndUntrimmed(t *testing.T) {
	// 187-189: empty or untrimmed addresses return "required" before
	// SplitHostPort runs.
	cases := []string{
		"",             // trips address == ""
		" 1.2.3.4:443", // trips TrimSpace(address) != address (leading space)
		"1.2.3.4:443 ", // trips TrimSpace(address) != address (trailing space)
	}
	for _, addr := range cases {
		err := validateProductionListenAddress(addr)
		if err == nil {
			t.Errorf("validateProductionListenAddress(%q) err = nil, want non-nil (:187 should fire)", addr)
			continue
		}
		if !strings.Contains(err.Error(), "listen address is required") {
			t.Errorf("validateProductionListenAddress(%q) err = %v, want substring \"listen address is required\"", addr, err)
		}
	}
}

func TestValidateProductionListenAddressRejectsMalformedHostPort(t *testing.T) {
	// 191-193: a non-empty, trimmed address that still fails to parse as
	// host:port returns "invalid". Each case trips a distinct sub-clause of
	// the 191 condition.
	cases := []struct {
		addr string
		want string
	}{
		{"noport", "no colon -> net.SplitHostPort err != nil"},
		{":443", "empty host -> host == \"\""},
		{"1.2.3.4:", "empty port -> portText == \"\""},
	}
	for _, c := range cases {
		err := validateProductionListenAddress(c.addr)
		if err == nil {
			t.Errorf("validateProductionListenAddress(%q) err = nil, want non-nil (:191 should fire; %s)", c.addr, c.want)
			continue
		}
		if !strings.Contains(err.Error(), "listen address is invalid") {
			t.Errorf("validateProductionListenAddress(%q) err = %v, want substring \"listen address is invalid\" (%s)", c.addr, err, c.want)
		}
	}
}
