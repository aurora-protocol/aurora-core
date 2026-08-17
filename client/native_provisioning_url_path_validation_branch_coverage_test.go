package client

// Adversarial white-box coverage for the eight count-0 pure-string-validation
// guards of validateNativeHTTPSURL and validateNativeCarrierPath
// (client/native_provisioning.go:852/:856/:859/:863/:868 + :875/:879/:882).
// This generalizes the #362 input-validation-in-pure-func vein to URL/path
// validators: both helpers take a string and return an error, with NO crypto,
// NO network, NO ValidateStructural — reachability is crafted strings only.
//
// validateNativeHTTPSURL(raw string, requirePath bool) error validates in order:
//   - :852  len(raw)==0 || len(raw) > maximumNativeProvisioningURLBytes
//        -> "URL length is invalid"
//   - :856  url.ParseRequestURI(raw) err -> return err  (raw ParseRequestURI err)
//   - :859  scheme!="https" || Host=="" || Hostname()=="" || User!=nil ||
//        RawQuery!="" || Fragment!="" || RawPath!="" -> "URL must be an HTTPS
//        authority without user info, query, or fragment"
//   - :863  (requirePath) validateNativeCarrierPath(parsed.Path) err ->
//        "URL path: %w"  (WRAPS validateNativeCarrierPath's error)
//   - :868  (!requirePath) parsed.Path != "" -> "issuer URL must not include a path"
//
// validateNativeCarrierPath(raw string) error validates in order:
//   - :875  len(raw)<2 || len(raw) > maximumNativeProvisioningURLBytes ||
//        !strings.HasPrefix(raw,"/") -> "path length or prefix is invalid"
//   - :879  url.ParseRequestURI(raw) err -> return err  (raw ParseRequestURI err)
//   - :882  parsed.IsAbs() || parsed.Host!="" || parsed.RawQuery!="" ||
//        parsed.Fragment!="" || parsed.Path!=raw || path.Clean(raw)!=raw ||
//        strings.Contains(raw,"//") -> "path is not canonical"
//
// No existing test references either helper (confirmed via grep), so all eight
// guards stayed COUNT 0 in the baseline (confirmed: each body count=0 on a clean
// tree; client 82.7%). The happy paths elsewhere in the package exercise the
// callers, not these validators' failure branches.
//
// Coverage targets (baseline measured on a clean tree; bodies COUNT 0):
//   - native_provisioning.go:852.67,854.3 0  — URL length invalid
//   - native_provisioning.go:856.16,858.3 0  — ParseRequestURI err (URL)
//   - native_provisioning.go:859.174,861.3 0 — not an HTTPS authority
//   - native_provisioning.go:863.64,865.4 0  — carrier path invalid (wraps inner)
//   - native_provisioning.go:868.23,870.3 0  — issuer URL has a path
//   - native_provisioning.go:875.98,877.3 0  — path length/prefix invalid
//   - native_provisioning.go:879.16,881.3 0  — ParseRequestURI err (path)
//   - native_provisioning.go:882.170,884.3 0 — path not canonical
//
// Reachability — one subtest per guard, each crafted to trip exactly ONE outer
// guard (the :863 subtest necessarily also trips an inner validateNativeCarrierPath
// guard since :863 wraps it; that is expected and the per-line flip still
// attributes :863 cleanly):
//   - :852  raw="" (len 0) trips before any parse.
//   - :856  raw="https://%invalid" has a valid length but a malformed %-escape,
//     so url.ParseRequestURI fails before :859 is reached.
//   - :859  raw="http://example.com" parses cleanly but scheme is "http" (!= "https").
//   - :868  raw="https://example.com/p", requirePath=false: parses cleanly, is a
//     valid HTTPS authority, but parsed.Path is non-empty while requirePath is false.
//   - :863  raw="https://example.com", requirePath=true: valid HTTPS authority,
//     parsed.Path is "" -> validateNativeCarrierPath("") trips :875 -> :863 wraps it.
//   - :875  raw="x" (len 1 < 2, no "/" prefix).
//   - :879  raw="/%zz": len 4 >= 2 with "/" prefix (passes :875) but the malformed
//     %-escape makes url.ParseRequestURI fail.
//   - :882  raw="/a//b": len 6 >= 2, "/" prefix, parses cleanly, but contains "//".
//
// The :856/:879 guards return url.ParseRequestURI's raw error, whose message has
// contained the substring "invalid URL escape" in net/url for the whole Go 1.x
// line; asserting that substring self-validates that the failure is the parse
// guard (not an accidental hit of a neighboring guard). The remaining guards
// assert their exact fmt.Errorf message. The per-line coverage flip (0->1 per
// guard) is the rigorous proof. In-package (package client) is required (both
// helpers are unexported) and matches the existing native_provisioning test
// family. Distinct filename + test name, no shared helpers, no collision with
// existing client tests. One TestXxx with eight t.Run subtests; imports
// strings/testing (all used) -> no U1000 surface.

import (
	"strings"
	"testing"
)

func TestValidateNativeHTTPSURLAndCarrierPathRejectInvalidInput(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		requirePath bool
		pathInput   string
		// direct selects which helper to call: false -> validateNativeHTTPSURL,
		// true -> validateNativeCarrierPath (pathInput is the raw arg).
		direct  bool
		wantSub string
	}{
		// validateNativeHTTPSURL guards
		{"https url length invalid", "", false, "", false, "URL length is invalid"},
		{"https parse request uri fails", "https://%invalid", false, "", false, "invalid URL escape"},
		{"https not an https authority", "http://example.com", false, "", false, "URL must be an HTTPS authority without user info, query, or fragment"},
		{"https issuer url has a path", "https://example.com/p", false, "", false, "issuer URL must not include a path"},
		{"https carrier path invalid", "https://example.com", true, "", false, "URL path:"},
		// validateNativeCarrierPath guards
		{"path length or prefix invalid", "", false, "x", true, "path length or prefix is invalid"},
		{"path parse request uri fails", "", false, "/%zz", true, "invalid URL escape"},
		{"path not canonical", "", false, "/a//b", true, "path is not canonical"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			if c.direct {
				err = validateNativeCarrierPath(c.pathInput)
			} else {
				err = validateNativeHTTPSURL(c.url, c.requirePath)
			}
			if err == nil || !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("%s: err = %v, want non-nil containing %q", c.name, err, c.wantSub)
			}
		})
	}
}
