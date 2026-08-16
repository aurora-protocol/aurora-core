package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/registry"
)

// TestIsExtensionSection covers every recognized extension prefix and the
// non-extension cases (recognized tables, empty). isExtensionSection gates
// forward-compatible unknown sections so parsers ignore x./ext./extension.*
// blocks rather than failing closed on them.
func TestIsExtensionSection(t *testing.T) {
	cases := []struct {
		section string
		want    bool
	}{
		{"x.foo", true},
		{"x.", true},
		{"ext.bar", true},
		{"extension.baz", true},
		{"extensions.qux", true},
		{"aurora", false},
		{"local", false},
		{"bogus", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isExtensionSection(tc.section); got != tc.want {
			t.Fatalf("isExtensionSection(%q) = %v, want %v", tc.section, got, tc.want)
		}
	}
}

// TestRouteNameToIDAllRoutes covers each named route and the default fallback.
// The oracle is the registry constant each name maps to; an unknown name falls
// back to RouteAuto.
func TestRouteNameToIDAllRoutes(t *testing.T) {
	cases := []struct {
		name string
		want uint64
	}{
		{"fast-1", registry.RouteFast1},
		{"split-2", registry.RouteSplit2},
		{"safe-3", registry.RouteSafe3},
		{"bridge-split", registry.RouteBridgeSplit},
		{"auto", registry.RouteAuto},
		{"unknown-route", registry.RouteAuto},
		{"", registry.RouteAuto},
	}
	for _, tc := range cases {
		if got := RouteNameToID(tc.name); got != tc.want {
			t.Fatalf("RouteNameToID(%q) = 0x%x, want 0x%x", tc.name, got, tc.want)
		}
	}
}

// TestValidateRejectsEachInvalidField drives each Validate error branch by
// mutating a single field of an otherwise-valid (Default) config. Each case is
// paired with the error substring it must produce.
func TestValidateRejectsEachInvalidField(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"unsupported version", func(c *Config) { c.Version = "1.0" }, "unsupported version"},
		{"unknown profile", func(c *Config) { c.Profile = "bogus-profile" }, ""},
		{"unknown route", func(c *Config) { c.Route = "bogus-route" }, "unknown route"},
		{"unknown speed", func(c *Config) { c.Speed = "turbo" }, "unknown speed"},
		{"unknown local mode", func(c *Config) { c.LocalMode = "raw-socket" }, "unknown local mode"},
		{"unknown local dns", func(c *Config) { c.LocalDNS = "system-direct" }, "unknown local dns"},
		{"unknown replay cache", func(c *Config) { c.ReplayCache = "flat-file" }, "unknown replay cache"},
		{"lab tokens without lab profile", func(c *Config) { c.AllowLabTokens = true; c.Profile = "smart" }, "allow_lab_tokens requires lab profile"},
	}
	for _, tc := range cases {
		cfg := Default()
		tc.mut(&cfg)
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("%s: invalid config accepted", tc.name)
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %q, want substring %q", tc.name, err, tc.want)
		}
	}
}

// TestValidateAcceptsEmptyRouteAndSpeedAndAdversarialProfile covers the
// pass-through branches: an empty Route skips the route switch (the
// `c.Route != ""` false branch), an empty Speed skips the speed switch, and the
// adversarial-dpi profile (not "smart") validates via policy.ProfileByName.
func TestValidateAcceptsEmptyRouteAndSpeedAndAdversarialProfile(t *testing.T) {
	cfg := Default()
	cfg.Route = ""
	cfg.Speed = ""
	cfg.Profile = "adversarial-dpi"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty route/speed + adversarial profile rejected: %v", err)
	}
}

// TestParseBoolRejectsNonBoolean covers the error branch of parseBool, which
// is the oracle the [methods]/[security] boolean gates route through.
func TestParseBoolRejectsNonBoolean(t *testing.T) {
	if _, err := parseBool("maybe"); err == nil {
		t.Fatal("parseBool accepted non-boolean value")
	}
	if v, err := parseBool("true"); err != nil || !v {
		t.Fatalf("parseBool(true) = %v, %v, want true, nil", v, err)
	}
	if v, err := parseBool("false"); err != nil || v {
		t.Fatalf("parseBool(false) = %v, %v, want false, nil", v, err)
	}
}

// TestParseAcceptsExtensionSections covers the forward-compatible path: an
// unknown section with a recognized extension prefix is silently accepted
// (set returns nil) rather than failing closed.
func TestParseAcceptsExtensionSections(t *testing.T) {
	for _, section := range []string{"x.foo", "ext.bar", "extension.baz", "extensions.qux"} {
		input := "[" + section + "]\nignored_key = \"value\"\n"
		if _, err := Parse(strings.NewReader(input)); err != nil {
			t.Fatalf("extension section %q rejected: %v", section, err)
		}
	}
}

// TestParseRejectsKeyOutsideTableAndUnknownTable covers the two bare-set error
// branches: a key before any section header, and a key under an unrecognized
// non-extension table.
func TestParseRejectsKeyOutsideTableAndUnknownTable(t *testing.T) {
	if _, err := Parse(strings.NewReader(`bare_key = "value"`)); err == nil {
		t.Fatal("key outside a table accepted")
	}
	if _, err := Parse(strings.NewReader(`[bogus]
key = "value"
`)); err == nil {
		t.Fatal("unknown table accepted")
	}
}

// TestParseRejectsNonBooleanMethodAndSecurity covers the parseBool error path
// inside set for both boolean-gated sections (methods and security).
func TestParseRejectsNonBooleanMethodAndSecurity(t *testing.T) {
	if _, err := Parse(strings.NewReader(`[methods]
allow_h2 = maybe
`)); err == nil {
		t.Fatal("non-boolean methods value accepted")
	}
	if _, err := Parse(strings.NewReader(`[security]
require_pq = maybe
`)); err == nil {
		t.Fatal("non-boolean security value accepted")
	}
}

// TestParseRejectsUnknownKeysPerSection covers the remaining unknown-key
// branches for local, methods, and storage sections (aurora and security
// unknown-key branches are already covered by existing tests).
func TestParseRejectsUnknownKeysPerSection(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"local", "[local]\nbogus = \"x\"\n"},
		{"methods", "[methods]\nbogus = true\n"},
		{"storage", "[storage]\nbogus = \"x\"\n"},
	}
	for _, tc := range cases {
		if _, err := Parse(strings.NewReader(tc.input)); err == nil {
			t.Fatalf("%s: unknown key accepted", tc.name)
		}
	}
}

// TestEffectiveProfileEmptyFallsBackToSmart covers the `c.Profile == ""`
// branch of EffectiveProfile (in addition to the "smart" branch covered
// elsewhere): an empty profile resolves to SmartProfile(pathClass).
func TestEffectiveProfileEmptyFallsBackToSmart(t *testing.T) {
	cfg := Config{Profile: ""}
	want := policy.SmartProfile("normal")
	if got := cfg.EffectiveProfile("normal"); got.ID != want.ID {
		t.Fatalf("EffectiveProfile(empty, normal).ID = 0x%x, want 0x%x", got.ID, want.ID)
	}
}

// TestParseOverridesVersionField covers the version override + the
// unsupported-version Validate branch through the full Parse pipeline (the
// existing tests only ever leave Version at its "2.0" default).
func TestParseOverridesVersionField(t *testing.T) {
	if _, err := Parse(strings.NewReader(`[aurora]
version = "1.0"
`)); err == nil {
		t.Fatal("unsupported version accepted through Parse")
	}
}

// failingReader returns a Read error on every call, exercising Parse's
// io.ReadAll error-propagation branch.
type failingReader struct{ err error }

func (r failingReader) Read(p []byte) (int, error) { return 0, r.err }

// TestParsePropagatesReaderError covers the ReadAll error branch: a reader that
// fails is surfaced as Parse's error rather than swallowed.
func TestParsePropagatesReaderError(t *testing.T) {
	want := errors.New("read boom")
	if _, err := Parse(failingReader{want}); err == nil {
		t.Fatal("reader error swallowed by Parse")
	} else if !errors.Is(err, want) {
		t.Fatalf("Parse error = %v, want %v", err, want)
	}
}

// TestParseRejectsLineMissingEquals covers the `strings.Cut` miss branch: a
// non-comment, non-section line with no '=' is rejected with a line number.
func TestParseRejectsLineMissingEquals(t *testing.T) {
	_, err := Parse(strings.NewReader("[aurora]\nprofile = \"smart\"\ngarbage_no_equals\n"))
	if err == nil {
		t.Fatal("line missing '=' accepted")
	}
	if !strings.Contains(err.Error(), "missing '='") {
		t.Fatalf("err = %q, want substring \"missing '='\"", err)
	}
}

// Parse's scanner.Err() branch (config.go:86-88) is intentionally NOT covered:
// it is dead-by-design. The MaxConfigBytes size guard (65536) is strictly
// tighter than the scanner buffer max (MaxConfigBytes+1 = 65537), so no input
// line can exceed the scanner token limit without first being rejected by the
// size guard. bufio.Scanner can only surface ErrTooLong (its sole error
// source); reader errors are caught by the preceding io.ReadAll. The branch
// is a defensive belt-and-suspenders check that is unreachable under the current
// size invariant, so reaching it would require contriving an impossible state.