package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestParseSpecExamples(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`[aurora]
profile = "adversarial-dpi"
route = "split-2"
speed = "balanced"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveProfile("normal").ID != registry.PolicyAdversarialDPI || RouteNameToID(cfg.Route) != registry.RouteSplit2 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestUnknownKeyFails(t *testing.T) {
	_, err := Parse(strings.NewReader(`[aurora]
unsafe = "true"
`))
	if err == nil {
		t.Fatalf("expected unknown key to fail")
	}
}

func TestParsePortableClientFloor(t *testing.T) {
	cfg, err := Parse(strings.NewReader(`[aurora]
version = "2.0"
profile = "smart"
route = "auto"
speed = "balanced"

[local]
mode = "socks5"
dns = "through-aurora"

[methods]
allow_h2 = true
allow_h1_ws = true
allow_h3_ext_dgram = false
allow_masque = false

[security]
require_pq = true
require_split2_for_adversarial = true
allow_lab_tokens = false

[storage]
replay_cache = "sqlite"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != "2.0" || cfg.LocalMode != "socks5" || cfg.LocalDNS != "through-aurora" {
		t.Fatalf("portable local floor not parsed: %+v", cfg)
	}
	if !cfg.AllowH2 || !cfg.AllowH1WS || cfg.AllowH3ExtDgram || cfg.AllowMasque {
		t.Fatalf("method gates not parsed: %+v", cfg)
	}
	if !cfg.RequirePQ || !cfg.RequireSplit2ForAdversarial || cfg.AllowLabTokens {
		t.Fatalf("security gates not parsed: %+v", cfg)
	}
	if cfg.ReplayCache != "sqlite" {
		t.Fatalf("storage floor not parsed: %+v", cfg)
	}
}

func TestParseRejectsConfigLargerThan64KiB(t *testing.T) {
	_, err := Parse(strings.NewReader(strings.Repeat("#\n", (64*1024/2)+1)))
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("Parse error = %v, want oversized-input error", err)
	}
}

func TestParseAcceptsConfigAt64KiB(t *testing.T) {
	cfg, err := Parse(strings.NewReader(strings.Repeat("#\n", 64*1024/2)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg != Default() {
		t.Fatalf("config = %+v, want defaults", cfg)
	}
}

func TestUnknownSecurityKeyFailsClosed(t *testing.T) {
	_, err := Parse(strings.NewReader(`[security]
allow_plaintext_tokens = true
`))
	if err == nil {
		t.Fatalf("unknown security key accepted")
	}
}

func TestAllowLabTokensRequiresLabProfile(t *testing.T) {
	_, err := Parse(strings.NewReader(`[aurora]
profile = "adversarial-dpi"

[security]
allow_lab_tokens = true
`))
	if err == nil {
		t.Fatalf("non-lab profile accepted lab token enablement")
	}

	cfg, err := Parse(strings.NewReader(`[aurora]
profile = "lab"

[security]
allow_lab_tokens = true
`))
	if err != nil {
		t.Fatalf("lab profile rejected lab token enablement: %v", err)
	}
	if !cfg.AllowLabTokens {
		t.Fatalf("lab token enablement was not parsed")
	}
}

func TestParseRejectsAmbiguousTablesAndKeys(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "unknown empty table",
			input: "[securty]\n# misspelled security table\n",
			want:  "unknown table",
		},
		{
			name:  "empty table",
			input: "[]\n",
			want:  "unknown table",
		},
		{
			name:  "malformed table",
			input: "[security\nrequire_pq = true\n",
			want:  "invalid table header",
		},
		{
			name: "repeated table",
			input: "[security]\nrequire_pq = true\n" +
				"[security]\nrequire_split2_for_adversarial = true\n",
			want: "repeats table",
		},
		{
			name: "repeated key",
			input: "[security]\nrequire_pq = true\n" +
				"require_pq = false\n",
			want: "repeats key",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseRejectsNilInput(t *testing.T) {
	if _, err := Parse(nil); err == nil || !strings.Contains(err.Error(), "input is required") {
		t.Fatalf("Parse(nil) error = %v, want required-input error", err)
	}
}

func TestParseDoesNotTreatBracketedExtensionValueAsTableHeader(t *testing.T) {
	if _, err := Parse(strings.NewReader("[x.future]\npayload = \"opaque]\"\n")); err != nil {
		t.Fatalf("opaque extension value rejected: %v", err)
	}
}

func TestRequirePQCannotBeDisabledForAdversarialProfiles(t *testing.T) {
	for _, profile := range []string{"adversarial-dpi", "adversarial-dpi-strict", "emergency-web"} {
		_, err := Parse(strings.NewReader("[aurora]\nprofile = \"" + profile + "\"\n\n[security]\nrequire_pq = false\n"))
		if err == nil {
			t.Fatalf("profile %q accepted require_pq = false", profile)
		}
	}

	for _, profile := range []string{"smart", "fast-web", "balanced-web"} {
		cfg, err := Parse(strings.NewReader("[aurora]\nprofile = \"" + profile + "\"\n\n[security]\nrequire_pq = false\n"))
		if err != nil {
			t.Fatalf("profile %q rejected require_pq = false: %v", profile, err)
		}
		if cfg.RequirePQ {
			t.Fatalf("profile %q did not parse require_pq = false", profile)
		}
	}
}

func TestRequireSplit2ForAdversarialForbidsFast1(t *testing.T) {
	for _, profile := range []string{"adversarial-dpi", "adversarial-dpi-strict", "emergency-web"} {
		_, err := Parse(strings.NewReader("[aurora]\nprofile = \"" + profile + "\"\nroute = \"fast-1\"\n"))
		if err == nil {
			t.Fatalf("profile %q accepted route fast-1 with require_split2_for_adversarial", profile)
		}

		cfg, err := Parse(strings.NewReader("[aurora]\nprofile = \"" + profile + "\"\nroute = \"fast-1\"\n\n[security]\nrequire_split2_for_adversarial = false\n"))
		if err != nil {
			t.Fatalf("profile %q rejected fast-1 with the split2 requirement disabled: %v", profile, err)
		}
		if cfg.RequireSplit2ForAdversarial {
			t.Fatalf("profile %q did not parse require_split2_for_adversarial = false", profile)
		}
	}

	cfg, err := Parse(strings.NewReader("[aurora]\nprofile = \"fast-web\"\nroute = \"fast-1\"\n"))
	if err != nil {
		t.Fatalf("fast-web rejected route fast-1: %v", err)
	}
	if !cfg.RequireSplit2ForAdversarial {
		t.Fatalf("default require_split2_for_adversarial changed")
	}
}
