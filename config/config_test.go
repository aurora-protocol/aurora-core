package config

import (
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
