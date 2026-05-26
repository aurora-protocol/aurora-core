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
