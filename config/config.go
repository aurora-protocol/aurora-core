package config

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/registry"
)

type Config struct {
	Profile string
	Route   string
	Speed   string
}

func Default() Config {
	return Config{Profile: "smart"}
}

func Parse(r io.Reader) (Config, error) {
	cfg := Default()
	scanner := bufio.NewScanner(r)
	inAurora := false
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inAurora = line == "[aurora]"
			continue
		}
		if !inAurora {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("config: line %d missing '='", lineNo)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), "\"")
		switch key {
		case "profile":
			cfg.Profile = val
		case "route":
			cfg.Route = val
		case "speed":
			cfg.Speed = val
		default:
			return Config{}, fmt.Errorf("config: unknown aurora key %q", key)
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Profile != "smart" {
		if _, err := policy.ProfileByName(c.Profile); err != nil {
			return err
		}
	}
	if c.Route != "" {
		switch c.Route {
		case "auto", "fast-1", "split-2", "safe-3", "bridge-split":
		default:
			return fmt.Errorf("config: unknown route %q", c.Route)
		}
	}
	if c.Speed != "" {
		switch c.Speed {
		case "balanced", "max":
		default:
			return fmt.Errorf("config: unknown speed %q", c.Speed)
		}
	}
	return nil
}

func (c Config) EffectiveProfile(pathClass string) policy.Profile {
	if c.Profile == "smart" || c.Profile == "" {
		return policy.SmartProfile(pathClass)
	}
	p, _ := policy.ProfileByName(c.Profile)
	return p
}

func RouteNameToID(name string) uint64 {
	switch name {
	case "fast-1":
		return registry.RouteFast1
	case "split-2":
		return registry.RouteSplit2
	case "safe-3":
		return registry.RouteSafe3
	case "bridge-split":
		return registry.RouteBridgeSplit
	default:
		return registry.RouteAuto
	}
}
