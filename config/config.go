package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/registry"
)

const MaxConfigBytes = 64 * 1024

var ErrInputTooLarge = errors.New("config: input exceeds maximum size")

type Config struct {
	Version                     string
	Profile                     string
	Route                       string
	Speed                       string
	LocalMode                   string
	LocalDNS                    string
	AllowH2                     bool
	AllowH1WS                   bool
	AllowH3ExtDgram             bool
	AllowMasque                 bool
	RequirePQ                   bool
	RequireSplit2ForAdversarial bool
	AllowLabTokens              bool
	ReplayCache                 string
}

func Default() Config {
	return Config{
		Version:                     "2.0",
		Profile:                     "smart",
		Route:                       "auto",
		Speed:                       "balanced",
		LocalMode:                   "socks5",
		LocalDNS:                    "through-aurora",
		AllowH2:                     true,
		AllowH1WS:                   true,
		RequirePQ:                   true,
		RequireSplit2ForAdversarial: true,
		ReplayCache:                 "sqlite",
	}
}

func Parse(r io.Reader) (Config, error) {
	if r == nil {
		return Config{}, fmt.Errorf("config: input is required")
	}
	input, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return Config{}, err
	}
	if len(input) > MaxConfigBytes {
		return Config{}, ErrInputTooLarge
	}

	cfg := Default()
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 4096), MaxConfigBytes+1)
	section := ""
	lineNo := 0
	seenSections := make(map[string]struct{})
	seenKeys := make(map[string]struct{})
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return Config{}, fmt.Errorf("config: line %d has an invalid table header", lineNo)
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if !isConfigSection(section) {
				return Config{}, fmt.Errorf("config: line %d has unknown table %q", lineNo, section)
			}
			if _, exists := seenSections[section]; exists {
				return Config{}, fmt.Errorf("config: line %d repeats table %q", lineNo, section)
			}
			seenSections[section] = struct{}{}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("config: line %d missing '='", lineNo)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return Config{}, fmt.Errorf("config: line %d has an empty key", lineNo)
		}
		keyID := section + "\x00" + key
		if _, exists := seenKeys[keyID]; exists {
			return Config{}, fmt.Errorf("config: line %d repeats key %q in table %q", lineNo, key, section)
		}
		seenKeys[keyID] = struct{}{}
		val = strings.Trim(strings.TrimSpace(val), "\"")
		if err := cfg.set(section, key, val); err != nil {
			return Config{}, err
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

func isConfigSection(section string) bool {
	switch section {
	case "aurora", "local", "methods", "security", "storage":
		return true
	default:
		return isExtensionSection(section)
	}
}

func (c *Config) set(section, key, val string) error {
	switch section {
	case "aurora":
		switch key {
		case "version":
			c.Version = val
		case "profile":
			c.Profile = val
		case "route":
			c.Route = val
		case "speed":
			c.Speed = val
		default:
			return fmt.Errorf("config: unknown aurora key %q", key)
		}
	case "local":
		switch key {
		case "mode":
			c.LocalMode = val
		case "dns":
			c.LocalDNS = val
		default:
			return fmt.Errorf("config: unknown local key %q", key)
		}
	case "methods":
		parsed, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("config: %s must be boolean", key)
		}
		switch key {
		case "allow_h2":
			c.AllowH2 = parsed
		case "allow_h1_ws":
			c.AllowH1WS = parsed
		case "allow_h3_ext_dgram":
			c.AllowH3ExtDgram = parsed
		case "allow_masque":
			c.AllowMasque = parsed
		default:
			return fmt.Errorf("config: unknown methods key %q", key)
		}
	case "security":
		parsed, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("config: %s must be boolean", key)
		}
		switch key {
		case "require_pq":
			c.RequirePQ = parsed
		case "require_split2_for_adversarial":
			c.RequireSplit2ForAdversarial = parsed
		case "allow_lab_tokens":
			c.AllowLabTokens = parsed
		default:
			return fmt.Errorf("config: unknown security key %q", key)
		}
	case "storage":
		switch key {
		case "replay_cache":
			c.ReplayCache = val
		default:
			return fmt.Errorf("config: unknown storage key %q", key)
		}
	default:
		if isExtensionSection(section) {
			return nil
		}
		if section == "" {
			return fmt.Errorf("config: key %q outside a table", key)
		}
		return fmt.Errorf("config: unknown table %q", section)
	}
	return nil
}

func parseBool(val string) (bool, error) {
	switch val {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("not a boolean")
	}
}

func isExtensionSection(section string) bool {
	return strings.HasPrefix(section, "x.") ||
		strings.HasPrefix(section, "ext.") ||
		strings.HasPrefix(section, "extension.") ||
		strings.HasPrefix(section, "extensions.")
}

func (c Config) Validate() error {
	if c.Version != "2.0" {
		return fmt.Errorf("config: unsupported version %q", c.Version)
	}
	if c.Profile != "smart" {
		profile, err := policy.ProfileByName(c.Profile)
		if err != nil {
			return err
		}
		if policy.RequiresPQPreludeSignature(profile.ID) && !c.RequirePQ {
			return fmt.Errorf("config: require_pq cannot be disabled for profile %q", c.Profile)
		}
		if c.Route == "fast-1" {
			// Spec sections 21.4/21.5 forbid fast-1 under the strict and
			// emergency profiles unconditionally; require_split2_for_adversarial
			// only gates the adversarial-dpi low-latency escape hatch.
			if profile.Fast1Forbidden {
				return fmt.Errorf("config: route %q is forbidden for profile %q", c.Route, c.Profile)
			}
			if c.RequireSplit2ForAdversarial && policy.RequiresPQPreludeSignature(profile.ID) {
				return fmt.Errorf("config: require_split2_for_adversarial forbids route %q for profile %q", c.Route, c.Profile)
			}
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
	switch c.LocalMode {
	case "socks5", "http-connect", "tun", "platform-vpn":
	default:
		return fmt.Errorf("config: unknown local mode %q", c.LocalMode)
	}
	switch c.LocalDNS {
	case "through-aurora":
	default:
		return fmt.Errorf("config: unknown local dns %q", c.LocalDNS)
	}
	switch c.ReplayCache {
	case "sqlite", "redis", "postgres", "memory-lab-only":
	default:
		return fmt.Errorf("config: unknown replay cache %q", c.ReplayCache)
	}
	if c.AllowLabTokens && c.Profile != "lab" {
		return fmt.Errorf("config: allow_lab_tokens requires lab profile")
	}
	if c.ReplayCache == "memory-lab-only" && c.Profile != "lab" {
		return fmt.Errorf("config: memory-lab-only replay cache requires lab profile")
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
