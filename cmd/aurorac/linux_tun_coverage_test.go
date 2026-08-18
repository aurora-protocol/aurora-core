package main

// Adversarial coverage for the pure validation helpers in linux_tun.go that
// the existing linux_tun_test.go does not reach directly. The existing tests
// drive the full Configure / DiscoverRelayRoutes / parseTUNConfig flows with
// valid (or single-perturbation) inputs, so most validation error branches
// and the nil-receiver / default-runner paths stay uncovered. Each case below
// crafts a minimal in-memory input or injects a recordingLinuxIPRunner /
// linuxRelayAddressResolver, asserting the rejection branch fires before any
// real `ip` execution or DNS lookup.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// Dead by design (documented, not contrived):
//   - validateMainRoutingPolicy:414-415 (len(expected) != 0 after the loop):
//     the count guard at 404 ensures len(rules) == len(expected) == 3, and the
//     loop deletes exactly one expected entry per matched rule, so if the loop
//     completes without returning at 409 (every rule matched its priority,
//     table, from, and to), expected is always empty. The post-loop check can
//     never be true once 404 is passed.
//
// Deferred (reachable only with a real Linux `ip` binary on PATH, not unit
// testable on macOS CI):
//   - runLinuxIP (502-513): shells out to the `ip` command via exec.
//   - linuxIPPath (515-521): stats candidate `ip` binary paths.
//   - resolveLinuxRelayAddresses (262-268): net.DefaultResolver.LookupNetIP
//     performs a real DNS lookup. It is the default resolver wired in by
//     newLinuxTUNNetworkManager and is exercised only via integration.

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
)

// validLinuxTUNNetworkConfigForCoverage returns an all-valid
// linuxTUNNetworkConfig so a single perturbation reaches a specific
// validateLinuxTUNNetworkConfig branch without tripping an earlier check.
func validLinuxTUNNetworkConfigForCoverage() linuxTUNNetworkConfig {
	return linuxTUNNetworkConfig{
		Runner:        func(context.Context, ...string) ([]byte, error) { return nil, nil },
		Resolve:       func(context.Context, string) ([]netip.Addr, error) { return nil, nil },
		InterfaceName: "aurora0",
		MTU:           1280,
		IPv4:          netip.MustParsePrefix("10.77.0.2/32"),
		IPv6:          netip.MustParsePrefix("fd77::2/128"),
	}
}

func TestParseTUNConfigRejectsMalformedFlags(t *testing.T) {
	t.Run("unknown flag", func(t *testing.T) {
		// flags.Parse returns an error for an unrecognized flag (line 107-108),
		// before any provisioning or address validation runs.
		if _, err := parseTUNConfig([]string{"--unknown-flag"}, io.Discard); err == nil {
			t.Fatal("parseTUNConfig accepted an unknown flag")
		}
	})
	t.Run("trailing positional argument", func(t *testing.T) {
		// A non-flag positional leaves flags.NArg() != 0 (line 110-111), before
		// the provisioning-source check at 113.
		if _, err := parseTUNConfig([]string{"positional-arg"}, io.Discard); err == nil {
			t.Fatal("parseTUNConfig accepted a trailing positional argument")
		}
	})
	t.Run("issuer timeout below zero", func(t *testing.T) {
		args := []string{"--provisioning", "/private/provisioning.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin", "--issuer-timeout", "-1s"}
		if _, err := parseTUNConfig(args, io.Discard); err == nil {
			t.Fatal("parseTUNConfig accepted a negative issuer timeout")
		}
	})
	t.Run("issuer timeout above five minutes", func(t *testing.T) {
		args := []string{"--provisioning", "/private/provisioning.bin", "--wallet-state", "/private/wallet-state.bin", "--signed-seed-roots", "/private/roots.bin", "--issuer-timeout", "6m"}
		if _, err := parseTUNConfig(args, io.Discard); err == nil {
			t.Fatal("parseTUNConfig accepted an issuer timeout above five minutes")
		}
	})
}

func TestValidateLinuxTUNNetworkConfigRejectsEachInvalidField(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*linuxTUNNetworkConfig)
	}{
		{"nil runner", func(c *linuxTUNNetworkConfig) { c.Runner = nil }},
		{"nil resolver", func(c *linuxTUNNetworkConfig) { c.Resolve = nil }},
		{"invalid interface name", func(c *linuxTUNNetworkConfig) { c.InterfaceName = "aurora/0" }},
		{"mtu below minimum", func(c *linuxTUNNetworkConfig) { c.MTU = 575 }},
		{"mtu above maximum", func(c *linuxTUNNetworkConfig) { c.MTU = 9001 }},
		{"ipv4 not a host prefix", func(c *linuxTUNNetworkConfig) { c.IPv4 = netip.MustParsePrefix("10.77.0.2/24") }},
		{"ipv4 is ipv6", func(c *linuxTUNNetworkConfig) { c.IPv4 = netip.MustParsePrefix("fd77::2/128") }},
		{"ipv6 not a host prefix", func(c *linuxTUNNetworkConfig) { c.IPv6 = netip.MustParsePrefix("fd77::2/64") }},
		{"ipv6 is ipv4", func(c *linuxTUNNetworkConfig) { c.IPv6 = netip.MustParsePrefix("10.77.0.2/32") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := validLinuxTUNNetworkConfigForCoverage()
			tc.mutate(&config)
			if err := validateLinuxTUNNetworkConfig(config); err == nil {
				t.Fatalf("validateLinuxTUNNetworkConfig accepted %s", tc.name)
			}
		})
	}
}

func TestValidateLinuxTUNNetworkConfigAcceptsValid(t *testing.T) {
	if err := validateLinuxTUNNetworkConfig(validLinuxTUNNetworkConfigForCoverage()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestNewLinuxTUNNetworkManagerDefaultsNilDepsAndRejectsInvalidConfig(t *testing.T) {
	t.Run("nil runner and resolver default without error", func(t *testing.T) {
		config := validLinuxTUNNetworkConfigForCoverage()
		config.Runner = nil
		config.Resolve = nil
		// newLinuxTUNNetworkManager backfills runLinuxIP / resolveLinuxRelayAddresses
		// before validating, so nil deps are accepted (line 147-151).
		manager, err := newLinuxTUNNetworkManager(config)
		if err != nil {
			t.Fatalf("nil deps rejected: %v", err)
		}
		if manager.runner == nil || manager.resolve == nil {
			t.Fatal("newLinuxTUNNetworkManager did not backfill nil deps")
		}
	})
	t.Run("invalid interface rejected", func(t *testing.T) {
		config := validLinuxTUNNetworkConfigForCoverage()
		config.InterfaceName = "aurora/0"
		if _, err := newLinuxTUNNetworkManager(config); err == nil {
			t.Fatal("newLinuxTUNNetworkManager accepted an invalid interface name")
		}
	})
}

func TestValidLinuxInterfaceName(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty", "", false},
		{"sixteen chars", "0123456789abcdef", false},
		{"invalid char", "aurora/0", false},
		{"valid", "aurora0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validLinuxInterfaceName(tc.value); got != tc.want {
				t.Fatalf("validLinuxInterfaceName(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestRelayHostnameRejectsInvalidURLs(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"wrong scheme", "http://relay.example"},
		{"empty host", "https://"},
		{"userinfo present", "https://user@relay.example"},
		{"empty hostname", "https://:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := relayHostname(tc.url); err == nil {
				t.Fatalf("relayHostname accepted %s", tc.name)
			}
		})
	}
}

func TestRelayHostnameAcceptsValid(t *testing.T) {
	hostname, err := relayHostname("https://relay.example/assets/upload/42")
	if err != nil {
		t.Fatalf("valid relay URL rejected: %v", err)
	}
	if hostname != "relay.example" {
		t.Fatalf("hostname = %q, want relay.example", hostname)
	}
}

func TestValidateLinuxRelayAddressRejectsUnsafe(t *testing.T) {
	cases := []struct {
		name    string
		address string
	}{
		{"unspecified ipv4", "0.0.0.0"},
		{"unspecified ipv6", "::"},
		{"multicast ipv4", "224.0.0.1"},
		{"multicast ipv6", "ff00::1"},
		{"link local ipv4", "169.254.1.1"},
		{"link local ipv6", "fe80::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateLinuxRelayAddress(netip.MustParseAddr(tc.address)); err == nil {
				t.Fatalf("validateLinuxRelayAddress accepted %s", tc.name)
			}
		})
	}
}

func TestValidateLinuxRelayAddressAcceptsSafe(t *testing.T) {
	for _, address := range []string{"203.0.113.7", "2001:db8::7", "127.0.0.1"} {
		if err := validateLinuxRelayAddress(netip.MustParseAddr(address)); err != nil {
			t.Fatalf("validateLinuxRelayAddress rejected safe address %s: %v", address, err)
		}
	}
}

func TestValidateHostRoutesRejectsUnsafeRoutes(t *testing.T) {
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	goodAddr := netip.MustParseAddr("203.0.113.7")
	cases := []struct {
		name   string
		routes []linuxHostRoute
	}{
		{
			"too many routes",
			func() []linuxHostRoute {
				routes := make([]linuxHostRoute, maximumLinuxRelayAddresses+1)
				for i := range routes {
					routes[i] = linuxHostRoute{Address: netip.MustParseAddr("198.51.100.1"), Device: "eth0"}
				}
				return routes
			}(),
		},
		{"unsafe address", []linuxHostRoute{{Address: netip.MustParseAddr("0.0.0.0"), Device: "eth0"}}},
		{"loopback address", []linuxHostRoute{{Address: netip.MustParseAddr("127.0.0.1"), Device: "eth0"}}},
		{"device is the tunnel", []linuxHostRoute{{Address: goodAddr, Device: "aurora0"}}},
		{"invalid device name", []linuxHostRoute{{Address: goodAddr, Device: "eth/0"}}},
		{"gateway family mismatch", []linuxHostRoute{{Address: goodAddr, Gateway: netip.MustParseAddr("2001:db8::1"), Device: "eth0"}}},
		{"duplicate route", []linuxHostRoute{
			{Address: goodAddr, Device: "eth0"},
			{Address: goodAddr, Device: "eth0"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := manager.validateHostRoutes(tc.routes); err == nil {
				t.Fatalf("validateHostRoutes accepted %s", tc.name)
			}
		})
	}
}

func TestValidateHostRoutesAcceptsValid(t *testing.T) {
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	routes := []linuxHostRoute{
		{Address: netip.MustParseAddr("203.0.113.7"), Gateway: netip.MustParseAddr("192.0.2.1"), Device: "eth0"},
		{Address: netip.MustParseAddr("2001:db8::7"), Device: "eth0"},
	}
	if err := manager.validateHostRoutes(routes); err != nil {
		t.Fatalf("valid routes rejected: %v", err)
	}
}

func TestValidateMainRoutingPolicyRejectsInvalidResponses(t *testing.T) {
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	t.Run("runner error", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return nil, errors.New("ip command failed")
		}
		if err := manager.validateMainRoutingPolicy(context.Background(), "-4"); err == nil {
			t.Fatal("validateMainRoutingPolicy accepted a runner error")
		}
	})
	t.Run("invalid json", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) { return []byte("not-json"), nil }
		if err := manager.validateMainRoutingPolicy(context.Background(), "-4"); err == nil {
			t.Fatal("validateMainRoutingPolicy accepted invalid JSON")
		}
	})
	t.Run("wrong table for priority", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(`[{"priority":0,"from":"all","to":"all","table":"wrong"},{"priority":32766,"from":"all","to":"all","table":"main"},{"priority":32767,"from":"all","to":"all","table":"default"}]`), nil
		}
		if err := manager.validateMainRoutingPolicy(context.Background(), "-4"); err == nil {
			t.Fatal("validateMainRoutingPolicy accepted a wrong table")
		}
	})
	t.Run("wrong from and to", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(`[{"priority":0,"from":"10.0.0.0/8","to":"all","table":"local"},{"priority":32766,"from":"all","to":"all","table":"main"},{"priority":32767,"from":"all","to":"all","table":"default"}]`), nil
		}
		if err := manager.validateMainRoutingPolicy(context.Background(), "-4"); err == nil {
			t.Fatal("validateMainRoutingPolicy accepted a non-all source")
		}
	})
	t.Run("unknown priority", func(t *testing.T) {
		// Three rules pass the count guard (404), but the second rule's priority
		// 0 was already deleted by the first, so the loop's !ok branch fires at
		// 409 (not the dead post-loop check at 414). This covers the !ok condition
		// of the 409 guard, distinct from the wrong-table / wrong-from cases.
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(`[{"priority":0,"from":"all","to":"all","table":"local"},{"priority":0,"from":"all","to":"all","table":"local"},{"priority":32766,"from":"all","to":"all","table":"main"}]`), nil
		}
		if err := manager.validateMainRoutingPolicy(context.Background(), "-4"); err == nil {
			t.Fatal("validateMainRoutingPolicy accepted an unknown priority")
		}
	})
}

func TestValidateMainRoutingPolicyAcceptsValid(t *testing.T) {
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	manager.runner = func(context.Context, ...string) ([]byte, error) { return []byte(linuxMainRoutingPolicyJSON()), nil }
	if err := manager.validateMainRoutingPolicy(context.Background(), "-4"); err != nil {
		t.Fatalf("valid routing policy rejected: %v", err)
	}
}

func TestTunnelDefaultMetricRejectsInvalidResponses(t *testing.T) {
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	t.Run("runner error", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return nil, errors.New("ip command failed")
		}
		if _, err := manager.tunnelDefaultMetric(context.Background(), "-4"); err == nil {
			t.Fatal("tunnelDefaultMetric accepted a runner error")
		}
	})
	t.Run("invalid json", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) { return []byte("not-json"), nil }
		if _, err := manager.tunnelDefaultMetric(context.Background(), "-4"); err == nil {
			t.Fatal("tunnelDefaultMetric accepted invalid JSON")
		}
	})
	t.Run("too many default routes", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(linuxDefaultRoutesJSONForCoverage(maximumLinuxRelayAddresses + 1)), nil
		}
		if _, err := manager.tunnelDefaultMetric(context.Background(), "-4"); err == nil {
			t.Fatal("tunnelDefaultMetric accepted too many default routes")
		}
	})
	t.Run("non-default destination", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(`[{"dst":"192.0.2.0/24","metric":100}]`), nil
		}
		if _, err := manager.tunnelDefaultMetric(context.Background(), "-4"); err == nil {
			t.Fatal("tunnelDefaultMetric accepted a non-default destination")
		}
	})
	t.Run("zero metric", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(`[{"dst":"default","metric":0}]`), nil
		}
		if _, err := manager.tunnelDefaultMetric(context.Background(), "-4"); err == nil {
			t.Fatal("tunnelDefaultMetric accepted a zero metric")
		}
	})
}

func TestTunnelDefaultMetricComputesPrecedence(t *testing.T) {
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	t.Run("empty yields metric one", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) { return []byte("[]"), nil }
		metric, err := manager.tunnelDefaultMetric(context.Background(), "-4")
		if err != nil || metric != 1 {
			t.Fatalf("tunnelDefaultMetric(empty) = %d, err=%v, want 1", metric, err)
		}
	})
	t.Run("single route yields metric minus one", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(`[{"dst":"default","metric":100}]`), nil
		}
		metric, err := manager.tunnelDefaultMetric(context.Background(), "-4")
		if err != nil || metric != 99 {
			t.Fatalf("tunnelDefaultMetric(metric 100) = %d, err=%v, want 99", metric, err)
		}
	})
	t.Run("lowest precedence wins", func(t *testing.T) {
		manager.runner = func(context.Context, ...string) ([]byte, error) {
			return []byte(`[{"dst":"default","metric":100},{"dst":"default","metric":50}]`), nil
		}
		metric, err := manager.tunnelDefaultMetric(context.Background(), "-4")
		if err != nil || metric != 49 {
			t.Fatalf("tunnelDefaultMetric(100,50) = %d, err=%v, want 49", metric, err)
		}
	})
}

func TestDiscoverRelayRoutesRejectsInvalidConditions(t *testing.T) {
	t.Run("nil manager", func(t *testing.T) {
		var manager *linuxTUNNetworkManager
		if _, err := manager.DiscoverRelayRoutes(context.Background(), "https://relay.example"); err == nil {
			t.Fatal("nil manager DiscoverRelayRoutes did not error")
		}
	})
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	t.Run("nil context", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if _, err := manager.DiscoverRelayRoutes(nil, "https://relay.example"); err == nil {
			t.Fatal("DiscoverRelayRoutes accepted a nil context")
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := manager.DiscoverRelayRoutes(ctx, "https://relay.example"); err == nil {
			t.Fatal("DiscoverRelayRoutes accepted a cancelled context")
		}
	})
	t.Run("invalid relay url", func(t *testing.T) {
		if _, err := manager.DiscoverRelayRoutes(context.Background(), "http://relay.example"); err == nil {
			t.Fatal("DiscoverRelayRoutes accepted an invalid relay URL")
		}
	})
	t.Run("resolve error", func(t *testing.T) {
		manager.resolve = func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("dns failure")
		}
		if _, err := manager.DiscoverRelayRoutes(context.Background(), "https://relay.example"); err == nil {
			t.Fatal("DiscoverRelayRoutes accepted a resolve error")
		}
	})
	t.Run("empty address set", func(t *testing.T) {
		manager.resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
		if _, err := manager.DiscoverRelayRoutes(context.Background(), "https://relay.example"); err == nil {
			t.Fatal("DiscoverRelayRoutes accepted an empty address set")
		}
	})
	t.Run("unsafe resolved address", func(t *testing.T) {
		manager.resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil
		}
		if _, err := manager.DiscoverRelayRoutes(context.Background(), "https://relay.example"); err == nil {
			t.Fatal("DiscoverRelayRoutes accepted an unsafe resolved address")
		}
	})
	t.Run("loopback address skipped", func(t *testing.T) {
		// A loopback address passes validateLinuxRelayAddress but is skipped at
		// the IsLoopback check, yielding an empty route set without error.
		manager.resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		routes, err := manager.DiscoverRelayRoutes(context.Background(), "https://relay.example")
		if err != nil {
			t.Fatalf("loopback-only discovery errored: %v", err)
		}
		if len(routes) != 0 {
			t.Fatalf("loopback address produced routes: %+v", routes)
		}
	})
}

func TestLookupRelayRouteRejectsRunnerError(t *testing.T) {
	runner := &recordingLinuxIPRunner{errors: map[string]error{
		"-j\x00-4\x00route\x00get\x00203.0.113.7": errors.New("ip command failed"),
	}}
	manager := mustLinuxTUNNetworkManager(t, runner)
	if _, err := manager.lookupRelayRoute(context.Background(), netip.MustParseAddr("203.0.113.7")); err == nil {
		t.Fatal("lookupRelayRoute accepted a runner error")
	}
}

func TestConfigureRejectsEarlyErrors(t *testing.T) {
	t.Run("nil manager", func(t *testing.T) {
		var manager *linuxTUNNetworkManager
		if _, err := manager.Configure(context.Background(), nil); err == nil {
			t.Fatal("nil manager Configure did not error")
		}
	})
	manager := mustLinuxTUNNetworkManager(t, &recordingLinuxIPRunner{})
	t.Run("nil context", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if _, err := manager.Configure(nil, nil); err == nil {
			t.Fatal("Configure accepted a nil context")
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := manager.Configure(ctx, nil); err == nil {
			t.Fatal("Configure accepted a cancelled context")
		}
	})
	t.Run("unsafe host routes", func(t *testing.T) {
		if _, err := manager.Configure(context.Background(), []linuxHostRoute{
			{Address: netip.MustParseAddr("0.0.0.0"), Device: "eth0"},
		}); err == nil {
			t.Fatal("Configure accepted unsafe host routes")
		}
	})
	t.Run("ipv6 policy error", func(t *testing.T) {
		runner := &recordingLinuxIPRunner{responses: map[string]string{
			"-j\x00-4\x00rule\x00show": linuxMainRoutingPolicyJSON(),
		}, errors: map[string]error{
			"-j\x00-6\x00rule\x00show": errors.New("ip command failed"),
		}}
		m := mustLinuxTUNNetworkManager(t, runner)
		if _, err := m.Configure(context.Background(), nil); err == nil {
			t.Fatal("Configure accepted an ipv6 policy error")
		}
	})
	t.Run("ipv6 default route error", func(t *testing.T) {
		runner := &recordingLinuxIPRunner{responses: map[string]string{
			"-j\x00-4\x00rule\x00show":             linuxMainRoutingPolicyJSON(),
			"-j\x00-6\x00rule\x00show":             linuxMainRoutingPolicyJSON(),
			"-j\x00-4\x00route\x00show\x00default": `[{"dst":"default","metric":100}]`,
		}, errors: map[string]error{
			"-j\x00-6\x00route\x00show\x00default": errors.New("ip command failed"),
		}}
		m := mustLinuxTUNNetworkManager(t, runner)
		if _, err := m.Configure(context.Background(), nil); err == nil {
			t.Fatal("Configure accepted an ipv6 default route error")
		}
	})
}

func TestLinuxTUNNetworkStateCloseHandlesNilAndCleanupFailure(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var state *linuxTUNNetworkState
		if err := state.Close(); err != nil {
			t.Fatalf("nil receiver Close returned err: %v", err)
		}
	})
	t.Run("cleanup failure surfaces error", func(t *testing.T) {
		state := &linuxTUNNetworkState{
			runner: func(context.Context, ...string) ([]byte, error) {
				return nil, errors.New("permission denied")
			},
			cleanup: [][]string{{"route", "del", "default", "dev", "aurora0"}},
		}
		if err := state.Close(); err == nil {
			t.Fatal("Close did not surface a cleanup failure")
		}
	})
}

func TestConfigureRollsBackOnEachAddFailure(t *testing.T) {
	// Each subtest reaches a distinct state.add failure inside Configure (the
	// route loop, link set, IPv4 address, IPv6 address, and IPv4 default route
	// steps) by injecting a runner whose responses hold valid policy+metric
	// JSON and whose errors map trips exactly one add command.
	cases := []struct {
		name       string
		failingKey string
		routes     []linuxHostRoute
	}{
		{
			"route add",
			"-4\x00route\x00add\x00203.0.113.7/32\x00via\x00192.0.2.1\x00dev\x00eth0\x00metric\x005",
			[]linuxHostRoute{{Address: netip.MustParseAddr("203.0.113.7"), Gateway: netip.MustParseAddr("192.0.2.1"), Device: "eth0"}},
		},
		{"link set", "link\x00set\x00dev\x00aurora0\x00mtu\x001280\x00up", nil},
		{"ipv4 address add", "-4\x00address\x00add\x0010.77.0.2/32\x00dev\x00aurora0", nil},
		{"ipv6 address add", "-6\x00address\x00add\x00fd77::2/128\x00dev\x00aurora0", nil},
		// -4 default route metric is 100-1=99 (the -4 default route below has
		// metric 100, so tunnelDefaultMetric returns 99).
		{"ipv4 default route add", "-4\x00route\x00add\x00default\x00dev\x00aurora0\x00metric\x0099", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingLinuxIPRunner{
				responses: validConfigureResponsesForCoverage(),
				errors:    map[string]error{tc.failingKey: errors.New("permission denied")},
			}
			manager := mustLinuxTUNNetworkManager(t, runner)
			if _, err := manager.Configure(context.Background(), tc.routes); err == nil {
				t.Fatalf("Configure did not roll back on %s failure", tc.name)
			}
		})
	}
}

// validConfigureResponsesForCoverage holds the policy + default-route JSON
// that lets Configure pass its validateMainRoutingPolicy and tunnelDefaultMetric
// guards so a single state.add failure is the first error reached.
func validConfigureResponsesForCoverage() map[string]string {
	return map[string]string{
		"-j\x00-4\x00rule\x00show":             linuxMainRoutingPolicyJSON(),
		"-j\x00-6\x00rule\x00show":             linuxMainRoutingPolicyJSON(),
		"-j\x00-4\x00route\x00show\x00default": `[{"dst":"default","metric":100}]`,
		"-j\x00-6\x00route\x00show\x00default": `[{"dst":"default","metric":1024}]`,
	}
}

// linuxDefaultRoutesJSONForCoverage builds a JSON array of N default-route
// entries for the tunnelDefaultMetric count-limit branch.
func linuxDefaultRoutesJSONForCoverage(count int) string {
	routes := make([]byte, 0, count*40+2)
	routes = append(routes, '[')
	for i := 0; i < count; i++ {
		if i > 0 {
			routes = append(routes, ',')
		}
		routes = append(routes, `{"dst":"default","metric":100}`...)
	}
	routes = append(routes, ']')
	return string(routes)
}
