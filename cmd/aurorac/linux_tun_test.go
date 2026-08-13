package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

func TestLinuxTUNNetworkConfiguresBypassesBeforeDefaults(t *testing.T) {
	runner := &recordingLinuxIPRunner{responses: map[string]string{
		"-j\x00-4\x00route\x00show\x00default": `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":100}]`,
		"-j\x00-6\x00route\x00show\x00default": `[{"dst":"default","gateway":"2001:db8::1","dev":"eth0","metric":1024}]`,
	}}
	manager, err := newLinuxTUNNetworkManager(linuxTUNNetworkConfig{
		Runner:        runner.Run,
		InterfaceName: "aurora0",
		MTU:           1280,
		IPv4:          netip.MustParsePrefix("10.77.0.2/32"),
		IPv6:          netip.MustParsePrefix("fd77::2/128"),
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.Configure(context.Background(), []linuxHostRoute{
		{Address: netip.MustParseAddr("203.0.113.7"), Gateway: netip.MustParseAddr("192.0.2.1"), Device: "eth0"},
		{Address: netip.MustParseAddr("2001:db8::7"), Device: "eth0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })

	requireLinuxIPCommandsInOrder(t, runner.Commands(), []string{
		"-j -4 route show default",
		"-j -6 route show default",
		"-4 route add 203.0.113.7/32 via 192.0.2.1 dev eth0 metric 5",
		"-6 route add 2001:db8::7/128 dev eth0 metric 5",
		"link set dev aurora0 mtu 1280 up",
		"-4 address add 10.77.0.2/32 dev aurora0",
		"-6 address add fd77::2/128 dev aurora0",
		"-4 route add default dev aurora0 metric 99",
		"-6 route add default dev aurora0 metric 1023",
	})
}

func TestLinuxTUNNetworkCloseRemovesOnlyOwnedRoutesInReverseOrder(t *testing.T) {
	runner := &recordingLinuxIPRunner{responses: map[string]string{
		"-j\x00-4\x00route\x00show\x00default": `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":100}]`,
		"-j\x00-6\x00route\x00show\x00default": `[]`,
	}}
	manager := mustLinuxTUNNetworkManager(t, runner)
	state, err := manager.Configure(context.Background(), []linuxHostRoute{
		{Address: netip.MustParseAddr("203.0.113.7"), Gateway: netip.MustParseAddr("192.0.2.1"), Device: "eth0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	requireLinuxIPCommandsInOrder(t, runner.Commands(), []string{
		"-6 route del default dev aurora0 metric 1",
		"-4 route del default dev aurora0 metric 99",
		"-4 route del 203.0.113.7/32 via 192.0.2.1 dev eth0 metric 5",
	})
	for _, command := range runner.Commands() {
		if strings.Contains(command, "route replace") || strings.Contains(command, "route del default") && !strings.Contains(command, "dev aurora0") {
			t.Fatalf("network manager touched an unowned route: %s", command)
		}
	}
}

func TestLinuxTUNNetworkRollsBackOnDefaultRouteFailure(t *testing.T) {
	runner := &recordingLinuxIPRunner{
		responses: map[string]string{
			"-j\x00-4\x00route\x00show\x00default": `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":100}]`,
			"-j\x00-6\x00route\x00show\x00default": `[]`,
		},
		errors: map[string]error{
			"-6\x00route\x00add\x00default\x00dev\x00aurora0\x00metric\x001": errors.New("permission denied"),
		},
	}
	manager := mustLinuxTUNNetworkManager(t, runner)
	if _, err := manager.Configure(context.Background(), []linuxHostRoute{
		{Address: netip.MustParseAddr("203.0.113.7"), Gateway: netip.MustParseAddr("192.0.2.1"), Device: "eth0"},
	}); err == nil {
		t.Fatal("network setup succeeded after a default route failure")
	}
	requireLinuxIPCommandsInOrder(t, runner.Commands(), []string{
		"-4 route del default dev aurora0 metric 99",
		"-4 route del 203.0.113.7/32 via 192.0.2.1 dev eth0 metric 5",
	})
}

func TestLinuxTUNNetworkRejectsUnsafeDefaultPrecedence(t *testing.T) {
	runner := &recordingLinuxIPRunner{responses: map[string]string{
		"-j\x00-4\x00route\x00show\x00default": `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":0}]`,
		"-j\x00-6\x00route\x00show\x00default": `[]`,
	}}
	manager := mustLinuxTUNNetworkManager(t, runner)
	if _, err := manager.Configure(context.Background(), nil); err == nil {
		t.Fatal("network setup accepted an unsafe default route metric")
	}
	for _, command := range runner.Commands() {
		if !strings.HasPrefix(command, "-j ") {
			t.Fatalf("network setup mutated routes after unsafe metric: %s", command)
		}
	}
}

func TestLinuxTUNNetworkDiscoversSafeRelayRoutes(t *testing.T) {
	runner := &recordingLinuxIPRunner{responses: map[string]string{
		"-j\x00-4\x00route\x00get\x00203.0.113.7": `[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","table":"main"}]`,
		"-j\x00-6\x00route\x00get\x002001:db8::7": `[{"dst":"2001:db8::7","gateway":"2001:db8::1","dev":"eth0","table":"main"}]`,
	}}
	manager := mustLinuxTUNNetworkManager(t, runner)
	manager.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("203.0.113.7"),
			netip.MustParseAddr("2001:db8::7"),
			netip.MustParseAddr("203.0.113.7"),
		}, nil
	}
	routes, err := manager.DiscoverRelayRoutes(context.Background(), "https://relay.example/assets/upload/42")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("relay routes = %+v, want two deduplicated routes", routes)
	}
	if routes[0].Address != netip.MustParseAddr("203.0.113.7") || routes[0].Gateway != netip.MustParseAddr("192.0.2.1") || routes[0].Device != "eth0" {
		t.Fatalf("IPv4 relay route = %+v", routes[0])
	}
	if routes[1].Address != netip.MustParseAddr("2001:db8::7") || routes[1].Gateway != netip.MustParseAddr("2001:db8::1") || routes[1].Device != "eth0" {
		t.Fatalf("IPv6 relay route = %+v", routes[1])
	}
}

func TestLinuxTUNNetworkRejectsUnsafeRelayRouteData(t *testing.T) {
	for name, response := range map[string]string{
		"empty":        `[]`,
		"tunnel":       `[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"aurora0","table":"main"}]`,
		"wrong family": `[{"dst":"203.0.113.7","gateway":"2001:db8::1","dev":"eth0","table":"main"}]`,
		"other table":  `[{"dst":"203.0.113.7","gateway":"192.0.2.1","dev":"eth0","table":"100"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			runner := &recordingLinuxIPRunner{responses: map[string]string{
				"-j\x00-4\x00route\x00get\x00203.0.113.7": response,
			}}
			manager := mustLinuxTUNNetworkManager(t, runner)
			manager.resolve = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
			}
			if _, err := manager.DiscoverRelayRoutes(context.Background(), "https://relay.example"); err == nil {
				t.Fatal("unsafe relay route data was accepted")
			}
		})
	}
}

func TestParseTUNConfigRequiresSafeHostPrefixes(t *testing.T) {
	for name, arguments := range map[string][]string{
		"IPv4 subnet":   {"--provisioning", "/private/provisioning.bin", "--ipv4-address", "10.77.0.2/24"},
		"IPv6 subnet":   {"--provisioning", "/private/provisioning.bin", "--ipv6-address", "fd77::2/64"},
		"bad interface": {"--provisioning", "/private/provisioning.bin", "--tun-iface", "aurora/0"},
		"bad MTU":       {"--provisioning", "/private/provisioning.bin", "--tun-mtu", "575"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTUNConfig(arguments, io.Discard); err == nil {
				t.Fatal("unsafe TUN configuration was accepted")
			}
		})
	}
	config, err := parseTUNConfig([]string{"--provisioning", "/private/provisioning.bin"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if config.devicePath == "" || config.interfaceName == "" || config.mtu != 1280 || config.ipv4 != netip.MustParsePrefix("10.77.0.2/32") || config.ipv6 != netip.MustParsePrefix("fd77::2/128") {
		t.Fatalf("default TUN configuration = %+v", config)
	}
}

func mustLinuxTUNNetworkManager(t *testing.T, runner *recordingLinuxIPRunner) *linuxTUNNetworkManager {
	t.Helper()
	manager, err := newLinuxTUNNetworkManager(linuxTUNNetworkConfig{
		Runner:        runner.Run,
		InterfaceName: "aurora0",
		MTU:           1280,
		IPv4:          netip.MustParsePrefix("10.77.0.2/32"),
		IPv6:          netip.MustParsePrefix("fd77::2/128"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

type recordingLinuxIPRunner struct {
	responses map[string]string
	errors    map[string]error
	commands  []string
}

func (r *recordingLinuxIPRunner) Run(_ context.Context, arguments ...string) ([]byte, error) {
	command := strings.Join(arguments, " ")
	r.commands = append(r.commands, command)
	key := strings.Join(arguments, "\x00")
	if err := r.errors[key]; err != nil {
		return nil, err
	}
	return []byte(r.responses[key]), nil
}

func (r *recordingLinuxIPRunner) Commands() []string {
	return append([]string(nil), r.commands...)
}

func requireLinuxIPCommandsInOrder(t *testing.T, commands, expected []string) {
	t.Helper()
	position := 0
	for _, command := range commands {
		if position < len(expected) && command == expected[position] {
			position++
		}
	}
	if position != len(expected) {
		t.Fatalf("commands = %q, missing ordered sequence %q", commands, expected[position:])
	}
}
