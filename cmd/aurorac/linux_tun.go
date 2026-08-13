package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/platform"
)

const (
	maximumLinuxRelayAddresses = 16
	linuxBypassRouteMetric     = 5
	linuxRouteCleanupTimeout   = 10 * time.Second
)

type linuxIPRunner func(context.Context, ...string) ([]byte, error)

type linuxRelayAddressResolver func(context.Context, string) ([]netip.Addr, error)

type tunConfig struct {
	provisioningPath string
	devicePath       string
	interfaceName    string
	mtu              int
	ipv4             netip.Prefix
	ipv6             netip.Prefix
	issuerTimeout    time.Duration
}

type linuxTUNNetworkConfig struct {
	Runner        linuxIPRunner
	Resolve       linuxRelayAddressResolver
	InterfaceName string
	MTU           int
	IPv4          netip.Prefix
	IPv6          netip.Prefix
}

type linuxTUNNetworkManager struct {
	runner        linuxIPRunner
	resolve       linuxRelayAddressResolver
	interfaceName string
	mtu           int
	ipv4          netip.Prefix
	ipv6          netip.Prefix
}

type linuxTUNNetworkState struct {
	runner    linuxIPRunner
	cleanup   [][]string
	closeOnce sync.Once
	closeErr  error
}

type linuxHostRoute struct {
	Address netip.Addr
	Gateway netip.Addr
	Device  string
}

type linuxRouteJSON struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gateway"`
	Device      string `json:"dev"`
	Table       string `json:"table"`
	Metric      int    `json:"metric"`
}

type linuxRuleJSON struct {
	Priority int    `json:"priority"`
	From     string `json:"from"`
	To       string `json:"to"`
	Table    string `json:"table"`
}

func parseTUNConfig(arguments []string, stderr io.Writer) (tunConfig, error) {
	defaults := platform.DefaultLinuxTUNConfig()
	config := tunConfig{issuerTimeout: defaultIssuerRequestTimeout}
	flags := flag.NewFlagSet("aurorac tun", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&config.provisioningPath, "provisioning", "", "owner-only native provisioning file")
	flags.StringVar(&config.devicePath, "tun-device", defaults.DevicePath, "Linux TUN device path")
	flags.StringVar(&config.interfaceName, "tun-iface", defaults.InterfaceName, "Linux TUN interface name")
	flags.IntVar(&config.mtu, "tun-mtu", defaults.MTU, "Linux TUN MTU")
	ipv4 := flags.String("ipv4-address", "10.77.0.2/32", "Linux TUN IPv4 host address")
	ipv6 := flags.String("ipv6-address", "fd77::2/128", "Linux TUN IPv6 host address")
	flags.DurationVar(&config.issuerTimeout, "issuer-timeout", defaultIssuerRequestTimeout, "issuer request timeout")
	if err := flags.Parse(arguments); err != nil {
		return tunConfig{}, err
	}
	if flags.NArg() != 0 {
		return tunConfig{}, fmt.Errorf("client: unexpected tunnel command arguments")
	}
	if strings.TrimSpace(config.provisioningPath) == "" || strings.TrimSpace(config.provisioningPath) != config.provisioningPath {
		return tunConfig{}, fmt.Errorf("client: provisioning file is required")
	}
	if !validLinuxInterfaceName(config.interfaceName) {
		return tunConfig{}, fmt.Errorf("client: Linux tunnel interface name is invalid")
	}
	if config.issuerTimeout <= 0 || config.issuerTimeout > 5*time.Minute {
		return tunConfig{}, fmt.Errorf("client: issuer timeout is invalid")
	}
	var err error
	if config.ipv4, err = netip.ParsePrefix(*ipv4); err != nil || !config.ipv4.Addr().Is4() || !isLinuxHostPrefix(config.ipv4, 32) {
		return tunConfig{}, fmt.Errorf("client: Linux tunnel IPv4 address must be a host prefix")
	}
	if config.ipv6, err = netip.ParsePrefix(*ipv6); err != nil || !config.ipv6.Addr().Is6() || !isLinuxHostPrefix(config.ipv6, 128) {
		return tunConfig{}, fmt.Errorf("client: Linux tunnel IPv6 address must be a host prefix")
	}
	if _, err := config.platformTUNConfig(); err != nil {
		return tunConfig{}, err
	}
	return config, nil
}

func (c tunConfig) platformTUNConfig() (platform.LinuxTUNConfig, error) {
	config := platform.DefaultLinuxTUNConfig()
	config.DevicePath = c.devicePath
	config.InterfaceName = c.interfaceName
	config.MTU = c.mtu
	if err := config.Validate(); err != nil {
		return platform.LinuxTUNConfig{}, err
	}
	return config, nil
}

func newLinuxTUNNetworkManager(config linuxTUNNetworkConfig) (*linuxTUNNetworkManager, error) {
	if config.Runner == nil {
		config.Runner = runLinuxIP
	}
	if config.Resolve == nil {
		config.Resolve = resolveLinuxRelayAddresses
	}
	if err := validateLinuxTUNNetworkConfig(config); err != nil {
		return nil, err
	}
	return &linuxTUNNetworkManager{
		runner:        config.Runner,
		resolve:       config.Resolve,
		interfaceName: config.InterfaceName,
		mtu:           config.MTU,
		ipv4:          config.IPv4,
		ipv6:          config.IPv6,
	}, nil
}

func validateLinuxTUNNetworkConfig(config linuxTUNNetworkConfig) error {
	if config.Runner == nil {
		return fmt.Errorf("client: Linux route runner is required")
	}
	if config.Resolve == nil {
		return fmt.Errorf("client: Linux relay resolver is required")
	}
	if !validLinuxInterfaceName(config.InterfaceName) {
		return fmt.Errorf("client: Linux tunnel interface name is invalid")
	}
	if config.MTU < 576 || config.MTU > 9000 {
		return fmt.Errorf("client: Linux tunnel MTU is invalid")
	}
	if !isLinuxHostPrefix(config.IPv4, 32) || !config.IPv4.Addr().Is4() {
		return fmt.Errorf("client: Linux tunnel IPv4 address must be a host prefix")
	}
	if !isLinuxHostPrefix(config.IPv6, 128) || !config.IPv6.Addr().Is6() {
		return fmt.Errorf("client: Linux tunnel IPv6 address must be a host prefix")
	}
	return nil
}

func validLinuxInterfaceName(name string) bool {
	if name == "" || len(name) >= 16 {
		return false
	}
	for _, value := range name {
		if (value < 'a' || value > 'z') && (value < 'A' || value > 'Z') && (value < '0' || value > '9') && value != '-' && value != '_' && value != '.' {
			return false
		}
	}
	return true
}

func isLinuxHostPrefix(prefix netip.Prefix, bits int) bool {
	return prefix.IsValid() && prefix.Bits() == bits && prefix == netip.PrefixFrom(prefix.Addr(), bits)
}

// DiscoverRelayRoutes resolves and validates current non-tunnel routes for the relay origin.
func (m *linuxTUNNetworkManager) DiscoverRelayRoutes(ctx context.Context, relayURL string) ([]linuxHostRoute, error) {
	if m == nil {
		return nil, fmt.Errorf("client: Linux tunnel network manager is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("client: Linux relay route context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hostname, err := relayHostname(relayURL)
	if err != nil {
		return nil, err
	}
	addresses, err := m.resolve(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("client: resolve relay route: %w", err)
	}
	if len(addresses) == 0 || len(addresses) > maximumLinuxRelayAddresses {
		return nil, fmt.Errorf("client: relay address count is invalid")
	}

	routes := make([]linuxHostRoute, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if err := validateLinuxRelayAddress(address); err != nil {
			return nil, err
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		if address.IsLoopback() {
			continue
		}
		route, err := m.lookupRelayRoute(ctx, address)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func relayHostname(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("client: relay URL is invalid")
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.TrimSpace(hostname) != hostname {
		return "", fmt.Errorf("client: relay hostname is invalid")
	}
	return hostname, nil
}

func resolveLinuxRelayAddresses(ctx context.Context, hostname string) ([]netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		return nil, err
	}
	return addresses, nil
}

func validateLinuxRelayAddress(address netip.Addr) error {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return fmt.Errorf("client: relay address is unsafe")
	}
	return nil
}

func (m *linuxTUNNetworkManager) lookupRelayRoute(ctx context.Context, address netip.Addr) (linuxHostRoute, error) {
	family := linuxIPFamily(address)
	encoded, err := m.runner(ctx, "-j", family, "route", "get", address.String())
	if err != nil {
		return linuxHostRoute{}, fmt.Errorf("client: inspect relay route: %w", err)
	}
	var responses []linuxRouteJSON
	if err := json.Unmarshal(encoded, &responses); err != nil || len(responses) != 1 {
		return linuxHostRoute{}, fmt.Errorf("client: relay route response is invalid")
	}
	response := responses[0]
	if response.Destination != address.String() || (response.Table != "" && response.Table != "main") || response.Device == m.interfaceName || !validLinuxInterfaceName(response.Device) {
		return linuxHostRoute{}, fmt.Errorf("client: relay route response is unsafe")
	}
	route := linuxHostRoute{Address: address, Device: response.Device}
	if response.Gateway != "" {
		gateway, err := netip.ParseAddr(response.Gateway)
		if err != nil || !gateway.IsValid() || gateway.IsUnspecified() || gateway.IsMulticast() || gateway.BitLen() != address.BitLen() {
			return linuxHostRoute{}, fmt.Errorf("client: relay route gateway is invalid")
		}
		route.Gateway = gateway.Unmap()
	}
	return route, nil
}

// Configure applies owned relay bypasses and tunnel defaults after validating route precedence.
func (m *linuxTUNNetworkManager) Configure(ctx context.Context, routes []linuxHostRoute) (*linuxTUNNetworkState, error) {
	if m == nil {
		return nil, fmt.Errorf("client: Linux tunnel network manager is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("client: Linux tunnel configuration context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := m.validateHostRoutes(routes); err != nil {
		return nil, err
	}
	if err := m.validateMainRoutingPolicy(ctx, "-4"); err != nil {
		return nil, err
	}
	if err := m.validateMainRoutingPolicy(ctx, "-6"); err != nil {
		return nil, err
	}
	ipv4Metric, err := m.tunnelDefaultMetric(ctx, "-4")
	if err != nil {
		return nil, err
	}
	ipv6Metric, err := m.tunnelDefaultMetric(ctx, "-6")
	if err != nil {
		return nil, err
	}
	state := &linuxTUNNetworkState{runner: m.runner}
	for _, route := range routes {
		add := linuxHostRouteArguments("add", route)
		remove := linuxHostRouteArguments("del", route)
		if err := state.add(ctx, add, remove); err != nil {
			return nil, state.fail(err)
		}
	}
	if err := state.add(ctx,
		[]string{"link", "set", "dev", m.interfaceName, "mtu", strconv.Itoa(m.mtu), "up"},
		[]string{"link", "set", "dev", m.interfaceName, "down"},
	); err != nil {
		return nil, state.fail(err)
	}
	if err := state.add(ctx,
		[]string{"-4", "address", "add", m.ipv4.String(), "dev", m.interfaceName},
		[]string{"-4", "address", "del", m.ipv4.String(), "dev", m.interfaceName},
	); err != nil {
		return nil, state.fail(err)
	}
	if err := state.add(ctx,
		[]string{"-6", "address", "add", m.ipv6.String(), "dev", m.interfaceName},
		[]string{"-6", "address", "del", m.ipv6.String(), "dev", m.interfaceName},
	); err != nil {
		return nil, state.fail(err)
	}
	if err := state.add(ctx,
		linuxDefaultRouteArguments("add", m.interfaceName, "-4", ipv4Metric),
		linuxDefaultRouteArguments("del", m.interfaceName, "-4", ipv4Metric),
	); err != nil {
		return nil, state.fail(err)
	}
	if err := state.add(ctx,
		linuxDefaultRouteArguments("add", m.interfaceName, "-6", ipv6Metric),
		linuxDefaultRouteArguments("del", m.interfaceName, "-6", ipv6Metric),
	); err != nil {
		return nil, state.fail(err)
	}
	return state, nil
}

func (m *linuxTUNNetworkManager) validateHostRoutes(routes []linuxHostRoute) error {
	if len(routes) > maximumLinuxRelayAddresses {
		return fmt.Errorf("client: relay route count is invalid")
	}
	seen := make(map[netip.Addr]struct{}, len(routes))
	for _, route := range routes {
		if err := validateLinuxRelayAddress(route.Address); err != nil {
			return err
		}
		if route.Address.IsLoopback() || route.Device == m.interfaceName || !validLinuxInterfaceName(route.Device) {
			return fmt.Errorf("client: relay route is unsafe")
		}
		if route.Gateway.IsValid() && route.Gateway.BitLen() != route.Address.BitLen() {
			return fmt.Errorf("client: relay route gateway is invalid")
		}
		if _, ok := seen[route.Address]; ok {
			return fmt.Errorf("client: relay route is duplicated")
		}
		seen[route.Address] = struct{}{}
	}
	return nil
}

func (m *linuxTUNNetworkManager) validateMainRoutingPolicy(ctx context.Context, family string) error {
	encoded, err := m.runner(ctx, "-j", family, "rule", "show")
	if err != nil {
		return fmt.Errorf("client: inspect Linux routing policy: %w", err)
	}
	var rules []linuxRuleJSON
	if err := json.Unmarshal(encoded, &rules); err != nil {
		return fmt.Errorf("client: Linux routing policy response is invalid")
	}
	expected := map[int]string{0: "local", 32766: "main", 32767: "default"}
	if len(rules) != len(expected) {
		return fmt.Errorf("client: Linux routing policy is unsafe")
	}
	for _, rule := range rules {
		table, ok := expected[rule.Priority]
		if !ok || rule.Table != table || rule.From != "all" || rule.To != "all" {
			return fmt.Errorf("client: Linux routing policy is unsafe")
		}
		delete(expected, rule.Priority)
	}
	if len(expected) != 0 {
		return fmt.Errorf("client: Linux routing policy is unsafe")
	}
	return nil
}

func (m *linuxTUNNetworkManager) tunnelDefaultMetric(ctx context.Context, family string) (int, error) {
	encoded, err := m.runner(ctx, "-j", family, "route", "show", "default")
	if err != nil {
		return 0, fmt.Errorf("client: inspect Linux default route: %w", err)
	}
	var routes []linuxRouteJSON
	if err := json.Unmarshal(encoded, &routes); err != nil {
		return 0, fmt.Errorf("client: Linux default route response is invalid")
	}
	if len(routes) > maximumLinuxRelayAddresses {
		return 0, fmt.Errorf("client: Linux default route count is invalid")
	}
	metric := 1
	if len(routes) > 0 {
		metric = int(^uint(0) >> 1)
	}
	for _, route := range routes {
		if route.Destination != "default" || route.Metric <= 0 {
			return 0, fmt.Errorf("client: Linux default route precedence is unsafe")
		}
		candidate := route.Metric - 1
		if candidate < metric {
			metric = candidate
		}
	}
	return metric, nil
}

func linuxHostRouteArguments(operation string, route linuxHostRoute) []string {
	arguments := []string{linuxIPFamily(route.Address), "route", operation, netip.PrefixFrom(route.Address, route.Address.BitLen()).String()}
	if route.Gateway.IsValid() {
		arguments = append(arguments, "via", route.Gateway.String())
	}
	arguments = append(arguments, "dev", route.Device, "metric", strconv.Itoa(linuxBypassRouteMetric))
	return arguments
}

func linuxDefaultRouteArguments(operation, interfaceName, family string, metric int) []string {
	return []string{family, "route", operation, "default", "dev", interfaceName, "metric", strconv.Itoa(metric)}
}

func linuxIPFamily(address netip.Addr) string {
	if address.Is4() {
		return "-4"
	}
	return "-6"
}

func (s *linuxTUNNetworkState) add(ctx context.Context, arguments, cleanup []string) error {
	if _, err := s.runner(ctx, arguments...); err != nil {
		return fmt.Errorf("client: configure Linux tunnel route: %w", err)
	}
	if len(cleanup) > 0 {
		s.cleanup = append(s.cleanup, cleanup)
	}
	return nil
}

func (s *linuxTUNNetworkState) fail(err error) error {
	return errors.Join(err, s.Close())
}

// Close removes routes and addresses that this network state added.
func (s *linuxTUNNetworkState) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), linuxRouteCleanupTimeout)
		defer cancel()
		var cleanupErrors []error
		for index := len(s.cleanup) - 1; index >= 0; index-- {
			if _, err := s.runner(ctx, s.cleanup[index]...); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("client: remove Linux tunnel route: %w", err))
			}
		}
		s.closeErr = errors.Join(cleanupErrors...)
		s.cleanup = nil
	})
	return s.closeErr
}

func runLinuxIP(ctx context.Context, arguments ...string) ([]byte, error) {
	path, err := linuxIPPath()
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, path, arguments...)
	encoded, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("client: execute Linux network command: %w", err)
	}
	return encoded, nil
}

func linuxIPPath() (string, error) {
	for _, candidate := range []string{"/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"} {
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("client: Linux network command is unavailable")
}
