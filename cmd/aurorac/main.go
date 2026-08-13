package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/platform"
	"github.com/aurora-protocol/aurora-core/transport"
)

const (
	maximumProvisioningFileBytes = 1 << 20
	maximumIssuerResponseBytes   = 1 << 20
	defaultIssuerRequestTimeout  = 30 * time.Second
)

var (
	proxyGOOS           = runtime.GOOS
	proxyListen         = net.Listen
	proxySignalContext  = defaultProxySignalContext
	newIssuerHTTPClient = defaultIssuerHTTPClient
	openLinuxClientTUN  = func(config platform.LinuxTUNConfig) (io.ReadWriteCloser, error) {
		return platform.OpenLinuxTUNDevice(config)
	}
)

type proxyConfig struct {
	provisioningPath    string
	httpListenAddress   string
	socksListenAddress  string
	allowPublicListener bool
	issuerTimeout       time.Duration
	runtimeOptions      client.TCPProxyRuntimeOptions
}

type proxyComponentResult struct {
	name string
	err  error
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: aurorac <proxy|tun> [options]")
		return 2
	}
	switch args[0] {
	case "proxy":
		return runProxyCommand(args[1:], stdout, stderr)
	case "tun":
		return runTUNCommand(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "aurorac: unknown command %q; use proxy or tun\n", args[0])
		return 2
	}
}

func runProxyCommand(args []string, stdout, stderr io.Writer) int {
	config, err := parseProxyConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	if proxyGOOS != "linux" {
		fmt.Fprintln(stderr, "client: local proxy command requires a Linux host")
		return 2
	}
	ctx, stop := proxySignalContext()
	defer stop()
	if err := runProxy(ctx, config, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runTUNCommand(args []string, stdout, stderr io.Writer) int {
	config, err := parseTUNConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	if proxyGOOS != "linux" {
		fmt.Fprintln(stderr, "client: tunnel command requires a Linux host")
		return 2
	}
	ctx, stop := proxySignalContext()
	defer stop()
	if err := runTUN(ctx, config, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseProxyConfig(args []string, stderr io.Writer) (proxyConfig, error) {
	flags := flag.NewFlagSet("aurorac proxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := proxyConfig{}
	flags.StringVar(&config.provisioningPath, "provisioning", "", "owner-only native provisioning file")
	flags.StringVar(&config.httpListenAddress, "http-listen", "127.0.0.1:8080", "local HTTP CONNECT listen address")
	flags.StringVar(&config.socksListenAddress, "socks-listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	flags.BoolVar(&config.allowPublicListener, "allow-public-listeners", false, "allow non-loopback local proxy listeners")
	flags.DurationVar(&config.issuerTimeout, "issuer-timeout", defaultIssuerRequestTimeout, "issuer request timeout")
	flags.IntVar(&config.runtimeOptions.MaxFlows, "max-flows", 0, "maximum concurrent local TCP proxy flows")
	flags.IntVar(&config.runtimeOptions.ReadBufferBytes, "read-buffer-bytes", 0, "per-flow local read buffer size")
	flags.IntVar(&config.runtimeOptions.MaxPendingWriteBytes, "max-pending-write-bytes", 0, "per-flow local pending write limit")
	if err := flags.Parse(args); err != nil {
		return proxyConfig{}, err
	}
	if flags.NArg() != 0 {
		return proxyConfig{}, fmt.Errorf("client: unexpected proxy command arguments")
	}
	if strings.TrimSpace(config.provisioningPath) == "" || strings.TrimSpace(config.provisioningPath) != config.provisioningPath {
		return proxyConfig{}, fmt.Errorf("client: provisioning file is required")
	}
	if config.issuerTimeout <= 0 || config.issuerTimeout > 5*time.Minute {
		return proxyConfig{}, fmt.Errorf("client: issuer timeout is invalid")
	}
	for _, listener := range []struct {
		name    string
		address string
	}{
		{"HTTP CONNECT", config.httpListenAddress},
		{"SOCKS5", config.socksListenAddress},
	} {
		if err := validateProxyListenAddress(listener.address, config.allowPublicListener); err != nil {
			return proxyConfig{}, fmt.Errorf("client: %s listener: %w", listener.name, err)
		}
	}
	if config.httpListenAddress == config.socksListenAddress {
		return proxyConfig{}, fmt.Errorf("client: HTTP CONNECT and SOCKS5 listeners must differ")
	}
	if err := client.ValidateTCPProxyRuntimeOptions(config.runtimeOptions); err != nil {
		return proxyConfig{}, err
	}
	return config, nil
}

func validateProxyListenAddress(address string, allowPublic bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("listen address must be a concrete host:port")
	}
	if !allowPublic && !isLoopbackProxyHost(host) {
		return fmt.Errorf("listen address must be loopback unless public listeners are explicitly allowed")
	}
	return nil
}

func isLoopbackProxyHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runProxy(ctx context.Context, config proxyConfig, stdout io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("client: proxy context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := readRestrictedProvisioningFile(config.provisioningPath)
	if err != nil {
		return err
	}
	provisioning, err := client.ParseNativeProvisioning(encoded, time.Now())
	zeroProxyBytes(encoded)
	if err != nil {
		return fmt.Errorf("client: parse provisioning: %w", err)
	}
	provisioned, work, err := client.BeginProvisionedSession(ctx, provisioning, client.ProvisionedSessionOptions{IssuerTimeout: config.issuerTimeout})
	zeroProxyProvisioning(&provisioning)
	if err != nil {
		return fmt.Errorf("client: begin provisioned session: %w", err)
	}
	defer provisioned.Close()
	issuerResponse, err := exchangeIssuerWork(ctx, config.issuerTimeout, work)
	work.Zero()
	if err != nil {
		return err
	}
	defer zeroProxyBytes(issuerResponse)
	established, err := provisioned.Complete(ctx, issuerResponse)
	if err != nil {
		return err
	}
	defer established.Close()

	runtime, err := client.NewTCPProxyRuntime(established.Application, config.runtimeOptions)
	if err != nil {
		return err
	}
	defer runtime.Close()
	httpListener, err := proxyListen("tcp", config.httpListenAddress)
	if err != nil {
		return fmt.Errorf("client: listen HTTP CONNECT: %w", err)
	}
	defer httpListener.Close()
	socksListener, err := proxyListen("tcp", config.socksListenAddress)
	if err != nil {
		return fmt.Errorf("client: listen SOCKS5: %w", err)
	}
	defer socksListener.Close()

	fmt.Fprintf(stdout, "aurorac local proxy http=%s socks=%s\n", httpListener.Addr(), socksListener.Addr())
	return runProxyComponents(ctx, established, runtime, httpListener, socksListener)
}

func runTUN(ctx context.Context, config tunConfig, stdout io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("client: tunnel context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := readRestrictedProvisioningFile(config.provisioningPath)
	if err != nil {
		return err
	}
	provisioning, err := client.ParseNativeProvisioning(encoded, time.Now())
	zeroProxyBytes(encoded)
	if err != nil {
		return fmt.Errorf("client: parse provisioning: %w", err)
	}
	defer zeroProxyProvisioning(&provisioning)
	platformConfig, err := config.platformTUNConfig()
	if err != nil {
		return err
	}
	network, err := newLinuxTUNNetworkManager(linuxTUNNetworkConfig{
		InterfaceName: platformConfig.InterfaceName,
		MTU:           platformConfig.MTU,
		IPv4:          config.ipv4,
		IPv6:          config.ipv6,
	})
	if err != nil {
		return err
	}
	relayRoutes, err := network.DiscoverRelayRoutes(ctx, provisioning.RelayURL)
	if err != nil {
		return err
	}
	provisioned, work, err := client.BeginProvisionedSession(ctx, provisioning, client.ProvisionedSessionOptions{IssuerTimeout: config.issuerTimeout})
	zeroProxyProvisioning(&provisioning)
	if err != nil {
		return fmt.Errorf("client: begin provisioned session: %w", err)
	}
	issuerResponse, err := exchangeIssuerWork(ctx, config.issuerTimeout, work)
	work.Zero()
	if err != nil {
		return errors.Join(err, provisioned.Close())
	}
	defer zeroProxyBytes(issuerResponse)
	established, err := provisioned.Complete(ctx, issuerResponse)
	if err != nil {
		return errors.Join(err, provisioned.Close())
	}
	device, err := openLinuxClientTUN(platformConfig)
	if err != nil {
		return errors.Join(fmt.Errorf("client: open Linux tunnel device: %w", err), established.Close(), provisioned.Close())
	}
	state, err := network.Configure(ctx, relayRoutes)
	if err != nil {
		return errors.Join(err, device.Close(), established.Close(), provisioned.Close())
	}
	adapter, err := client.NewPacketAdapter(established.Application, client.PacketAdapterOptions{MaxPacketBytes: platformConfig.MTU})
	if err != nil {
		return errors.Join(err, state.Close(), device.Close(), established.Close(), provisioned.Close())
	}
	runtime, err := client.NewPacketTUNRuntime(adapter, device, client.PacketTUNRuntimeOptions{ReadBufferBytes: platformConfig.MTU})
	if err != nil {
		return errors.Join(err, state.Close(), device.Close(), established.Close(), provisioned.Close())
	}
	fmt.Fprintf(stdout, "aurorac tunnel interface=%s\n", platformConfig.InterfaceName)
	componentErr := runTUNComponents(ctx, established, runtime, state.Close)
	return errors.Join(componentErr, provisioned.Close())
}

func exchangeIssuerWork(ctx context.Context, timeout time.Duration, work client.IssuerWork) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("client: issuer context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("client: issuer timeout is invalid")
	}
	target, err := issuerWorkURL(work)
	if err != nil {
		return nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, target, bytes.NewReader(work.RequestBody))
	if err != nil {
		return nil, fmt.Errorf("client: create issuer request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Pragma", "no-cache")
	httpClient := newIssuerHTTPClient()
	if httpClient == nil {
		return nil, fmt.Errorf("client: issuer HTTP client is unavailable")
	}
	defer httpClient.CloseIdleConnections()
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("client: issuer request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: issuer returned status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		return nil, fmt.Errorf("client: issuer response content type is invalid")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maximumIssuerResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("client: read issuer response: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumIssuerResponseBytes {
		zeroProxyBytes(encoded)
		return nil, fmt.Errorf("client: issuer response length is invalid")
	}
	return encoded, nil
}

func defaultIssuerHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DisableCompression:  true,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
			MaxConnsPerHost:     1,
			MaxIdleConnsPerHost: 0,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func issuerWorkURL(work client.IssuerWork) (string, error) {
	if work.IssuerURL == "" || work.IssuerCarrierPath == "" || len(work.RequestBody) == 0 {
		return "", fmt.Errorf("client: issuer work is incomplete")
	}
	issuerURL, err := url.Parse(work.IssuerURL)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" || issuerURL.User != nil || issuerURL.Path != "" || issuerURL.RawPath != "" || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return "", fmt.Errorf("client: issuer URL is invalid")
	}
	carrierPath, err := url.ParseRequestURI(work.IssuerCarrierPath)
	if err != nil || carrierPath.IsAbs() || carrierPath.Host != "" || carrierPath.RawQuery != "" || carrierPath.Fragment != "" || carrierPath.Path != work.IssuerCarrierPath || !strings.HasPrefix(work.IssuerCarrierPath, "/") || strings.Contains(work.IssuerCarrierPath, "//") || path.Clean(work.IssuerCarrierPath) != work.IssuerCarrierPath {
		return "", fmt.Errorf("client: issuer carrier path is invalid")
	}
	issuerURL.Path = carrierPath.Path
	return issuerURL.String(), nil
}

func runProxyComponents(ctx context.Context, established *handshake.EstablishedSession, runtime *client.TCPProxyRuntime, httpListener, socksListener net.Listener) error {
	if ctx == nil || established == nil || established.Application == nil || established.ReadCarrier == nil || established.WriteCarrier == nil || runtime == nil || httpListener == nil || socksListener == nil {
		return fmt.Errorf("client: proxy components are incomplete")
	}
	componentContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan proxyComponentResult, 3)
	go func() {
		results <- proxyComponentResult{name: "HTTP CONNECT listener", err: runtime.Serve(componentContext, httpListener)}
	}()
	go func() {
		results <- proxyComponentResult{name: "SOCKS5 listener", err: runtime.Serve(componentContext, socksListener)}
	}()
	go func() {
		results <- proxyComponentResult{
			name: "encrypted carrier",
			err:  transport.RunPacketDuplex(componentContext, established.ReadCarrier, established.WriteCarrier, established.Application, runtime.HandleFrameBlock, transport.DefaultMaxRecordBodyBytes),
		}
	}()

	var terminal proxyComponentResult
	select {
	case terminal = <-results:
	case <-ctx.Done():
		terminal = proxyComponentResult{err: ctx.Err()}
	}
	cancel()
	closeErr := errors.Join(closeProxyListener(httpListener), closeProxyListener(socksListener), runtime.Close(), established.Close())
	for remaining := 0; remaining < 2; remaining++ {
		<-results
	}
	if ctx.Err() != nil {
		return nil
	}
	if terminal.err == nil {
		return fmt.Errorf("client: %s stopped unexpectedly", terminal.name)
	}
	if closeErr != nil {
		return errors.Join(fmt.Errorf("client: %s: %w", terminal.name, terminal.err), closeErr)
	}
	return fmt.Errorf("client: %s: %w", terminal.name, terminal.err)
}

func runTUNComponents(ctx context.Context, established *handshake.EstablishedSession, runtime *client.PacketTUNRuntime, beforeDeviceClose func() error) error {
	if ctx == nil || established == nil || established.Application == nil || established.ReadCarrier == nil || established.WriteCarrier == nil || runtime == nil {
		return fmt.Errorf("client: tunnel components are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	componentContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan proxyComponentResult, 2)
	go func() {
		results <- proxyComponentResult{name: "Linux tunnel device", err: runtime.Serve(componentContext)}
	}()
	go func() {
		results <- proxyComponentResult{
			name: "encrypted carrier",
			err:  transport.RunPacketDuplex(componentContext, established.ReadCarrier, established.WriteCarrier, established.Application, runtime.HandleFrameBlock, transport.DefaultMaxRecordBodyBytes),
		}
	}()

	var terminal proxyComponentResult
	collected := 0
	select {
	case terminal = <-results:
		collected = 1
	case <-ctx.Done():
		terminal = proxyComponentResult{err: ctx.Err()}
	}

	// Keep the device alive while owned routes are removed, so cleanup never
	// depends on a tunnel interface that has already disappeared.
	closeErr := established.Close()
	if beforeDeviceClose != nil {
		closeErr = errors.Join(closeErr, beforeDeviceClose())
	}
	closeErr = errors.Join(closeErr, runtime.Close())
	cancel()
	for collected < 2 {
		<-results
		collected++
	}
	if ctx.Err() != nil {
		return closeErr
	}
	if terminal.err == nil {
		return errors.Join(fmt.Errorf("client: %s stopped unexpectedly", terminal.name), closeErr)
	}
	return errors.Join(fmt.Errorf("client: %s: %w", terminal.name, terminal.err), closeErr)
}

func closeProxyListener(listener net.Listener) error {
	if listener == nil {
		return nil
	}
	err := listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func readRestrictedProvisioningFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("client: inspect provisioning file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("client: provisioning file must be regular")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("client: open provisioning file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("client: inspect opened provisioning file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("client: provisioning file changed while opening")
	}
	if runtime.GOOS != "windows" && openedInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("client: provisioning file permissions are too broad")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumProvisioningFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("client: read provisioning file: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumProvisioningFileBytes {
		zeroProxyBytes(encoded)
		return nil, fmt.Errorf("client: provisioning file length is invalid")
	}
	return encoded, nil
}

func zeroProxyProvisioning(provisioning *client.NativeProvisioning) {
	if provisioning == nil {
		return
	}
	for _, value := range [][]byte{
		provisioning.Descriptor,
		provisioning.TrustedDescriptorHash,
		provisioning.Template,
		provisioning.TemplateAuthorityKey,
		provisioning.AccessHint,
		provisioning.PolicyOffer,
		provisioning.TransportHints,
		provisioning.RelayRequestHeaders,
		provisioning.RelayResponseHeaders,
		provisioning.RelayTrustRoots,
	} {
		zeroProxyBytes(value)
	}
	*provisioning = client.NativeProvisioning{}
}

func zeroProxyBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func setProxyGOOSForTest(value string) func() {
	previous := proxyGOOS
	proxyGOOS = value
	return func() { proxyGOOS = previous }
}

func setNewIssuerHTTPClientForTest(value func() *http.Client) func() {
	previous := newIssuerHTTPClient
	newIssuerHTTPClient = value
	return func() { newIssuerHTTPClient = previous }
}
