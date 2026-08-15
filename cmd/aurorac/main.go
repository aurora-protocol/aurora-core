package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
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
	defaultCarrierRetryInitial   = 250 * time.Millisecond
	defaultCarrierRetryMaximum   = 10 * time.Second
	encryptedCarrierComponent    = "encrypted carrier"
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
	provisioningPath       string
	provisioningWalletPath string
	walletStatePath        string
	signedSeedTrustPath    string
	httpListenAddress      string
	socksListenAddress     string
	allowPublicListener    bool
	issuerTimeout          time.Duration
	runtimeOptions         client.TCPProxyRuntimeOptions
}

type proxyComponentResult struct {
	name string
	err  error
}

type componentFailure struct {
	name string
	err  error
}

func (e *componentFailure) Error() string {
	if e == nil {
		return "client: component failure is unavailable"
	}
	if e.err == nil {
		return fmt.Sprintf("client: %s stopped unexpectedly", e.name)
	}
	return fmt.Sprintf("client: %s: %v", e.name, e.err)
}

func (e *componentFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

type carrierRecoveryPolicy struct {
	InitialDelay time.Duration
	MaximumDelay time.Duration
	Jitter       func(time.Duration) (time.Duration, error)
	Wait         func(context.Context, time.Duration) error
}

type carrierRecoveryAttempt func(context.Context) (recoverable bool, err error)

type provisioningWalletReservation func(time.Time) (client.NativeProvisioningReservation, error)

type provisioningWalletAttempt func(context.Context, client.NativeProvisioningReservation) error

func newComponentFailure(result proxyComponentResult) *componentFailure {
	return &componentFailure{name: result.name, err: result.err}
}

func isRecoverableCarrierFailure(err error) bool {
	var failure *componentFailure
	return errors.As(err, &failure) && failure.name == encryptedCarrierComponent && (errors.Is(failure.err, transport.ErrCarrierRead) || errors.Is(failure.err, transport.ErrCarrierWrite))
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
	flags.StringVar(&config.provisioningPath, "provisioning", "", "owner-only one-time native provisioning file")
	flags.StringVar(&config.provisioningWalletPath, "provisioning-wallet", "", "owner-only native provisioning wallet file")
	flags.StringVar(&config.walletStatePath, "wallet-state", "", "owner-only local wallet reservation state file")
	flags.StringVar(&config.signedSeedTrustPath, "signed-seed-roots", "", "owner-only signed-seed root configuration")
	flags.StringVar(&config.httpListenAddress, "http-listen", "127.0.0.1:8080", "local HTTP CONNECT listen address")
	flags.StringVar(&config.socksListenAddress, "socks-listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	flags.BoolVar(&config.allowPublicListener, "allow-public-listeners", false, "allow non-loopback local proxy listeners")
	flags.DurationVar(&config.issuerTimeout, "issuer-timeout", defaultIssuerRequestTimeout, "issuer request timeout")
	flags.IntVar(&config.runtimeOptions.MaxFlows, "max-flows", 0, "maximum concurrent local TCP proxy flows")
	flags.IntVar(&config.runtimeOptions.ReadBufferBytes, "read-buffer-bytes", 0, "per-flow local read buffer size")
	flags.IntVar(&config.runtimeOptions.MaxPendingWriteBytes, "max-pending-write-bytes", 0, "per-flow local pending write limit")
	flags.IntVar(&config.runtimeOptions.MaxTotalPendingWriteBytes, "max-total-pending-write-bytes", 0, "aggregate local pending write limit")
	if err := flags.Parse(args); err != nil {
		return proxyConfig{}, err
	}
	if flags.NArg() != 0 {
		return proxyConfig{}, fmt.Errorf("client: unexpected proxy command arguments")
	}
	if err := validateProvisioningSource(config.provisioningPath, config.provisioningWalletPath, config.walletStatePath, config.signedSeedTrustPath); err != nil {
		return proxyConfig{}, err
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

func validateProvisioningSource(provisioningPath, walletPath, statePath, trustPath string) error {
	single := validProvisioningPath(provisioningPath)
	wallet := validProvisioningPath(walletPath)
	state := validProvisioningPath(statePath)
	trusted := validProvisioningPath(trustPath)
	if (provisioningPath != "" && !single) || (walletPath != "" && !wallet) || (statePath != "" && !state) || (trustPath != "" && !trusted) {
		return fmt.Errorf("client: provisioning source path is invalid")
	}
	if single == wallet {
		return fmt.Errorf("client: exactly one provisioning source is required")
	}
	if (single || wallet) != state {
		return fmt.Errorf("client: provisioning requires a wallet state file")
	}
	if (single || wallet) != trusted {
		return fmt.Errorf("client: provisioning requires a signed-seed root configuration")
	}
	return nil
}

func validProvisioningPath(path string) bool {
	return strings.TrimSpace(path) != "" && strings.TrimSpace(path) == path
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
	signedSeedTrust, err := loadNativeProvisioningTrust(config.signedSeedTrustPath)
	if err != nil {
		return err
	}
	if config.provisioningWalletPath != "" {
		return runProxyWithProvisioningWallet(ctx, config, signedSeedTrust, stdout)
	}
	return runProxyAttempt(ctx, config, signedSeedTrust, stdout)
}

func runProxyAttempt(ctx context.Context, config proxyConfig, signedSeedTrust client.NativeProvisioningTrust, stdout io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("client: proxy context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	reservation, err := reserveSingleNativeProvisioning(config.provisioningPath, config.walletStatePath, signedSeedTrust, time.Now().UTC())
	if err != nil {
		return err
	}
	defer reservation.Zero()
	return runProxyWithProvisioning(ctx, config, reservation.Provisioning, stdout)
}

func runProxyWithProvisioningWallet(ctx context.Context, config proxyConfig, signedSeedTrust client.NativeProvisioningTrust, stdout io.Writer) error {
	encoded, err := readRestrictedProvisioningWalletFile(config.provisioningWalletPath)
	if err != nil {
		return err
	}
	sourceDigest := provisioningWalletSourceDigest(encoded)
	wallet, err := client.ParseNativeProvisioningWalletWithTrust(encoded, signedSeedTrust, time.Now().UTC())
	zeroProxyBytes(encoded)
	if err != nil {
		return fmt.Errorf("client: parse provisioning wallet: %w", err)
	}
	defer wallet.Zero()
	store, err := newProvisioningWalletStateStore(config.walletStatePath)
	if err != nil {
		return err
	}
	return runWithProvisioningWallet(ctx, carrierRecoveryPolicy{}, func(now time.Time) (client.NativeProvisioningReservation, error) {
		return store.Reserve(wallet, sourceDigest, now)
	}, func(attemptContext context.Context, reservation client.NativeProvisioningReservation) error {
		return runProxyWithProvisioning(attemptContext, config, reservation.Provisioning, stdout)
	})
}

func runProxyWithProvisioning(ctx context.Context, config proxyConfig, provisioning client.NativeProvisioning, stdout io.Writer) error {
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
	signedSeedTrust, err := loadNativeProvisioningTrust(config.signedSeedTrustPath)
	if err != nil {
		return err
	}
	if config.provisioningWalletPath != "" {
		return runTUNWithProvisioningWallet(ctx, config, signedSeedTrust, stdout)
	}
	return runTUNAttempt(ctx, config, signedSeedTrust, stdout)
}

func runTUNAttempt(ctx context.Context, config tunConfig, signedSeedTrust client.NativeProvisioningTrust, stdout io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("client: tunnel context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	reservation, err := reserveSingleNativeProvisioning(config.provisioningPath, config.walletStatePath, signedSeedTrust, time.Now().UTC())
	if err != nil {
		return err
	}
	defer reservation.Zero()
	return runTUNWithProvisioning(ctx, config, reservation.Provisioning, stdout)
}

func runTUNWithProvisioningWallet(ctx context.Context, config tunConfig, signedSeedTrust client.NativeProvisioningTrust, stdout io.Writer) error {
	encoded, err := readRestrictedProvisioningWalletFile(config.provisioningWalletPath)
	if err != nil {
		return err
	}
	sourceDigest := provisioningWalletSourceDigest(encoded)
	wallet, err := client.ParseNativeProvisioningWalletWithTrust(encoded, signedSeedTrust, time.Now().UTC())
	zeroProxyBytes(encoded)
	if err != nil {
		return fmt.Errorf("client: parse provisioning wallet: %w", err)
	}
	defer wallet.Zero()
	store, err := newProvisioningWalletStateStore(config.walletStatePath)
	if err != nil {
		return err
	}
	return runWithProvisioningWallet(ctx, carrierRecoveryPolicy{}, func(now time.Time) (client.NativeProvisioningReservation, error) {
		return store.Reserve(wallet, sourceDigest, now)
	}, func(attemptContext context.Context, reservation client.NativeProvisioningReservation) error {
		return runTUNWithProvisioning(attemptContext, config, reservation.Provisioning, stdout)
	})
}

func runTUNWithProvisioning(ctx context.Context, config tunConfig, provisioning client.NativeProvisioning, stdout io.Writer) error {
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

func runWithCarrierRecovery(ctx context.Context, policy carrierRecoveryPolicy, attempt carrierRecoveryAttempt) error {
	if ctx == nil {
		return fmt.Errorf("client: carrier recovery context is required")
	}
	if attempt == nil {
		return fmt.Errorf("client: carrier recovery attempt is required")
	}
	policy, err := normalizeCarrierRecoveryPolicy(policy)
	if err != nil {
		return err
	}
	delay := policy.InitialDelay
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		recoverable, err := attempt(ctx)
		if ctx.Err() != nil {
			if err == nil || err == ctx.Err() {
				return nil
			}
			return err
		}
		if err == nil {
			return nil
		}
		if !recoverable {
			return err
		}
		waitDelay, jitterErr := policy.Jitter(delay)
		if jitterErr != nil {
			return fmt.Errorf("client: randomize carrier recovery delay: %w", jitterErr)
		}
		if waitDelay <= 0 || waitDelay > delay {
			return fmt.Errorf("client: carrier recovery jitter is invalid")
		}
		if waitErr := policy.Wait(ctx, waitDelay); waitErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return waitErr
		}
		delay = nextCarrierRecoveryDelay(delay, policy.MaximumDelay)
	}
}

func runWithProvisioningWallet(ctx context.Context, policy carrierRecoveryPolicy, reserve provisioningWalletReservation, attempt provisioningWalletAttempt) error {
	if reserve == nil {
		return fmt.Errorf("client: wallet reservation is required")
	}
	if attempt == nil {
		return fmt.Errorf("client: wallet attempt is required")
	}
	return runWithCarrierRecovery(ctx, policy, func(attemptContext context.Context) (bool, error) {
		now := time.Now().UTC()
		reservation, err := reserve(now)
		if err != nil {
			return false, err
		}
		defer reservation.Zero()
		if reservation.AccessHintExpiryUnix <= uint64(now.Unix()) {
			return false, fmt.Errorf("client: wallet reservation is expired")
		}
		err = attempt(attemptContext, reservation)
		return isRecoverableCarrierFailure(err), err
	})
}

func normalizeCarrierRecoveryPolicy(policy carrierRecoveryPolicy) (carrierRecoveryPolicy, error) {
	if policy.InitialDelay == 0 {
		policy.InitialDelay = defaultCarrierRetryInitial
	}
	if policy.MaximumDelay == 0 {
		policy.MaximumDelay = defaultCarrierRetryMaximum
	}
	if policy.InitialDelay <= 0 || policy.MaximumDelay <= 0 || policy.InitialDelay > policy.MaximumDelay {
		return carrierRecoveryPolicy{}, fmt.Errorf("client: carrier recovery policy is invalid")
	}
	if policy.Wait == nil {
		policy.Wait = waitForCarrierRecovery
	}
	if policy.Jitter == nil {
		policy.Jitter = jitterCarrierRecoveryDelay
	}
	return policy, nil
}

func jitterCarrierRecoveryDelay(maximum time.Duration) (time.Duration, error) {
	if maximum <= 0 {
		return 0, fmt.Errorf("client: carrier recovery delay is invalid")
	}
	minimum := maximum / 2
	if minimum == 0 {
		return maximum, nil
	}
	span := maximum - minimum
	if span == 0 {
		return maximum, nil
	}
	random, err := rand.Int(rand.Reader, big.NewInt(int64(span)+1))
	if err != nil {
		return 0, err
	}
	return minimum + time.Duration(random.Int64()), nil
}

func waitForCarrierRecovery(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextCarrierRecoveryDelay(delay, maximum time.Duration) time.Duration {
	if delay >= maximum || delay > maximum/2 {
		return maximum
	}
	return delay * 2
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
	stopResponseCancel := context.AfterFunc(requestContext, func() {
		_ = response.Body.Close()
	})
	defer stopResponseCancel()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: issuer returned status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		return nil, fmt.Errorf("client: issuer response content type is invalid")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maximumIssuerResponseBytes+1))
	if err != nil {
		zeroProxyBytes(encoded)
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
			name: encryptedCarrierComponent,
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
		return closeErr
	}
	terminalErr := newComponentFailure(terminal)
	if closeErr != nil {
		return errors.Join(terminalErr, closeErr)
	}
	return terminalErr
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
			name: encryptedCarrierComponent,
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
	return errors.Join(newComponentFailure(terminal), closeErr)
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
	return readRestrictedOwnerFile(path, maximumProvisioningFileBytes, "provisioning file")
}

func readRestrictedProvisioningWalletFile(path string) ([]byte, error) {
	return readRestrictedOwnerFile(path, client.MaximumNativeProvisioningWalletBytes, "provisioning wallet file")
}

func loadNativeProvisioningTrust(path string) (client.NativeProvisioningTrust, error) {
	encoded, err := readRestrictedOwnerFile(path, client.MaximumNativeProvisioningTrustBytes, "signed-seed root configuration")
	if err != nil {
		return client.NativeProvisioningTrust{}, err
	}
	trusted, err := client.ParseNativeProvisioningTrust(encoded)
	zeroProxyBytes(encoded)
	if err != nil {
		return client.NativeProvisioningTrust{}, fmt.Errorf("client: parse signed-seed root configuration: %w", err)
	}
	return trusted, nil
}

func reserveSingleNativeProvisioning(provisioningPath, statePath string, signedSeedTrust client.NativeProvisioningTrust, now time.Time) (client.NativeProvisioningReservation, error) {
	encoded, err := readRestrictedProvisioningFile(provisioningPath)
	if err != nil {
		return client.NativeProvisioningReservation{}, err
	}
	sourceDigest := provisioningWalletSourceDigest(encoded)
	provisioning, err := client.ParseNativeProvisioningWithTrust(encoded, signedSeedTrust, now)
	zeroProxyBytes(encoded)
	if err != nil {
		return client.NativeProvisioningReservation{}, fmt.Errorf("client: parse provisioning: %w", err)
	}
	walletEncoded, err := client.EncodeNativeProvisioningWallet([]client.NativeProvisioning{provisioning})
	zeroProxyProvisioning(&provisioning)
	if err != nil {
		return client.NativeProvisioningReservation{}, fmt.Errorf("client: encode single provisioning wallet: %w", err)
	}
	wallet, err := client.ParseNativeProvisioningWalletWithTrust(walletEncoded, signedSeedTrust, now)
	zeroProxyBytes(walletEncoded)
	if err != nil {
		return client.NativeProvisioningReservation{}, fmt.Errorf("client: load single provisioning wallet: %w", err)
	}
	defer wallet.Zero()
	store, err := newProvisioningWalletStateStore(statePath)
	if err != nil {
		return client.NativeProvisioningReservation{}, err
	}
	return store.Reserve(wallet, sourceDigest, now)
}

func readRestrictedOwnerFile(path string, maximumBytes int, label string) ([]byte, error) {
	if maximumBytes <= 0 || label == "" {
		return nil, fmt.Errorf("client: restricted file limits are invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("client: inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("client: %s must be regular", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("client: open %s: %w", label, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("client: inspect opened %s: %w", label, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("client: %s changed while opening", label)
	}
	if err := validateRestrictedOwnerFileOwner(openedInfo); err != nil {
		return nil, fmt.Errorf("client: %s: %w", label, err)
	}
	if runtime.GOOS != "windows" && openedInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("client: %s permissions are too broad", label)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if err != nil {
		zeroProxyBytes(encoded)
		return nil, fmt.Errorf("client: read %s: %w", label, err)
	}
	if len(encoded) == 0 || len(encoded) > maximumBytes {
		zeroProxyBytes(encoded)
		return nil, fmt.Errorf("client: %s length is invalid", label)
	}
	return encoded, nil
}

func zeroProxyProvisioning(provisioning *client.NativeProvisioning) {
	if provisioning == nil {
		return
	}
	for _, value := range [][]byte{
		provisioning.IssuerMetadata,
		provisioning.SignedSeed,
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
