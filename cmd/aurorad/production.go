package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	maximumProductionConfigurationFileBytes = 1 << 20
	productionShutdownTimeout               = 15 * time.Second
)

var (
	productionListen        = func(address string) (net.Listener, error) { return net.Listen("tcp", address) }
	productionSignalContext = defaultProductionSignalContext
)

type productionConfig struct {
	listenAddress             string
	authority                 string
	path                      string
	tlsCertificatePath        string
	tlsPrivateKeyPath         string
	coverOriginURL            string
	descriptorPath            string
	trustedDescriptorHashPath string
	templatePath              string
	templateAuthorityKeyPath  string
	requestClassID            uint64
	suite                     uint64
	classicalSignerPath       string
	pqSignerPath              string
	accessHintsPath           string
	tokenVerificationKeyPath  string
	hintSpentCachePath        string
	tokenSpentCachePath       string
	bootstrapCachePath        string
	maxConcurrentSessions     int
	policy                    uint64
	route                     uint64
	shape                     uint64
	sessionLimits             session.Limits
	egressLimits              relay.SocketEgressLimits
	exitRateLimit             relay.ExitRateLimit
	egressResolvedTTL         uint
	egressMaxFlowOpens        uint
	udpConfirmTTL             uint
	dnsUpstream               string
	allowPrivateExit          bool
	maxTemplateFutureSkew     uint64
}

func runServe(args []string, stdout, stderr io.Writer) int {
	config, err := parseProductionConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "server: production service requires a Linux host")
		return 2
	}
	service, caches, err := newProductionService(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer closeProductionCaches(caches)
	listener, err := productionListen(config.listenAddress)
	if err != nil {
		fmt.Fprintf(stderr, "server: listen: %v\n", err)
		return 1
	}
	defer listener.Close()
	ctx, stop := productionSignalContext()
	defer stop()
	fmt.Fprintln(stdout, "aurorad production server started")
	if err := serveProduction(ctx, service, listener); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseProductionConfig(args []string, stderr io.Writer) (productionConfig, error) {
	flags := flag.NewFlagSet("aurorad serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := productionConfig{}
	flags.StringVar(&config.listenAddress, "listen", "", "public listen address")
	flags.StringVar(&config.authority, "authority", "", "carrier authority")
	flags.StringVar(&config.path, "path", "", "carrier path")
	flags.StringVar(&config.tlsCertificatePath, "tls-cert", "", "TLS certificate path")
	flags.StringVar(&config.tlsPrivateKeyPath, "tls-key", "", "TLS private key path")
	flags.StringVar(&config.coverOriginURL, "cover-origin-url", "", "cover origin URL")
	flags.StringVar(&config.descriptorPath, "relay-descriptor", "", "canonical relay descriptor path")
	flags.StringVar(&config.trustedDescriptorHashPath, "trusted-descriptor-hash", "", "trusted relay descriptor hash path")
	flags.StringVar(&config.templatePath, "cover-template", "", "canonical cover template path")
	flags.StringVar(&config.templateAuthorityKeyPath, "template-authority-key", "", "canonical template authority key path")
	flags.Uint64Var(&config.requestClassID, "request-class", 0, "carrier request class ID")
	flags.Uint64Var(&config.suite, "suite", 0, "cryptographic suite")
	flags.StringVar(&config.classicalSignerPath, "classical-signer-key", "", "P-256 transcript private key path")
	flags.StringVar(&config.pqSignerPath, "pq-signer-key", "", "ML-DSA transcript private key path")
	flags.StringVar(&config.accessHintsPath, "access-hints", "", "canonical access hint credential set path")
	flags.StringVar(&config.tokenVerificationKeyPath, "token-verification-key", "", "Blind RSA verification key path")
	flags.StringVar(&config.hintSpentCachePath, "hint-spent-cache", "", "durable spent access-hint cache path")
	flags.StringVar(&config.tokenSpentCachePath, "token-spent-cache", "", "durable spent admission-token cache path")
	flags.StringVar(&config.bootstrapCachePath, "bootstrap-cache", "", "durable bootstrap replay cache path")
	flags.IntVar(&config.maxConcurrentSessions, "max-sessions", 0, "maximum concurrent authenticated sessions")
	flags.Uint64Var(&config.policy, "policy", registry.PolicyBalancedWeb, "fixed policy ID")
	flags.Uint64Var(&config.route, "route", registry.RouteFast1, "fixed route mode ID")
	flags.Uint64Var(&config.shape, "shape", registry.ShapeNormal, "fixed shape ID")
	flags.IntVar(&config.sessionLimits.MaxQueuedPackets, "session-max-queued-packets", 256, "session outbound packet queue limit")
	flags.IntVar(&config.sessionLimits.MaxQueuedBytes, "session-max-queued-bytes", 4<<20, "session outbound queue byte limit")
	flags.IntVar(&config.sessionLimits.ControlReservedPackets, "session-control-reserved-packets", 2, "session reserved control packets")
	flags.IntVar(&config.sessionLimits.ControlReservedBytes, "session-control-reserved-bytes", 16<<10, "session reserved control bytes")
	flags.Uint64Var(&config.sessionLimits.ReplayWindow, "session-replay-window", 1024, "session replay window")
	flags.IntVar(&config.egressLimits.MaxFlows, "egress-max-flows", 256, "maximum concurrent egress flows per session")
	flags.IntVar(&config.egressLimits.MaxBufferedBytes, "egress-max-buffered-bytes", 16<<20, "egress buffered-byte limit per session")
	flags.IntVar(&config.egressLimits.TCPReadBufferBytes, "egress-tcp-read-buffer-bytes", 32<<10, "egress TCP read buffer size")
	flags.IntVar(&config.egressLimits.MaxUDPDatagramBytes, "egress-max-udp-datagram-bytes", 65535, "egress UDP datagram size")
	flags.DurationVar(&config.egressLimits.DialTimeout, "egress-dial-timeout", 10*time.Second, "egress dial timeout")
	flags.DurationVar(&config.egressLimits.WriteTimeout, "egress-write-timeout", 10*time.Second, "egress write timeout")
	flags.DurationVar(&config.egressLimits.IdleTimeout, "egress-idle-timeout", 2*time.Minute, "egress flow idle timeout")
	flags.DurationVar(&config.egressLimits.QueueRetryInterval, "egress-queue-retry", 5*time.Millisecond, "egress backpressure retry interval")
	flags.UintVar(&config.egressResolvedTTL, "egress-resolved-ttl", 300, "egress resolved target TTL in seconds")
	flags.Uint64Var(&config.exitRateLimit.WindowSeconds, "egress-rate-window", 60, "egress rate limit window in seconds")
	flags.UintVar(&config.egressMaxFlowOpens, "egress-max-flow-opens", 1024, "egress maximum flow opens per window")
	flags.Uint64Var(&config.exitRateLimit.MaxBytes, "egress-max-bytes", 64<<20, "egress maximum bytes per window")
	flags.UintVar(&config.udpConfirmTTL, "udp-confirm-ttl", 300, "UDP association confirmation TTL in seconds")
	flags.StringVar(&config.dnsUpstream, "dns-upstream", "", "numeric UDP DNS resolver address")
	flags.BoolVar(&config.allowPrivateExit, "allow-private-exit", false, "allow private destination ranges")
	flags.Uint64Var(&config.maxTemplateFutureSkew, "max-template-future-skew", 120, "maximum future template validity skew in seconds")
	if err := flags.Parse(args); err != nil {
		return productionConfig{}, err
	}
	if flags.NArg() != 0 {
		return productionConfig{}, fmt.Errorf("server: unexpected production command arguments")
	}
	if err := config.validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return productionConfig{}, err
	}
	return config, nil
}

func (c productionConfig) validate() error {
	for _, field := range []struct{ name, value string }{
		{"listen address", c.listenAddress},
		{"authority", c.authority},
		{"path", c.path},
		{"TLS certificate", c.tlsCertificatePath},
		{"TLS private key", c.tlsPrivateKeyPath},
		{"cover origin URL", c.coverOriginURL},
		{"relay descriptor", c.descriptorPath},
		{"trusted descriptor hash", c.trustedDescriptorHashPath},
		{"cover template", c.templatePath},
		{"template authority key", c.templateAuthorityKeyPath},
		{"classical signer key", c.classicalSignerPath},
		{"PQ signer key", c.pqSignerPath},
		{"access hints", c.accessHintsPath},
		{"token verification key", c.tokenVerificationKeyPath},
		{"hint spent cache", c.hintSpentCachePath},
		{"token spent cache", c.tokenSpentCachePath},
		{"bootstrap cache", c.bootstrapCachePath},
		{"DNS upstream", c.dnsUpstream},
	} {
		if strings.TrimSpace(field.value) == "" || strings.TrimSpace(field.value) != field.value {
			return fmt.Errorf("server: %s is required", field.name)
		}
	}
	if c.requestClassID == 0 || c.suite == 0 || c.maxConcurrentSessions <= 0 {
		return fmt.Errorf("server: request class, suite, and session limit are required")
	}
	if c.maxTemplateFutureSkew == 0 {
		return fmt.Errorf("server: maximum template future skew is required")
	}
	if c.egressResolvedTTL > uint(^uint32(0)) || c.egressMaxFlowOpens > uint(^uint32(0)) || c.udpConfirmTTL > uint(^uint32(0)) {
		return fmt.Errorf("server: egress limits exceed supported range")
	}
	c.egressLimits.ResolvedTTLSeconds = uint32(c.egressResolvedTTL)
	c.exitRateLimit.MaxFlowOpens = uint32(c.egressMaxFlowOpens)
	if _, err := url.ParseRequestURI(c.coverOriginURL); err != nil {
		return fmt.Errorf("server: cover origin URL is invalid: %w", err)
	}
	if _, _, err := net.SplitHostPort(c.listenAddress); err != nil {
		return fmt.Errorf("server: listen address is invalid: %w", err)
	}
	if err := relay.ValidateSocketEgressLimits(c.egressLimits); err != nil {
		return fmt.Errorf("server: egress limits: %w", err)
	}
	if _, err := relay.NewUDPDNSMessageResolver(c.dnsUpstream); err != nil {
		return fmt.Errorf("server: DNS upstream: %w", err)
	}
	return nil
}

func newProductionService(config productionConfig) (*server.ProductionFirstHopServer, []io.Closer, error) {
	config.egressLimits.ResolvedTTLSeconds = uint32(config.egressResolvedTTL)
	config.exitRateLimit.MaxFlowOpens = uint32(config.egressMaxFlowOpens)
	dnsResolver, err := relay.NewUDPDNSMessageResolver(config.dnsUpstream)
	if err != nil {
		return nil, nil, fmt.Errorf("server: DNS upstream: %w", err)
	}
	deployment, err := loadProductionDeployment(config)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := loadProductionTLSConfig(config.tlsCertificatePath, config.tlsPrivateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	classicalSigner, err := loadClassicalTranscriptSigner(config.classicalSignerPath)
	if err != nil {
		return nil, nil, err
	}
	pqSigner, err := loadPQTranscriptSigner(config.pqSignerPath)
	if err != nil {
		return nil, nil, err
	}
	hints, err := readRestrictedProductionFile(config.accessHintsPath)
	if err != nil {
		return nil, nil, err
	}
	defer zeroProductionBytes(hints)
	credentials, err := admission.DecodeAccessHintCredentialSet(hints)
	if err != nil {
		return nil, nil, fmt.Errorf("server: decode access hints: %w", err)
	}
	defer zeroAccessHintCredentials(credentials)
	hintResolver, err := handshake.NewStaticAccessHintResolver(credentials)
	if err != nil {
		return nil, nil, err
	}
	tokenVerificationKey, err := readProductionFile(config.tokenVerificationKeyPath)
	if err != nil {
		return nil, nil, err
	}
	admissionVerifier, err := handshake.NewBlindRSAAdmissionVerifier(tokenVerificationKey)
	if err != nil {
		return nil, nil, err
	}
	policy, err := handshake.NewFixedProxyPolicySelector(config.suite, config.policy, config.route, config.shape)
	if err != nil {
		return nil, nil, err
	}
	caches, err := openProductionCaches(config)
	if err != nil {
		return nil, nil, err
	}
	driver, err := handshake.NewRelayDriver(handshake.RelayDriverConfig{
		Deployment:        deployment,
		HintResolver:      hintResolver,
		HintSpentCache:    caches[0].(*admission.FileReplayCache),
		AdmissionVerifier: admissionVerifier,
		TokenSpentCache:   caches[1].(*admission.FileReplayCache),
		BootstrapCache:    caches[2].(*admission.FileReplayCache),
		ClassicalSigner:   classicalSigner,
		PQSigner:          pqSigner,
		PolicySelector:    policy,
		RequirePQ:         true,
		SessionLimits:     config.sessionLimits,
	})
	zeroProductionBytes(tokenVerificationKey)
	if err != nil {
		closeProductionCaches(caches)
		return nil, nil, err
	}
	coverOrigin, err := newProductionCoverOrigin(config.coverOriginURL)
	if err != nil {
		closeProductionCaches(caches)
		return nil, nil, err
	}
	service, err := server.NewProductionFirstHopServer(server.ProductionFirstHopOptions{
		Deployment:    deployment,
		Driver:        driver,
		ListenAddress: config.listenAddress,
		Authority:     config.authority,
		Path:          config.path,
		TLSConfig:     tlsConfig,
		CarrierStatus: http.StatusCreated,
		CarrierHeader: http.Header{"Content-Type": {"application/octet-stream"}},
		CoverOrigin:   coverOrigin,
		ProxySession: server.FirstHopProxySessionOptions{
			ExitPolicy:    relay.ExitPolicy{AllowPrivate: config.allowPrivateExit},
			RateLimit:     config.exitRateLimit,
			UDPConfirmTTL: uint32(config.udpConfirmTTL),
			Dialer:        &net.Dialer{},
			Resolver:      net.DefaultResolver,
			DNSResolver:   dnsResolver,
			Limits:        config.egressLimits,
		},
		MaxConcurrentSessions: config.maxConcurrentSessions,
	})
	if err != nil {
		closeProductionCaches(caches)
		return nil, nil, err
	}
	return service, caches, nil
}

func loadProductionDeployment(config productionConfig) (trust.VerifiedRelayDeployment, error) {
	descriptor, err := readProductionFile(config.descriptorPath)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, err
	}
	hash, err := readProductionFile(config.trustedDescriptorHashPath)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, err
	}
	template, err := readProductionFile(config.templatePath)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, err
	}
	authorityKey, err := readProductionFile(config.templateAuthorityKeyPath)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, err
	}
	return trust.VerifyCanonicalRelayDeployment(trust.CanonicalRelayDeploymentInput{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    hash,
		Template:                 template,
		TemplateAuthorityKey:     authorityKey,
		RequestClassID:           config.requestClassID,
		Suite:                    config.suite,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  uint64(time.Now().Unix()),
		MaxTemplateFutureSkew:    config.maxTemplateFutureSkew,
		RequirePQDescriptorProof: true,
	})
}

func loadProductionTLSConfig(certificatePath, privateKeyPath string) (*tls.Config, error) {
	certificatePEM, err := readProductionFile(certificatePath)
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := readRestrictedProductionFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	defer zeroProductionBytes(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("server: load TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}}, nil
}

func loadClassicalTranscriptSigner(path string) (handshake.TranscriptSigner, error) {
	encoded, err := readRestrictedProductionFile(path)
	if err != nil {
		return nil, err
	}
	defer zeroProductionBytes(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("server: classical signer key must contain one PEM block")
	}
	var key any
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("server: classical signer key PEM type is invalid")
	}
	if err != nil {
		return nil, fmt.Errorf("server: parse classical signer key: %w", err)
	}
	private, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("server: classical signer key must be ECDSA")
	}
	signer, err := handshake.NewECDSAP256TranscriptSigner(private)
	private.D.SetInt64(0)
	return signer, err
}

func loadPQTranscriptSigner(path string) (handshake.TranscriptSigner, error) {
	encoded, err := readRestrictedProductionFile(path)
	if err != nil {
		return nil, err
	}
	defer zeroProductionBytes(encoded)
	private := new(mldsa65.PrivateKey)
	if err := private.UnmarshalBinary(encoded); err != nil {
		return nil, fmt.Errorf("server: parse PQ signer key: %w", err)
	}
	return handshake.NewMLDSA65TranscriptSigner(private)
}

func openProductionCaches(config productionConfig) ([]io.Closer, error) {
	paths := []string{config.hintSpentCachePath, config.tokenSpentCachePath, config.bootstrapCachePath}
	if err := validateProductionCachePaths(paths); err != nil {
		return nil, err
	}
	caches := make([]io.Closer, 0, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		directory, err := openProductionCacheDirectory(filepath.Dir(clean))
		if err != nil {
			closeProductionCaches(caches)
			return nil, err
		}
		cache, err := admission.NewFileReplayCacheAt(directory, filepath.Base(clean))
		closeDirectoryErr := directory.Close()
		if err != nil {
			closeProductionCaches(caches)
			return nil, fmt.Errorf("server: open durable replay cache: %w", err)
		}
		if closeDirectoryErr != nil {
			_ = cache.Close()
			closeProductionCaches(caches)
			return nil, fmt.Errorf("server: close durable replay cache directory: %w", closeDirectoryErr)
		}
		caches = append(caches, cache)
	}
	return caches, nil
}

func validateProductionCachePaths(paths []string) error {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if clean == "." || clean == string(filepath.Separator) {
			return fmt.Errorf("server: durable replay cache path is invalid")
		}
		if _, exists := seen[clean]; exists {
			return fmt.Errorf("server: durable replay cache paths must be distinct")
		}
		seen[clean] = struct{}{}
		if err := validateProductionCacheDirectory(filepath.Dir(clean)); err != nil {
			return err
		}
		info, err := os.Lstat(clean)
		if err == nil {
			if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
				return fmt.Errorf("server: durable replay cache file is unsafe")
			}
			if err := validateProductionFileOwner(info); err != nil {
				return fmt.Errorf("server: durable replay cache file: %w", err)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("server: inspect durable replay cache: %w", err)
		}
	}
	return nil
}

func validateProductionCacheDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("server: inspect durable replay cache directory: %w", err)
	}
	return validateProductionCacheDirectoryInfo(info)
}

func validateProductionCacheDirectoryInfo(info os.FileInfo) error {
	if info == nil || !info.IsDir() {
		return fmt.Errorf("server: durable replay cache directory is invalid")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("server: durable replay cache directory permissions are too broad")
	}
	if err := validateProductionFileOwner(info); err != nil {
		return fmt.Errorf("server: durable replay cache directory: %w", err)
	}
	return nil
}

func openProductionCacheDirectory(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("server: inspect durable replay cache directory: %w", err)
	}
	if err := validateProductionCacheDirectoryInfo(info); err != nil {
		return nil, err
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("server: open durable replay cache directory: %w", err)
	}
	openedInfo, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("server: inspect opened durable replay cache directory: %w", err)
	}
	if !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		_ = directory.Close()
		return nil, fmt.Errorf("server: durable replay cache directory changed while opening")
	}
	if err := validateProductionCacheDirectoryInfo(openedInfo); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func closeProductionCaches(caches []io.Closer) {
	for index := len(caches) - 1; index >= 0; index-- {
		_ = caches[index].Close()
	}
}

func newProductionCoverOrigin(raw string) (server.ProductionCoverOrigin, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("server: parse cover origin URL: %w", err)
	}
	return server.NewProductionReverseProxyCoverOrigin(parsed)
}

func readProductionFile(path string) ([]byte, error) {
	return readProductionFileWithMode(path, false)
}

func readRestrictedProductionFile(path string) ([]byte, error) {
	return readProductionFileWithMode(path, true)
}

func readProductionFileWithMode(path string, restricted bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("server: inspect configuration file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("server: configuration file must be regular")
	}
	if restricted {
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("server: private configuration file permissions are too broad")
		}
		if err := validateProductionFileOwner(info); err != nil {
			return nil, fmt.Errorf("server: private configuration file: %w", err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("server: open configuration file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("server: inspect opened configuration file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("server: configuration file changed while opening")
	}
	if restricted {
		if runtime.GOOS != "windows" && openedInfo.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("server: private configuration file permissions are too broad")
		}
		if err := validateProductionFileOwner(openedInfo); err != nil {
			return nil, fmt.Errorf("server: private configuration file: %w", err)
		}
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumProductionConfigurationFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("server: read configuration file: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumProductionConfigurationFileBytes {
		return nil, fmt.Errorf("server: configuration file length is invalid")
	}
	return encoded, nil
}

func serveProduction(ctx context.Context, service *server.ProductionFirstHopServer, listener net.Listener) error {
	if ctx == nil {
		return fmt.Errorf("server: production service context is required")
	}
	if service == nil || listener == nil {
		return fmt.Errorf("server: production service and listener are required")
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- service.Serve(listener) }()
	select {
	case err := <-serveResult:
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), productionShutdownTimeout)
		defer cancel()
		shutdownErr := service.Shutdown(shutdownContext)
		serveErr := <-serveResult
		return errors.Join(shutdownErr, serveErr)
	}
}

func zeroProductionBytes(bytes []byte) {
	for index := range bytes {
		bytes[index] = 0
	}
}

func zeroAccessHintCredentials(credentials []admission.AccessHintCredential) {
	for index := range credentials {
		zeroProductionBytes(credentials[index].HintIssuerID)
		zeroProductionBytes(credentials[index].RelayBucketID)
		zeroProductionBytes(credentials[index].HintSelector)
		zeroProductionBytes(credentials[index].HintSecret)
	}
}
