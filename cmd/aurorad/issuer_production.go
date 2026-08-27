package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"
)

const (
	issuerProductionReadHeaderTimeout         = 5 * time.Second
	issuerProductionReadTimeout               = 15 * time.Second
	issuerProductionWriteTimeout              = 15 * time.Second
	issuerProductionIdleTimeout               = 2 * time.Minute
	issuerProductionHTTP2ReadIdleTimeout      = 30 * time.Second
	issuerProductionHTTP2PingTimeout          = 15 * time.Second
	issuerProductionMaxHeaderBytes            = 8 << 10
	issuerProductionMaximumConnections        = 128
	issuerProductionHTTP2MaxConcurrentStreams = 16
	issuerProductionDefaultConcurrentIssues   = 16
)

type issuerProductionConfig struct {
	listenAddress            string
	tlsCertificatePath       string
	tlsPrivateKeyPath        string
	gatewayClientCAPath      string
	issuerMetadataPath       string
	metadataAuthorityKeyPath string
	blindRSAKeyPath          string
	spentTokenCachePath      string
	relayBucketID            []byte
	originInfoPolicyID       uint64
	maxConcurrentIssues      int
}

type productionIssuerService struct {
	service   *issuerd.Service
	tlsConfig *tls.Config
	cache     io.Closer
	maxIssues int
}

func (s *productionIssuerService) Close() error {
	if s == nil || s.cache == nil {
		return nil
	}
	return s.cache.Close()
}

func runIssuer(args []string, stdout, stderr io.Writer) (exitCode int) {
	config, err := parseProductionIssuerConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "issuer: production service requires a Linux host")
		return 2
	}
	issuerRuntime, err := newProductionIssuerService(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return runProductionIssuer(issuerRuntime, config.listenAddress, stdout, stderr)
}

func runProductionIssuer(issuerRuntime *productionIssuerService, listenAddress string, stdout, stderr io.Writer) (exitCode int) {
	defer func() {
		if err := closeProductionIssuerRuntime(issuerRuntime, stderr); err != nil {
			exitCode = 1
		}
	}()
	listener, err := productionListen(listenAddress)
	if err != nil {
		fmt.Fprintf(stderr, "issuer: listen: %v\n", err)
		return 1
	}
	defer listener.Close()
	ctx, stop := productionSignalContext()
	defer stop()
	fmt.Fprintln(stdout, "aurorad private issuer backend started; public cover gateway admission remains external and incomplete")
	if err := serveProductionIssuer(ctx, issuerRuntime, listener); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseProductionIssuerConfig(args []string, stderr io.Writer) (issuerProductionConfig, error) {
	configPath, hasConfigFile, err := productionArgumentsFilePath("issuer", args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return issuerProductionConfig{}, err
	}
	if hasConfigFile {
		args, err = readProductionArgumentsFile("issuer", configPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return issuerProductionConfig{}, err
		}
	}
	return parseProductionIssuerConfigArguments(args, stderr)
}

func parseProductionIssuerConfigArguments(args []string, stderr io.Writer) (issuerProductionConfig, error) {
	flags := flag.NewFlagSet("aurorad issuer", flag.ContinueOnError)
	flags.SetOutput(stderr)
	setProductionArgumentsFileUsage(flags)
	config := issuerProductionConfig{}
	var relayBucketID string
	flags.StringVar(&config.listenAddress, "listen", "", "private loopback gateway-backend listen address")
	flags.StringVar(&config.tlsCertificatePath, "tls-cert", "", "TLS certificate path")
	flags.StringVar(&config.tlsPrivateKeyPath, "tls-key", "", "TLS private key path")
	flags.StringVar(&config.gatewayClientCAPath, "gateway-client-ca", "", "dedicated gateway client CA certificate path")
	flags.StringVar(&config.issuerMetadataPath, "issuer-metadata", "", "signed issuer metadata path")
	flags.StringVar(&config.metadataAuthorityKeyPath, "metadata-authority-key", "", "issuer metadata authority key path")
	flags.StringVar(&config.blindRSAKeyPath, "blind-rsa-key", "", "Blind RSA private key path")
	flags.StringVar(&config.spentTokenCachePath, "spent-token-cache", "", "durable spent-token cache path")
	flags.StringVar(&relayBucketID, "relay-bucket-id", "", "16-byte relay bucket ID encoded as hexadecimal")
	flags.Uint64Var(&config.originInfoPolicyID, "origin-info-policy", 0, "authorized origin-info policy ID")
	flags.IntVar(&config.maxConcurrentIssues, "max-concurrent-issues", issuerProductionDefaultConcurrentIssues, "maximum concurrent Blind RSA signing operations")
	if err := rejectDuplicateProductionFlags("issuer", flags, args); err != nil {
		fmt.Fprintln(stderr, err)
		return issuerProductionConfig{}, err
	}
	if err := flags.Parse(args); err != nil {
		return issuerProductionConfig{}, err
	}
	if flags.NArg() != 0 {
		return issuerProductionConfig{}, fmt.Errorf("issuer: unexpected production command arguments")
	}
	if err := config.validateRequiredFields(); err != nil {
		fmt.Fprintln(stderr, err)
		return issuerProductionConfig{}, err
	}
	decodedRelayBucketID, err := hex.DecodeString(relayBucketID)
	if err != nil || len(decodedRelayBucketID) != 16 {
		relayBucketErr := fmt.Errorf("issuer: relay bucket ID must be 16 hexadecimal bytes")
		fmt.Fprintln(stderr, relayBucketErr)
		return issuerProductionConfig{}, relayBucketErr
	}
	config.relayBucketID = decodedRelayBucketID
	if err := config.validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return issuerProductionConfig{}, err
	}
	return config, nil
}

func (c issuerProductionConfig) validate() error {
	if err := c.validateRequiredFields(); err != nil {
		return err
	}
	if err := validateProductionIssuerListenAddress(c.listenAddress); err != nil {
		return err
	}
	if len(c.relayBucketID) != 16 {
		return fmt.Errorf("issuer: relay bucket ID must be 16 bytes")
	}
	if c.originInfoPolicyID == 0 {
		return fmt.Errorf("issuer: origin-info policy is required")
	}
	if c.maxConcurrentIssues <= 0 || c.maxConcurrentIssues > issuerd.MaximumProductionBlindRSABackendConcurrency {
		return fmt.Errorf("issuer: maximum concurrent issues must be between 1 and %d", issuerd.MaximumProductionBlindRSABackendConcurrency)
	}
	return nil
}

func validateProductionIssuerListenAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || portText == "" {
		return fmt.Errorf("issuer: listen address is invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || !isDecimalIssuerPort(portText) {
		return fmt.Errorf("issuer: listen port is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("issuer: private backend listen address must use a literal loopback IP")
	}
	return nil
}

func isDecimalIssuerPort(port string) bool {
	for _, value := range port {
		if value < '0' || value > '9' {
			return false
		}
	}
	return port != ""
}

func (c issuerProductionConfig) validateRequiredFields() error {
	for _, field := range []struct{ name, value string }{
		{"listen address", c.listenAddress},
		{"TLS certificate", c.tlsCertificatePath},
		{"TLS private key", c.tlsPrivateKeyPath},
		{"gateway client CA", c.gatewayClientCAPath},
		{"issuer metadata", c.issuerMetadataPath},
		{"metadata authority key", c.metadataAuthorityKeyPath},
		{"Blind RSA key", c.blindRSAKeyPath},
		{"spent-token cache", c.spentTokenCachePath},
	} {
		if strings.TrimSpace(field.value) == "" || strings.TrimSpace(field.value) != field.value {
			return fmt.Errorf("issuer: %s is required", field.name)
		}
	}
	return nil
}

func newProductionIssuerService(config issuerProductionConfig) (*productionIssuerService, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	tlsConfig, err := loadProductionTLSConfig(config.tlsCertificatePath, config.tlsPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	clientCAs, err := loadProductionGatewayClientCAs(config.gatewayClientCAPath)
	if err != nil {
		return nil, err
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{"h2"}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = clientCAs
	tlsConfig.SessionTicketsDisabled = true
	metadata, err := loadProductionIssuerMetadata(config.issuerMetadataPath)
	if err != nil {
		return nil, err
	}
	authorityKey, err := loadProductionIssuerAuthorityKey(config.metadataAuthorityKeyPath)
	if err != nil {
		return nil, err
	}
	privateKey, err := loadProductionBlindRSAKey(config.blindRSAKeyPath)
	if err != nil {
		return nil, err
	}
	defer zeroRSAPrivateKey(privateKey)
	nowUnix := time.Now().Unix()
	if nowUnix <= 0 {
		return nil, fmt.Errorf("issuer: current time is invalid")
	}
	cache, err := openProductionIssuerSpentTokenCache(config.spentTokenCachePath, uint64(nowUnix))
	if err != nil {
		return nil, err
	}
	service, err := issuerd.NewProductionBlindRSAService(issuerd.ProductionBlindRSAServiceOptions{
		Metadata:           metadata,
		AuthorityKeys:      []protocol.AuthorityKeyRecord{authorityKey},
		BlindRSAKey:        privateKey,
		SpentTokenCache:    cache,
		RelayBucketID:      config.relayBucketID,
		OriginInfoPolicyID: config.originInfoPolicyID,
		NowUnix: func() uint64 {
			nowUnix := time.Now().Unix()
			if nowUnix <= 0 {
				return 0
			}
			return uint64(nowUnix)
		},
	})
	if err != nil {
		return nil, errors.Join(err, cache.Close())
	}
	return &productionIssuerService{
		service:   service,
		tlsConfig: tlsConfig,
		cache:     cache,
		maxIssues: config.maxConcurrentIssues,
	}, nil
}

func loadProductionGatewayClientCAs(path string) (*x509.CertPool, error) {
	encoded, err := readProductionFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	remaining := encoded
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("issuer: gateway client CA must contain only PEM certificates")
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, fmt.Errorf("issuer: gateway client CA must contain only PEM certificates")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("issuer: gateway client CA PEM block is invalid")
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("issuer: parse gateway client CA: %w", parseErr)
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("issuer: gateway client CA certificate must be a certificate-signing CA")
		}
		pool.AddCert(certificate)
		count++
		remaining = rest
	}
	if count == 0 {
		return nil, fmt.Errorf("issuer: gateway client CA certificate is required")
	}
	return pool, nil
}

func loadProductionIssuerMetadata(path string) (protocol.IssuerMetadata, error) {
	encoded, err := readProductionFile(path)
	if err != nil {
		return protocol.IssuerMetadata{}, err
	}
	reader := wire.NewReader(encoded)
	metadata := protocol.DecodeIssuerMetadata(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.IssuerMetadata{}, fmt.Errorf("issuer: decode issuer metadata failed")
	}
	return metadata, nil
}

func loadProductionIssuerAuthorityKey(path string) (protocol.AuthorityKeyRecord, error) {
	encoded, err := readProductionFile(path)
	if err != nil {
		return protocol.AuthorityKeyRecord{}, err
	}
	reader := wire.NewReader(encoded)
	authorityKey := protocol.DecodeAuthorityKeyRecord(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.AuthorityKeyRecord{}, fmt.Errorf("issuer: decode metadata authority key failed")
	}
	return authorityKey, nil
}

func loadProductionBlindRSAKey(path string) (*rsa.PrivateKey, error) {
	encoded, err := readRestrictedProductionFile(path)
	if err != nil {
		return nil, err
	}
	defer zeroProductionBytes(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("issuer: Blind RSA key must contain one PEM block")
	}
	defer zeroPrivatePEMBlock(block)
	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("issuer: parse Blind RSA key: %w", parseErr)
		}
		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("issuer: Blind RSA key must be RSA")
		}
	default:
		return nil, fmt.Errorf("issuer: Blind RSA key PEM type is invalid")
	}
	if err != nil {
		return nil, fmt.Errorf("issuer: parse Blind RSA key: %w", err)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("issuer: validate Blind RSA key: %w", err)
	}
	return privateKey, nil
}

func openProductionIssuerSpentTokenCache(path string, nowUnix uint64) (*admission.RetentionFileReplayCache, error) {
	if err := validateProductionCachePaths([]string{path}); err != nil {
		return nil, err
	}
	clean := filepath.Clean(path)
	directory, err := openProductionCacheDirectory(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	cache, err := admission.NewRetentionFileReplayCacheAt(directory, filepath.Base(clean), nowUnix)
	if err != nil {
		return nil, fmt.Errorf("issuer: open durable spent-token cache: %w", errors.Join(err, directory.Close()))
	}
	return cache, nil
}

func closeProductionIssuerRuntime(runtime io.Closer, stderr io.Writer) error {
	if runtime == nil {
		return nil
	}
	err := runtime.Close()
	if err != nil {
		fmt.Fprintf(stderr, "issuer: close durable spent-token cache: %v\n", err)
	}
	return err
}

func serveProductionIssuer(ctx context.Context, runtime *productionIssuerService, listener net.Listener) error {
	if ctx == nil {
		return fmt.Errorf("issuer: production service context is required")
	}
	httpServer, err := newProductionIssuerHTTPServer(runtime)
	if err != nil {
		return err
	}
	if listener == nil {
		return fmt.Errorf("issuer: production service and listener are required")
	}
	return serveProductionIssuerHTTPServer(ctx, httpServer, listener)
}

func serveProductionIssuerHTTPServer(ctx context.Context, httpServer *http.Server, listener net.Listener) error {
	if ctx == nil || httpServer == nil || listener == nil {
		return fmt.Errorf("issuer: production HTTP server, context, and listener are required")
	}
	if ctx.Err() != nil {
		return shutdownProductionIssuerHTTPServer(httpServer)
	}
	limitedListener := netutil.LimitListener(listener, issuerProductionMaximumConnections)
	serveResult := make(chan error, 1)
	go func() { serveResult <- httpServer.ServeTLS(limitedListener, "", "") }()
	select {
	case serveErr := <-serveResult:
		shutdownErr := shutdownProductionIssuerHTTPServer(httpServer)
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(serveErr, shutdownErr)
	case <-ctx.Done():
		shutdownErr := shutdownProductionIssuerHTTPServer(httpServer)
		serveErr := <-serveResult
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	}
}

func shutdownProductionIssuerHTTPServer(httpServer *http.Server) error {
	if httpServer == nil {
		return fmt.Errorf("issuer: production HTTP server is required for shutdown")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), productionShutdownTimeout)
	defer cancel()
	shutdownErr := httpServer.Shutdown(shutdownContext)
	if shutdownErr == nil {
		return nil
	}
	closeErr := httpServer.Close()
	if errors.Is(closeErr, http.ErrServerClosed) {
		closeErr = nil
	}
	return errors.Join(shutdownErr, closeErr)
}

func newProductionIssuerHTTPServer(runtime *productionIssuerService) (*http.Server, error) {
	if runtime == nil || runtime.service == nil || runtime.tlsConfig == nil || runtime.maxIssues <= 0 {
		return nil, fmt.Errorf("issuer: production service is required")
	}
	handler, err := issuerd.NewProductionBlindRSABackendHandler(runtime.service, issuerd.ProductionBlindRSABackendOptions{
		MaxConcurrentIssues: runtime.maxIssues,
	})
	if err != nil {
		return nil, fmt.Errorf("issuer: production backend handler: %w", err)
	}
	tlsConfig, err := ownedProductionIssuerTLSConfig(runtime.tlsConfig)
	if err != nil {
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	httpServer := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: issuerProductionReadHeaderTimeout,
		ReadTimeout:       issuerProductionReadTimeout,
		WriteTimeout:      issuerProductionWriteTimeout,
		IdleTimeout:       issuerProductionIdleTimeout,
		MaxHeaderBytes:    issuerProductionMaxHeaderBytes,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: issuerProductionHTTP2MaxConcurrentStreams,
			SendPingTimeout:      issuerProductionHTTP2ReadIdleTimeout,
			PingTimeout:          issuerProductionHTTP2PingTimeout,
			WriteByteTimeout:     issuerProductionWriteTimeout,
		},
		Protocols: protocols,
	}
	httpServer.ErrorLog = log.New(io.Discard, "", 0)
	if err := http2.ConfigureServer(httpServer, &http2.Server{
		MaxConcurrentStreams: issuerProductionHTTP2MaxConcurrentStreams,
		IdleTimeout:          issuerProductionIdleTimeout,
		ReadIdleTimeout:      issuerProductionHTTP2ReadIdleTimeout,
		PingTimeout:          issuerProductionHTTP2PingTimeout,
	}); err != nil {
		return nil, fmt.Errorf("issuer: configure HTTP/2 server: %w", err)
	}
	httpServer.TLSConfig.NextProtos = []string{"h2"}
	return httpServer, nil
}

func ownedProductionIssuerTLSConfig(source *tls.Config) (*tls.Config, error) {
	if source == nil || len(source.Certificates) == 0 {
		return nil, fmt.Errorf("issuer: backend TLS certificate is required")
	}
	if source.GetCertificate != nil || source.GetConfigForClient != nil || source.GetClientCertificate != nil || source.GetEncryptedClientHelloKeys != nil {
		return nil, fmt.Errorf("issuer: backend dynamic TLS configuration is forbidden")
	}
	if source.VerifyPeerCertificate != nil || source.VerifyConnection != nil {
		return nil, fmt.Errorf("issuer: backend dynamic TLS verification is forbidden")
	}
	if source.Rand != nil || source.Time != nil || source.KeyLogWriter != nil {
		return nil, fmt.Errorf("issuer: backend custom TLS randomness, time, or key logging is forbidden")
	}
	//lint:ignore SA1019 Reject the deprecated map so it cannot bypass owned certificate selection.
	if source.NameToCertificate != nil {
		return nil, fmt.Errorf("issuer: backend deprecated TLS certificate map is forbidden")
	}
	if source.WrapSession != nil || source.UnwrapSession != nil || source.ClientSessionCache != nil {
		return nil, fmt.Errorf("issuer: backend TLS session hooks are forbidden")
	}
	if source.MinVersion != tls.VersionTLS13 || source.MaxVersion != tls.VersionTLS13 {
		return nil, fmt.Errorf("issuer: backend TLS version must be exactly TLS 1.3")
	}
	if len(source.NextProtos) != 1 || source.NextProtos[0] != "h2" {
		return nil, fmt.Errorf("issuer: backend TLS ALPN must be h2 only")
	}
	if !source.SessionTicketsDisabled {
		return nil, fmt.Errorf("issuer: backend TLS session tickets must be disabled")
	}
	if source.ClientAuth != tls.RequireAndVerifyClientCert || source.ClientCAs == nil || source.ClientCAs.Equal(x509.NewCertPool()) {
		return nil, fmt.Errorf("issuer: backend requires a dedicated gateway client CA")
	}
	certificates := make([]tls.Certificate, len(source.Certificates))
	for i, certificate := range source.Certificates {
		if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return nil, fmt.Errorf("issuer: backend TLS certificate chain or private key is missing")
		}
		certificates[i] = tls.Certificate{
			Certificate: cloneProductionIssuerByteSlices(certificate.Certificate),
		}
		leaf, err := x509.ParseCertificate(certificates[i].Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("issuer: parse backend TLS leaf certificate: %w", err)
		}
		encodedPrivateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("issuer: clone backend TLS private key: %w", err)
		}
		privateKey, err := x509.ParsePKCS8PrivateKey(encodedPrivateKey)
		zeroProductionBytes(encodedPrivateKey[:cap(encodedPrivateKey)])
		if err != nil {
			return nil, fmt.Errorf("issuer: clone backend TLS private key: %w", err)
		}
		signer, ok := privateKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("issuer: backend TLS private key cannot sign")
		}
		certificatePublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("issuer: encode backend TLS certificate public key: %w", err)
		}
		privatePublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return nil, fmt.Errorf("issuer: encode backend TLS private key public component: %w", err)
		}
		if !bytes.Equal(certificatePublicKey, privatePublicKey) {
			return nil, fmt.Errorf("issuer: backend TLS private key does not match certificate")
		}
		certificates[i].PrivateKey = privateKey
		certificates[i].Leaf = leaf
	}
	return &tls.Config{
		Certificates:           certificates,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{"h2"},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              source.ClientCAs.Clone(),
		SessionTicketsDisabled: true,
	}, nil
}

func cloneProductionIssuerByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for i, value := range values {
		cloned[i] = append([]byte(nil), value...)
	}
	return cloned
}

func zeroRSAPrivateKey(privateKey *rsa.PrivateKey) {
	if privateKey == nil {
		return
	}
	zeroPrivateBigInt(privateKey.D)
	for _, prime := range privateKey.Primes {
		zeroPrivateBigInt(prime)
	}
	zeroPrivateBigInt(privateKey.Precomputed.Dp)
	zeroPrivateBigInt(privateKey.Precomputed.Dq)
	zeroPrivateBigInt(privateKey.Precomputed.Qinv)
	//lint:ignore SA1019 Clear legacy retained CRT limbs if a parser populated them.
	for _, value := range privateKey.Precomputed.CRTValues {
		zeroPrivateBigInt(value.Exp)
		zeroPrivateBigInt(value.Coeff)
		zeroPrivateBigInt(value.R)
	}
	*privateKey = rsa.PrivateKey{}
}

var _ io.Closer = (*productionIssuerService)(nil)
