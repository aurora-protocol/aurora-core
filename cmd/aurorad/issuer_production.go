package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
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
)

type issuerProductionConfig struct {
	listenAddress            string
	tlsCertificatePath       string
	tlsPrivateKeyPath        string
	issuerMetadataPath       string
	metadataAuthorityKeyPath string
	blindRSAKeyPath          string
	spentTokenCachePath      string
	relayBucketID            []byte
	originInfoPolicyID       uint64
}

type productionIssuerService struct {
	service   *issuerd.Service
	tlsConfig *tls.Config
	cache     *admission.RetentionFileReplayCache
}

func (s *productionIssuerService) Close() error {
	if s == nil || s.cache == nil {
		return nil
	}
	return s.cache.Close()
}

func runIssuer(args []string, stdout, stderr io.Writer) int {
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
	defer issuerRuntime.Close()
	listener, err := productionListen(config.listenAddress)
	if err != nil {
		fmt.Fprintf(stderr, "issuer: listen: %v\n", err)
		return 1
	}
	defer listener.Close()
	ctx, stop := productionSignalContext()
	defer stop()
	fmt.Fprintln(stdout, "aurorad production issuer started")
	if err := serveProductionIssuer(ctx, issuerRuntime, listener); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func parseProductionIssuerConfig(args []string, stderr io.Writer) (issuerProductionConfig, error) {
	flags := flag.NewFlagSet("aurorad issuer", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := issuerProductionConfig{}
	var relayBucketID string
	flags.StringVar(&config.listenAddress, "listen", "", "public TLS listen address")
	flags.StringVar(&config.tlsCertificatePath, "tls-cert", "", "TLS certificate path")
	flags.StringVar(&config.tlsPrivateKeyPath, "tls-key", "", "TLS private key path")
	flags.StringVar(&config.issuerMetadataPath, "issuer-metadata", "", "signed issuer metadata path")
	flags.StringVar(&config.metadataAuthorityKeyPath, "metadata-authority-key", "", "issuer metadata authority key path")
	flags.StringVar(&config.blindRSAKeyPath, "blind-rsa-key", "", "Blind RSA private key path")
	flags.StringVar(&config.spentTokenCachePath, "spent-token-cache", "", "durable spent-token cache path")
	flags.StringVar(&relayBucketID, "relay-bucket-id", "", "16-byte relay bucket ID encoded as hexadecimal")
	flags.Uint64Var(&config.originInfoPolicyID, "origin-info-policy", 0, "authorized origin-info policy ID")
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
	if _, _, err := net.SplitHostPort(c.listenAddress); err != nil {
		return fmt.Errorf("issuer: listen address is invalid: %w", err)
	}
	if len(c.relayBucketID) != 16 {
		return fmt.Errorf("issuer: relay bucket ID must be 16 bytes")
	}
	if c.originInfoPolicyID == 0 {
		return fmt.Errorf("issuer: origin-info policy is required")
	}
	return nil
}

func (c issuerProductionConfig) validateRequiredFields() error {
	for _, field := range []struct{ name, value string }{
		{"listen address", c.listenAddress},
		{"TLS certificate", c.tlsCertificatePath},
		{"TLS private key", c.tlsPrivateKeyPath},
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
		_ = cache.Close()
		return nil, err
	}
	tlsConfig, err := loadProductionTLSConfig(config.tlsCertificatePath, config.tlsPrivateKeyPath)
	if err != nil {
		_ = cache.Close()
		return nil, err
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	return &productionIssuerService{service: service, tlsConfig: tlsConfig, cache: cache}, nil
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
		_ = directory.Close()
		return nil, fmt.Errorf("issuer: open durable spent-token cache: %w", err)
	}
	return cache, nil
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
	limitedListener := netutil.LimitListener(listener, issuerProductionMaximumConnections)
	serveResult := make(chan error, 1)
	go func() { serveResult <- httpServer.ServeTLS(limitedListener, "", "") }()
	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), productionShutdownTimeout)
		defer cancel()
		shutdownErr := httpServer.Shutdown(shutdownContext)
		serveErr := <-serveResult
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	}
}

func newProductionIssuerHTTPServer(runtime *productionIssuerService) (*http.Server, error) {
	if runtime == nil || runtime.service == nil || runtime.tlsConfig == nil {
		return nil, fmt.Errorf("issuer: production service is required")
	}
	httpServer := &http.Server{
		Handler:           issuerd.NewHTTPHandler(runtime.service),
		TLSConfig:         runtime.tlsConfig,
		ReadHeaderTimeout: issuerProductionReadHeaderTimeout,
		ReadTimeout:       issuerProductionReadTimeout,
		WriteTimeout:      issuerProductionWriteTimeout,
		IdleTimeout:       issuerProductionIdleTimeout,
		MaxHeaderBytes:    issuerProductionMaxHeaderBytes,
	}
	if err := http2.ConfigureServer(httpServer, &http2.Server{
		MaxConcurrentStreams: issuerProductionHTTP2MaxConcurrentStreams,
		IdleTimeout:          issuerProductionIdleTimeout,
		ReadIdleTimeout:      issuerProductionHTTP2ReadIdleTimeout,
		PingTimeout:          issuerProductionHTTP2PingTimeout,
	}); err != nil {
		return nil, fmt.Errorf("issuer: configure HTTP/2 server: %w", err)
	}
	return httpServer, nil
}

func zeroRSAPrivateKey(privateKey *rsa.PrivateKey) {
	if privateKey != nil {
		*privateKey = rsa.PrivateKey{}
	}
}

var _ io.Closer = (*productionIssuerService)(nil)
