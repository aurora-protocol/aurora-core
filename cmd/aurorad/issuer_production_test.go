package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestNewProductionIssuerServiceLoadsSignedBlindRSAState(t *testing.T) {
	config := newProductionIssuerCommandFixture(t)
	runtime, err := newProductionIssuerService(config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if runtime.tlsConfig.MinVersion != tls.VersionTLS13 || runtime.tlsConfig.MaxVersion != tls.VersionTLS13 || runtime.tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || runtime.tlsConfig.ClientCAs == nil || !runtime.tlsConfig.SessionTicketsDisabled {
		t.Fatalf("issuer backend TLS policy is incomplete: %+v", runtime.tlsConfig)
	}

	handler, err := issuerd.NewProductionBlindRSABackendHandler(runtime.service, issuerd.ProductionBlindRSABackendOptions{MaxConcurrentIssues: runtime.maxIssues})
	if err != nil {
		t.Fatal(err)
	}
	metadata := httptest.NewRecorder()
	handler.ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "/issuer-metadata", nil))
	if metadata.Code != http.StatusServiceUnavailable || metadata.Body.Len() != 0 {
		t.Fatalf("private issuer backend exposed metadata: status=%d body=%q", metadata.Code, metadata.Body.String())
	}
	issue := httptest.NewRecorder()
	handler.ServeHTTP(issue, httptest.NewRequest(http.MethodPost, "/blind-rsa/issue", nil))
	if issue.Code != http.StatusServiceUnavailable || issue.Body.Len() != 0 {
		t.Fatalf("private issuer backend exposed JSON issue route: status=%d body=%q", issue.Code, issue.Body.String())
	}
	if _, err := runtime.service.IssueBlindRSA2048(issuerd.IssueBlindRSA2048Request{
		TokenNonce:            issuerCommandBytes(0x91, 32),
		RedemptionContextHash: issuerCommandBytes(0x92, 48),
		ExpiryUnix:            uint64(time.Now().Unix()) + 60,
	}); err != nil {
		t.Fatalf("loaded production issuer did not issue: %v", err)
	}
}

func TestZeroRSAPrivateKeyClearsPrivateMaterial(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private.Precompute()
	privateExponent := private.D
	prime := private.Primes[0]
	secondPrime := private.Primes[1]
	precomputedExponent := private.Precomputed.Dp
	secondPrecomputedExponent := private.Precomputed.Dq
	precomputedInverse := private.Precomputed.Qinv
	if privateExponent == nil || prime == nil || secondPrime == nil || precomputedExponent == nil || secondPrecomputedExponent == nil || precomputedInverse == nil {
		t.Fatal("generated RSA private key is unexpectedly incomplete")
	}
	zeroRSAPrivateKey(private)
	if private.D != nil || len(private.Primes) != 0 {
		t.Fatal("RSA private key struct retained material after zeroization")
	}
	for name, value := range map[string]*big.Int{
		"private exponent":            privateExponent,
		"first prime":                 prime,
		"second prime":                secondPrime,
		"precomputed exponent":        precomputedExponent,
		"second precomputed exponent": secondPrecomputedExponent,
		"precomputed inverse":         precomputedInverse,
	} {
		if value.Sign() != 0 {
			t.Fatalf("RSA %s limbs retained material after zeroization", name)
		}
	}
}

func TestNewProductionIssuerHTTPServerSetsResourceBounds(t *testing.T) {
	config := newProductionIssuerCommandFixture(t)
	runtime, err := newProductionIssuerService(config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	httpServer, err := newProductionIssuerHTTPServer(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if httpServer.ReadHeaderTimeout <= 0 || httpServer.ReadTimeout <= 0 || httpServer.WriteTimeout <= 0 || httpServer.IdleTimeout <= 0 || httpServer.MaxHeaderBytes <= 0 || httpServer.ErrorLog == nil || httpServer.ErrorLog.Writer() != io.Discard {
		t.Fatalf("issuer HTTP server resource bounds are incomplete: %+v", httpServer)
	}
	if httpServer.Protocols == nil || !httpServer.Protocols.HTTP2() || httpServer.Protocols.HTTP1() {
		t.Fatalf("issuer backend protocols are not HTTP/2-only: %+v", httpServer.Protocols)
	}
	if httpServer.HTTP2 == nil || httpServer.HTTP2.MaxConcurrentStreams == 0 {
		t.Fatalf("issuer HTTP/2 resource bounds are incomplete: %+v", httpServer.HTTP2)
	}
}

func TestNewProductionIssuerHTTPServerOwnsStrictGatewayTLS(t *testing.T) {
	runtime, err := newProductionIssuerService(newProductionIssuerCommandFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	sourceCertificate := runtime.tlsConfig.Certificates[0].Certificate[0]
	sourcePrivateKey := runtime.tlsConfig.Certificates[0].PrivateKey
	httpServer, err := newProductionIssuerHTTPServer(runtime)
	if err != nil {
		t.Fatal(err)
	}
	owned := httpServer.TLSConfig
	if owned == runtime.tlsConfig || owned.MinVersion != tls.VersionTLS13 || owned.MaxVersion != tls.VersionTLS13 || len(owned.NextProtos) != 1 || owned.NextProtos[0] != "h2" || owned.ClientAuth != tls.RequireAndVerifyClientCert || !owned.SessionTicketsDisabled {
		t.Fatalf("owned issuer backend TLS policy is incomplete: %+v", owned)
	}
	if owned.ClientCAs == runtime.tlsConfig.ClientCAs || !owned.ClientCAs.Equal(runtime.tlsConfig.ClientCAs) {
		t.Fatal("issuer backend did not own an independent gateway CA pool")
	}
	if &owned.Certificates[0].Certificate[0][0] == &sourceCertificate[0] {
		t.Fatal("issuer backend retained the caller's certificate byte storage")
	}
	if reflect.ValueOf(owned.Certificates[0].PrivateKey).Kind() == reflect.Pointer && reflect.ValueOf(sourcePrivateKey).Kind() == reflect.Pointer && reflect.ValueOf(owned.Certificates[0].PrivateKey).Pointer() == reflect.ValueOf(sourcePrivateKey).Pointer() {
		t.Fatal("issuer backend retained the caller's TLS private key object")
	}
	firstOwnedCertificateByte := owned.Certificates[0].Certificate[0][0]
	runtime.tlsConfig.NextProtos[0] = "http/1.1"
	runtime.tlsConfig.Certificates[0].Certificate[0][0] ^= 0xff
	if owned.NextProtos[0] != "h2" || owned.Certificates[0].Certificate[0][0] != firstOwnedCertificateByte {
		t.Fatal("issuer backend TLS config changed after caller mutation")
	}
}

func TestOwnedProductionIssuerTLSConfigRejectsPolicyDrift(t *testing.T) {
	runtime, err := newProductionIssuerService(newProductionIssuerCommandFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, test := range []struct {
		name   string
		mutate func(*tls.Config)
	}{
		{name: "TLS 1.2", mutate: func(config *tls.Config) { config.MinVersion = tls.VersionTLS12 }},
		{name: "extra ALPN", mutate: func(config *tls.Config) { config.NextProtos = []string{"h2", "http/1.1"} }},
		{name: "tickets", mutate: func(config *tls.Config) { config.SessionTicketsDisabled = false }},
		{name: "optional client cert", mutate: func(config *tls.Config) { config.ClientAuth = tls.VerifyClientCertIfGiven }},
		{name: "missing client CA", mutate: func(config *tls.Config) { config.ClientCAs = nil }},
		{name: "empty client CA", mutate: func(config *tls.Config) { config.ClientCAs = x509.NewCertPool() }},
		{name: "dynamic verification", mutate: func(config *tls.Config) { config.VerifyConnection = func(tls.ConnectionState) error { return nil } }},
		{name: "key log", mutate: func(config *tls.Config) { config.KeyLogWriter = io.Discard }},
		{name: "custom time", mutate: func(config *tls.Config) { config.Time = time.Now }},
		{name: "client session cache", mutate: func(config *tls.Config) { config.ClientSessionCache = tls.NewLRUClientSessionCache(1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := runtime.tlsConfig.Clone()
			test.mutate(candidate)
			if owned, err := ownedProductionIssuerTLSConfig(candidate); err == nil || owned != nil {
				t.Fatalf("unsafe issuer TLS config accepted: owned=%v err=%v", owned != nil, err)
			}
		})
	}
}

func TestLoadProductionGatewayClientCAsRequiresCertificateSigningRoots(t *testing.T) {
	config := newProductionIssuerCommandFixture(t)
	if pool, err := loadProductionGatewayClientCAs(config.gatewayClientCAPath); err != nil || pool == nil || pool.Equal(x509.NewCertPool()) {
		t.Fatalf("valid dedicated gateway client CA rejected: pool=%v err=%v", pool != nil, err)
	}
	nonSigningCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonSigningCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1003),
		Subject:               pkix.Name{CommonName: "Aurora non-signing CA fixture"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	nonSigningCADER, err := x509.CreateCertificate(rand.Reader, nonSigningCATemplate, nonSigningCATemplate, &nonSigningCAKey.PublicKey, nonSigningCAKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		encoded []byte
	}{
		{name: "leaf certificate", encoded: mustReadIssuerTestFile(t, config.tlsCertificatePath)},
		{name: "gateway leaf", encoded: mustReadIssuerTestFile(t, filepath.Join(filepath.Dir(config.gatewayClientCAPath), "gateway-client-cert.pem"))},
		{name: "CA without certificate-signing usage", encoded: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nonSigningCADER})},
		{name: "leading data", encoded: append([]byte("not a PEM root\n"), mustReadIssuerTestFile(t, config.gatewayClientCAPath)...)},
		{name: "wrong PEM type", encoded: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01}})},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway-ca.pem")
			writeProductionCommandFile(t, path, test.encoded, 0o644)
			if pool, err := loadProductionGatewayClientCAs(path); err == nil || pool != nil {
				t.Fatalf("unsafe gateway client CA accepted: pool=%v err=%v", pool != nil, err)
			}
		})
	}
}

func mustReadIssuerTestFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestServeProductionIssuerForceClosesLingeringTLSConnection(t *testing.T) {
	config := newProductionIssuerCommandFixture(t)
	runtime, err := newProductionIssuerService(config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	signalingListener := &issuerProductionSignalingListener{Listener: listener, accepted: make(chan struct{})}
	previousTimeout := productionShutdownTimeout
	productionShutdownTimeout = 20 * time.Millisecond
	t.Cleanup(func() { productionShutdownTimeout = previousTimeout })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- serveProductionIssuer(ctx, runtime, signalingListener) }()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case <-signalingListener.accepted:
	case <-time.After(time.Second):
		t.Fatal("issuer did not accept lingering TLS connection")
	}
	cancel()
	select {
	case err := <-serveResult:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("issuer shutdown error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("issuer shutdown did not return after graceful deadline")
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("issuer left lingering TLS connection open after shutdown")
	} else if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		t.Fatalf("issuer did not close lingering TLS connection: %v", err)
	}
}

func TestProductionIssuerBackendEnforcesGatewayMTLSAndHTTP2(t *testing.T) {
	config := newProductionIssuerCommandFixture(t)
	runtime, err := newProductionIssuerService(config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	httpServer, err := newProductionIssuerHTTPServer(runtime)
	if err != nil {
		t.Fatal(err)
	}
	backendHandler := httpServer.Handler
	var handlerCalls atomic.Int32
	httpServer.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlerCalls.Add(1)
		backendHandler.ServeHTTP(writer, request)
	})
	serveResult := make(chan error, 1)
	go func() { serveResult <- serveProductionIssuerHTTPServer(ctx, httpServer, listener) }()
	var authenticated, withoutCertificate, http1Client *http.Client
	defer func() {
		for _, client := range []*http.Client{authenticated, withoutCertificate, http1Client} {
			if client != nil {
				client.CloseIdleConnections()
			}
		}
		cancel()
		select {
		case serveErr := <-serveResult:
			if serveErr != nil {
				t.Errorf("stop private issuer backend: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("private issuer backend did not stop")
		}
	}()

	backendURL := "https://" + listener.Addr().String() + "/"
	body := productionIssuerBlindRSARequestBody(t)
	authenticated = productionIssuerGatewayHTTPClient(t, config)
	response, err := authenticated.Post(backendURL, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || response.TLS == nil || response.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("authenticated gateway transport = status=%d proto=%q TLS=%+v", response.StatusCode, response.Proto, response.TLS)
	}
	if handlerCalls.Load() != 1 {
		t.Fatalf("authenticated HTTP/2 request reached backend handler %d times", handlerCalls.Load())
	}

	withoutCertificate = &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				NextProtos:         []string{"h2"},
				InsecureSkipVerify: true,
			},
		},
	}
	if unauthenticated, requestErr := withoutCertificate.Post(backendURL, "application/octet-stream", bytes.NewReader(body)); requestErr == nil {
		unauthenticated.Body.Close()
		t.Fatalf("issuer backend accepted a client without a gateway certificate: status=%d", unauthenticated.StatusCode)
	}
	if handlerCalls.Load() != 1 {
		t.Fatalf("unauthenticated TLS request reached backend handler %d times", handlerCalls.Load())
	}

	directory := filepath.Dir(config.gatewayClientCAPath)
	gatewayCertificate, err := tls.LoadX509KeyPair(filepath.Join(directory, "gateway-client-cert.pem"), filepath.Join(directory, "gateway-client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	http1Client = &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"http/1.1"},
			Certificates:       []tls.Certificate{gatewayCertificate},
			InsecureSkipVerify: true,
		}},
	}
	beforeHTTP1 := handlerCalls.Load()
	if http1Response, requestErr := http1Client.Post(backendURL, "application/octet-stream", bytes.NewReader(body)); requestErr == nil {
		defer http1Response.Body.Close()
		if http1Response.StatusCode == http.StatusOK {
			t.Fatalf("issuer backend accepted HTTP/1.1: protocol=%q", http1Response.Proto)
		}
	}
	if handlerCalls.Load() != beforeHTTP1 {
		t.Fatalf("HTTP/1.1 reached the h2-only backend handler: calls before=%d after=%d", beforeHTTP1, handlerCalls.Load())
	}
}

func TestCloseProductionIssuerRuntimeReportsDurableCacheFailure(t *testing.T) {
	closeErr := errors.New("spent-token cache close failed")
	var stderr bytes.Buffer
	err := closeProductionIssuerRuntime(productionCloseRecorder{err: closeErr}, &stderr)
	if !errors.Is(err, closeErr) {
		t.Fatalf("close error = %v, want %v", err, closeErr)
	}
	if output := stderr.String(); !strings.Contains(output, "spent-token cache close failed") {
		t.Fatalf("close failure output = %q", output)
	}
}

type issuerProductionSignalingListener struct {
	net.Listener
	accepted chan struct{}
	once     sync.Once
}

func (l *issuerProductionSignalingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.once.Do(func() { close(l.accepted) })
	}
	return connection, err
}

func TestRunIssuerStartsAndStopsProductionService(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production serving requires Linux")
	}
	config := newProductionIssuerCommandFixture(t)
	ready := make(chan struct{})
	restoreListen := setProductionListenForTest(func(string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			close(ready)
		}
		return listener, err
	})
	defer restoreListen()
	restoreSignals := setProductionSignalContextForTest(func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-ready
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		return ctx, cancel
	})
	defer restoreSignals()

	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"issuer"}, productionIssuerCommandArguments(config)...), &stdout, &stderr); code != 0 {
		t.Fatalf("run issuer code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "private issuer backend started") || !strings.Contains(stdout.String(), "public cover gateway admission remains external and incomplete") {
		t.Fatalf("issuer startup output = %s", stdout.String())
	}
}

func TestRunProductionIssuerFailsWhenDurableCacheCannotClose(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production serving requires Linux")
	}
	config := newProductionIssuerCommandFixture(t)
	issuerRuntime, err := newProductionIssuerService(config)
	if err != nil {
		t.Fatal(err)
	}
	cache := issuerRuntime.cache
	issuerRuntime.cache = productionCloseRecorder{err: errors.New("spent-token cache close failed")}
	if err := cache.Close(); err != nil {
		t.Fatalf("close fixture cache: %v", err)
	}
	ready := make(chan struct{})
	restoreListen := setProductionListenForTest(func(string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			close(ready)
		}
		return listener, err
	})
	defer restoreListen()
	restoreSignals := setProductionSignalContextForTest(func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-ready
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		return ctx, cancel
	})
	defer restoreSignals()

	var stdout, stderr bytes.Buffer
	if code := runProductionIssuer(issuerRuntime, config.listenAddress, &stdout, &stderr); code != 1 {
		t.Fatalf("run issuer close failure code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if output := stderr.String(); !strings.Contains(output, "spent-token cache close failed") {
		t.Fatalf("close failure output = %q", output)
	}
}

func TestParseProductionIssuerConfigLoadsOwnerOnlyArgumentsFile(t *testing.T) {
	config := newProductionIssuerCommandFixture(t)
	encoded, err := json.Marshal(struct {
		Arguments []string `json:"arguments"`
	}{Arguments: productionIssuerCommandArguments(config)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "issuer.json")
	writeProductionCommandFile(t, path, encoded, 0o600)

	parsed, err := parseProductionIssuerConfig([]string{"--config", path}, io.Discard)
	if err != nil {
		t.Fatalf("parse issuer configuration file: %v", err)
	}
	if !reflect.DeepEqual(parsed, config) {
		t.Fatalf("parsed issuer configuration = %+v, want %+v", parsed, config)
	}
}

func TestParseProductionIssuerConfigRequiresGatewayCAAndBoundsSigning(t *testing.T) {
	config := newProductionIssuerCommandFixture(t)
	for _, concurrency := range []int{1, issuerd.MaximumProductionBlindRSABackendConcurrency} {
		candidate := config
		candidate.maxConcurrentIssues = concurrency
		parsed, err := parseProductionIssuerConfig(productionIssuerCommandArguments(candidate), io.Discard)
		if err != nil {
			t.Fatalf("parse signing concurrency %d: %v", concurrency, err)
		}
		if parsed.maxConcurrentIssues != concurrency {
			t.Fatalf("parsed signing concurrency = %d, want %d", parsed.maxConcurrentIssues, concurrency)
		}
	}
	for _, concurrency := range []int{0, issuerd.MaximumProductionBlindRSABackendConcurrency + 1} {
		candidate := config
		candidate.maxConcurrentIssues = concurrency
		if parsed, err := parseProductionIssuerConfig(productionIssuerCommandArguments(candidate), io.Discard); err == nil || parsed.maxConcurrentIssues != 0 {
			t.Fatalf("unsafe signing concurrency %d accepted: parsed=%+v err=%v", concurrency, parsed, err)
		}
	}
	arguments := productionIssuerCommandArguments(config)
	for i := 0; i < len(arguments); i++ {
		if arguments[i] == "--gateway-client-ca" {
			arguments = append(arguments[:i], arguments[i+2:]...)
			break
		}
	}
	if parsed, err := parseProductionIssuerConfig(arguments, io.Discard); err == nil || parsed.gatewayClientCAPath != "" {
		t.Fatalf("issuer config without gateway client CA accepted: parsed=%+v err=%v", parsed, err)
	}
}

func TestParseProductionIssuerConfigHelpDescribesArgumentsFile(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseProductionIssuerConfig([]string{"--help"}, &stderr)
	if err == nil {
		t.Fatal("issuer help did not stop parsing")
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("issuer help does not describe configuration file mode: %s", stderr.String())
	}
}

func TestProductionIssuerBinaryServesOnlySafeEndpointsAndStopsOnSIGTERM(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SIGTERM process lifecycle is Linux-specific")
	}
	config := newProductionIssuerCommandFixture(t)
	binary := filepath.Join(t.TempDir(), "aurorad")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build issuer binary: %v\n%s", err, output)
	}
	var command *exec.Cmd
	var stderr *bytes.Buffer
	for attempt := 0; attempt < 5; attempt++ {
		config.listenAddress = productionCommandListenAddress(t)
		candidate, candidateStderr, started := startProductionIssuerCommand(t, binary, productionIssuerCommandArguments(config))
		if started {
			command = candidate
			stderr = candidateStderr
			break
		}
		if !strings.Contains(candidateStderr.String(), "address already in use") {
			t.Fatalf("issuer binary did not start: %s", candidateStderr.String())
		}
	}
	if command == nil {
		t.Fatal("issuer binary could not obtain a test listen address")
	}
	defer func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	_, port, err := net.SplitHostPort(config.listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	client := productionIssuerGatewayHTTPClient(t, config)
	backendURL := "https://127.0.0.1:" + port + "/"
	requestBody := productionIssuerBlindRSARequestBody(t)
	var issued *http.Response
	for attempt := 0; attempt < 20; attempt++ {
		issued, err = client.Post(backendURL, "application/octet-stream", bytes.NewReader(requestBody))
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("private issuer backend request: %v stderr=%s", err, stderr.String())
	}
	issuedBody, readErr := io.ReadAll(issued.Body)
	issued.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if issued.StatusCode != http.StatusOK {
		t.Fatalf("private issuer backend status = %d body=%q", issued.StatusCode, issuedBody)
	}
	if kind, _, decodeErr := carrier.Decode(issuedBody); decodeErr != nil || kind != carrier.BlindRSAIssueResponse {
		t.Fatalf("private issuer backend carrier = kind=%d err=%v", kind, decodeErr)
	}
	for _, path := range []string{"/healthz", "/issuer-metadata", "/blind-rsa/issue", "/token/spend", "/packet"} {
		request, requestErr := http.NewRequest(http.MethodPost, backendURL[:len(backendURL)-1]+path, bytes.NewReader(requestBody))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/octet-stream")
		response, requestErr := client.Do(request)
		if requestErr != nil {
			t.Fatalf("private issuer negative route %q: %v", path, requestErr)
		}
		body, bodyErr := io.ReadAll(response.Body)
		response.Body.Close()
		if bodyErr != nil {
			t.Fatal(bodyErr)
		}
		if response.StatusCode != http.StatusServiceUnavailable || len(body) != 0 {
			t.Fatalf("private issuer route %q = status=%d body=%q", path, response.StatusCode, body)
		}
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- command.Wait() }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("issuer binary shutdown: %v stderr=%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("issuer binary did not stop after SIGTERM")
	}
}

func TestNewProductionIssuerServiceRejectsUnsafePrivateState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not provide Unix owner-only permission bits")
	}
	config := newProductionIssuerCommandFixture(t)
	if err := os.Chmod(config.blindRSAKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime, err := newProductionIssuerService(config); err == nil {
		_ = runtime.Close()
		t.Fatal("world-readable Blind RSA key accepted")
	}
	config = newProductionIssuerCommandFixture(t)
	if err := os.Chmod(filepath.Dir(config.spentTokenCachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime, err := newProductionIssuerService(config); err == nil {
		_ = runtime.Close()
		t.Fatal("group-readable spent-token cache directory accepted")
	}
}

func newProductionIssuerCommandFixture(t *testing.T) issuerProductionConfig {
	t.Helper()
	now := uint64(time.Now().Unix())
	issuer, err := issuerd.NewHarnessService(now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := issuer.PublishIssuerMetadata()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := productionCommandRSAPSSPublicKey(t, &privateKey.PublicKey)
	keyID := sha256.Sum256(publicKey)
	metadata.SupportedProofTypes = []uint64{registry.ProofBlindRSA2048}
	metadata.TokenKeyMappings = []protocol.IssuerTokenKeyRecord{{
		ProofType:  registry.ProofBlindRSA2048,
		TokenKeyID: keyID[:],
		TokenVerificationKey: protocol.TokenVerificationKeyRecord{
			TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
			TokenVerificationKey:       publicKey,
		},
		ValidFromUnix:  metadata.ValidFromUnix,
		ValidUntilUnix: metadata.ValidUntilUnix,
		KeyStatus:      registry.IssuerStatusActive,
	}}
	metadata.VerifierServices = nil
	authoritySigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityPublicKey, err := authoritySigner.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	metadata.SignatureScheme = registry.SigECDSAP256SHA384DER
	metadata.KeyEncoding = registry.KeyP256SEC1Uncompressed
	authorityPublicRecord := protocol.PublicKeyRecord{
		SignatureScheme: metadata.SignatureScheme,
		KeyEncoding:     metadata.KeyEncoding,
		PublicKey:       authorityPublicKey,
	}
	encodedAuthorityPublicRecord, err := protocol.Encode(authorityPublicRecord)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSigningKeyID = auroratrust.AuthorityKeyID(encodedAuthorityPublicRecord)
	input, err := auroratrust.IssuerMetadataSignatureInput(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, authoritySigner, input)
	if err != nil {
		t.Fatal(err)
	}
	authority := protocol.AuthorityKeyRecord{
		AuthorityID:    issuerCommandBytes(0x94, 16),
		AuthorityKeyID: append([]byte(nil), metadata.MetadataSigningKeyID...),
		PublicKey:      authorityPublicRecord,
		ValidFromUnix:  metadata.ValidFromUnix,
		ValidUntilUnix: metadata.ValidUntilUnix,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}
	directory := t.TempDir()
	cacheDirectory := filepath.Join(directory, "replay-state")
	if err := os.Mkdir(cacheDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(directory, "issuer-metadata.bin")
	writeProductionCommandFile(t, metadataPath, mustEncodeProductionCommand(t, metadata), 0o644)
	authorityPath := filepath.Join(directory, "issuer-authority.bin")
	writeProductionCommandFile(t, authorityPath, mustEncodeProductionCommand(t, authority), 0o644)
	privatePath := filepath.Join(directory, "issuer-key.pem")
	writeProductionCommandFile(t, privatePath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0o600)
	tlsSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tlsTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject:      pkix.Name{CommonName: "Aurora test private issuer backend"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	tlsCertificateDER, err := x509.CreateCertificate(rand.Reader, tlsTemplate, tlsTemplate, &tlsSigner.PublicKey, tlsSigner)
	if err != nil {
		t.Fatal(err)
	}
	tlsPrivateKey, err := x509.MarshalPKCS8PrivateKey(tlsSigner)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "issuer-cert.pem")
	tlsKeyPath := filepath.Join(directory, "issuer-tls-key.pem")
	writeProductionCommandFile(t, certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCertificateDER}), 0o644)
	writeProductionCommandFile(t, tlsKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsPrivateKey}), 0o600)
	gatewayClientCAPath := filepath.Join(directory, "gateway-client-ca.pem")
	gatewayClientCertificatePath := filepath.Join(directory, "gateway-client-cert.pem")
	gatewayClientKeyPath := filepath.Join(directory, "gateway-client-key.pem")
	writeProductionIssuerGatewayIdentity(t, gatewayClientCAPath, gatewayClientCertificatePath, gatewayClientKeyPath)
	return issuerProductionConfig{
		listenAddress:            "127.0.0.1:8443",
		tlsCertificatePath:       certificatePath,
		tlsPrivateKeyPath:        tlsKeyPath,
		gatewayClientCAPath:      gatewayClientCAPath,
		issuerMetadataPath:       metadataPath,
		metadataAuthorityKeyPath: authorityPath,
		blindRSAKeyPath:          privatePath,
		spentTokenCachePath:      filepath.Join(cacheDirectory, "spent-token-cache.log"),
		relayBucketID:            append([]byte(nil), metadata.RelayBucketScopes[0].RelayBucketID...),
		originInfoPolicyID:       metadata.OriginInfoPolicies[0].PolicyID,
		maxConcurrentIssues:      issuerProductionDefaultConcurrentIssues,
	}
}

func productionIssuerCommandArguments(config issuerProductionConfig) []string {
	return []string{
		"--listen", config.listenAddress,
		"--tls-cert", config.tlsCertificatePath,
		"--tls-key", config.tlsPrivateKeyPath,
		"--gateway-client-ca", config.gatewayClientCAPath,
		"--issuer-metadata", config.issuerMetadataPath,
		"--metadata-authority-key", config.metadataAuthorityKeyPath,
		"--blind-rsa-key", config.blindRSAKeyPath,
		"--spent-token-cache", config.spentTokenCachePath,
		"--relay-bucket-id", hex.EncodeToString(config.relayBucketID),
		"--origin-info-policy", strconv.FormatUint(config.originInfoPolicyID, 10),
		"--max-concurrent-issues", strconv.Itoa(config.maxConcurrentIssues),
	}
}

func startProductionIssuerCommand(t *testing.T, binary string, arguments []string) (*exec.Cmd, *bytes.Buffer, bool) {
	t.Helper()
	command := exec.Command(binary, append([]string{"issuer"}, arguments...)...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	started := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "aurorad private issuer backend started; public cover gateway admission remains external and incomplete" {
				started <- true
				return
			}
		}
		started <- false
	}()
	select {
	case ok := <-started:
		if ok {
			return command, stderr, true
		}
		_ = command.Wait()
		return nil, stderr, false
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("issuer binary did not report startup")
	}
	return nil, nil, false
}

func writeProductionIssuerGatewayIdentity(t *testing.T, caPath, certificatePath, keyPath string) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "Aurora test gateway client CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject:      pkix.Name{CommonName: "Aurora test authenticated gateway"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, client, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedClientKey, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	writeProductionCommandFile(t, caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	writeProductionCommandFile(t, certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o644)
	writeProductionCommandFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedClientKey}), 0o600)
}

func productionIssuerGatewayHTTPClient(t *testing.T, config issuerProductionConfig) *http.Client {
	t.Helper()
	directory := filepath.Dir(config.gatewayClientCAPath)
	certificate, err := tls.LoadX509KeyPair(filepath.Join(directory, "gateway-client-cert.pem"), filepath.Join(directory, "gateway-client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				NextProtos:         []string{"h2"},
				Certificates:       []tls.Certificate{certificate},
				InsecureSkipVerify: true,
			},
		},
	}
}

func productionIssuerBlindRSARequestBody(t *testing.T) []byte {
	t.Helper()
	payload, err := carrier.EncodeIssueRequest(issuerCommandBytes(0x91, carrier.TokenNonceLength), issuerCommandBytes(0x92, carrier.RedemptionContextLength), uint64(time.Now().Unix())+60)
	if err != nil {
		t.Fatal(err)
	}
	return carrier.Encode(carrier.BlindRSAIssueRequest, payload)
}

func issuerCommandBytes(value byte, length int) []byte {
	return bytes.Repeat([]byte{value}, length)
}
