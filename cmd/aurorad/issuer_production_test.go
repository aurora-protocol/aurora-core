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
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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
	if runtime.tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("issuer TLS minimum version = %d, want TLS 1.3", runtime.tlsConfig.MinVersion)
	}

	handler := issuerd.NewHTTPHandler(runtime.service)
	metadata := httptest.NewRecorder()
	handler.ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "/issuer-metadata", nil))
	if metadata.Code != http.StatusOK {
		t.Fatalf("issuer metadata status = %d body=%s", metadata.Code, metadata.Body.String())
	}
	issue := httptest.NewRecorder()
	handler.ServeHTTP(issue, httptest.NewRequest(http.MethodPost, "/blind-rsa/issue", nil))
	if issue.Code != http.StatusNotFound {
		t.Fatalf("production issuer exposed harness issue endpoint: %d", issue.Code)
	}
	if _, err := runtime.service.IssueBlindRSA2048(issuerd.IssueBlindRSA2048Request{
		TokenNonce:            issuerCommandBytes(0x91, 32),
		RedemptionContextHash: issuerCommandBytes(0x92, 48),
		ExpiryUnix:            uint64(time.Now().Unix()) + 60,
	}); err != nil {
		t.Fatalf("loaded production issuer did not issue: %v", err)
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
	if httpServer.ReadHeaderTimeout <= 0 || httpServer.ReadTimeout <= 0 || httpServer.WriteTimeout <= 0 || httpServer.IdleTimeout <= 0 || httpServer.MaxHeaderBytes <= 0 {
		t.Fatalf("issuer HTTP server resource bounds are incomplete: %+v", httpServer)
	}
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
	if !strings.Contains(stdout.String(), "production issuer started") {
		t.Fatalf("issuer startup output = %s", stdout.String())
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
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	metadataURL := "https://127.0.0.1:" + port + "/issuer-metadata"
	var metadata *http.Response
	for attempt := 0; attempt < 20; attempt++ {
		metadata, err = client.Get(metadataURL)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("issuer metadata request: %v stderr=%s", err, stderr.String())
	}
	if metadata.StatusCode != http.StatusOK {
		metadata.Body.Close()
		t.Fatalf("issuer metadata status = %d", metadata.StatusCode)
	}
	metadata.Body.Close()
	health, err := client.Get(metadataURL[:len(metadataURL)-len("issuer-metadata")] + "healthz")
	if err != nil {
		t.Fatalf("issuer health request: %v", err)
	}
	if health.StatusCode != http.StatusOK {
		health.Body.Close()
		t.Fatalf("issuer health status = %d", health.StatusCode)
	}
	health.Body.Close()
	issue, err := client.Post(metadataURL[:len(metadataURL)-len("issuer-metadata")]+"blind-rsa/issue", "application/json", nil)
	if err != nil {
		t.Fatalf("issuer issue request: %v", err)
	}
	if issue.StatusCode != http.StatusNotFound {
		issue.Body.Close()
		t.Fatalf("issuer exposed harness issue endpoint: %d", issue.StatusCode)
	}
	issue.Body.Close()
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
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(certificateServer.Close)
	certificate := certificateServer.TLS.Certificates[0]
	tlsPrivateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "issuer-cert.pem")
	tlsKeyPath := filepath.Join(directory, "issuer-tls-key.pem")
	writeProductionCommandFile(t, certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o644)
	writeProductionCommandFile(t, tlsKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsPrivateKey}), 0o600)
	return issuerProductionConfig{
		listenAddress:            "0.0.0.0:8443",
		tlsCertificatePath:       certificatePath,
		tlsPrivateKeyPath:        tlsKeyPath,
		issuerMetadataPath:       metadataPath,
		metadataAuthorityKeyPath: authorityPath,
		blindRSAKeyPath:          privatePath,
		spentTokenCachePath:      filepath.Join(cacheDirectory, "spent-token-cache.log"),
		relayBucketID:            append([]byte(nil), metadata.RelayBucketScopes[0].RelayBucketID...),
		originInfoPolicyID:       metadata.OriginInfoPolicies[0].PolicyID,
	}
}

func productionIssuerCommandArguments(config issuerProductionConfig) []string {
	return []string{
		"--listen", config.listenAddress,
		"--tls-cert", config.tlsCertificatePath,
		"--tls-key", config.tlsPrivateKeyPath,
		"--issuer-metadata", config.issuerMetadataPath,
		"--metadata-authority-key", config.metadataAuthorityKeyPath,
		"--blind-rsa-key", config.blindRSAKeyPath,
		"--spent-token-cache", config.spentTokenCachePath,
		"--relay-bucket-id", hex.EncodeToString(config.relayBucketID),
		"--origin-info-policy", strconv.FormatUint(config.originInfoPolicyID, 10),
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
			if scanner.Text() == "aurorad production issuer started" {
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

func issuerCommandBytes(value byte, length int) []byte {
	return bytes.Repeat([]byte{value}, length)
}
