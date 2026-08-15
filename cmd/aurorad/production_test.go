package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
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
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestNewProductionServiceLoadsVerifiedDeploymentAndPrivateDependencies(t *testing.T) {
	config := newProductionCommandFixture(t)
	service, caches, err := newProductionService(config)
	if err != nil {
		t.Fatalf("new production service: %v", err)
	}
	if service == nil {
		t.Fatal("new production service returned nil")
	}
	closeProductionCaches(caches)
}

func TestNewProductionServiceUsesRetentionReplayCaches(t *testing.T) {
	service, caches, err := newProductionService(newProductionCommandFixture(t))
	if err != nil || service == nil {
		closeProductionCaches(caches)
		t.Fatalf("new production service: service=%v err=%v", service, err)
	}
	defer closeProductionCaches(caches)
	for index, cache := range caches {
		if _, ok := cache.(*admission.RetentionFileReplayCache); !ok {
			t.Fatalf("production cache %d type = %T, want retention cache", index, cache)
		}
	}
}

func TestCloseProductionCachesReportsEveryFailure(t *testing.T) {
	firstErr := errors.New("first durable cache close failed")
	secondErr := errors.New("second durable cache close failed")
	var closed []string
	var stderr bytes.Buffer
	err := closeProductionCachesAndReport([]io.Closer{
		productionCloseRecorder{name: "first", err: firstErr, closed: &closed},
		productionCloseRecorder{name: "second", err: secondErr, closed: &closed},
	}, &stderr)
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("close error = %v, want both close failures", err)
	}
	if got, want := strings.Join(closed, ","), "second,first"; got != want {
		t.Fatalf("cache close order = %q, want %q", got, want)
	}
	if output := stderr.String(); !strings.Contains(output, "first durable cache close failed") || !strings.Contains(output, "second durable cache close failed") {
		t.Fatalf("close failure output = %q", output)
	}
}

type productionCloseRecorder struct {
	name   string
	err    error
	closed *[]string
}

func (c productionCloseRecorder) Close() error {
	if c.closed != nil {
		*c.closed = append(*c.closed, c.name)
	}
	return c.err
}

func TestZeroMLDSA65PrivateKeyClearsPrivateMaterial(t *testing.T) {
	_, private, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := private.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encoded, make([]byte, len(encoded))) {
		t.Fatal("generated ML-DSA private key is unexpectedly empty")
	}
	zeroMLDSA65PrivateKey(private)
	if !private.Equal(new(mldsa65.PrivateKey)) {
		t.Fatal("ML-DSA private key material remained after zeroization")
	}
}

func TestZeroPrivatePEMBlockClearsDecodedPrivateMaterial(t *testing.T) {
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bytes.Repeat([]byte{0x81}, 48)})
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 {
		t.Fatal("decode private PEM block")
	}
	decoded := block.Bytes
	zeroPrivatePEMBlock(block)
	if block.Type != "" || len(block.Bytes) != 0 || len(block.Headers) != 0 {
		t.Fatal("PEM block retained metadata after zeroization")
	}
	if !bytes.Equal(decoded, make([]byte, len(decoded))) {
		t.Fatal("PEM block retained decoded private material after zeroization")
	}
}

func TestRunServeStartsAndStopsProductionService(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production serving requires Linux")
	}
	config := newProductionCommandFixture(t)
	arguments := productionCommandArguments(config)
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
	if code := run(append([]string{"serve"}, arguments...), &stdout, &stderr); code != 0 {
		t.Fatalf("run serve code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("production server started")) {
		t.Fatalf("production start output = %s", stdout.String())
	}
}

func TestRunProductionServiceFailsWhenDurableCacheCannotClose(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production serving requires Linux")
	}
	config := newProductionCommandFixture(t)
	service, caches, err := newProductionService(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := closeProductionCaches(caches); err != nil {
		t.Fatalf("close fixture caches: %v", err)
	}
	closeErr := errors.New("replay cache close failed")
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
	if code := runProductionService(service, []io.Closer{productionCloseRecorder{err: closeErr}}, config.listenAddress, &stdout, &stderr); code != 1 {
		t.Fatalf("run service close failure code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if output := stderr.String(); !strings.Contains(output, "replay cache close failed") {
		t.Fatalf("close failure output = %q", output)
	}
}

func TestParseProductionConfigLoadsOwnerOnlyArgumentsFile(t *testing.T) {
	config := newProductionCommandFixture(t)
	encoded, err := json.Marshal(struct {
		Arguments []string `json:"arguments"`
	}{Arguments: productionCommandArguments(config)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "aurorad.json")
	writeProductionCommandFile(t, path, encoded, 0o600)

	parsed, err := parseProductionConfig([]string{"--config", path}, io.Discard)
	if err != nil {
		t.Fatalf("parse production configuration file: %v", err)
	}
	if parsed != config {
		t.Fatalf("parsed production configuration = %+v, want %+v", parsed, config)
	}
}

func TestParseProductionConfigRejectsArgumentsFileCombinedWithCLIOptions(t *testing.T) {
	config := newProductionCommandFixture(t)
	encoded, err := json.Marshal(struct {
		Arguments []string `json:"arguments"`
	}{Arguments: productionCommandArguments(config)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "aurorad.json")
	writeProductionCommandFile(t, path, encoded, 0o600)

	_, err = parseProductionConfig([]string{"--config", path, "--max-sessions", "2"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("configuration file combined with CLI options error = %v, want rejection", err)
	}
}

func TestParseProductionConfigRejectsArgumentsFilePrecededByCLIOptions(t *testing.T) {
	config := newProductionCommandFixture(t)
	encoded, err := json.Marshal(struct {
		Arguments []string `json:"arguments"`
	}{Arguments: productionCommandArguments(config)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "aurorad.json")
	writeProductionCommandFile(t, path, encoded, 0o600)

	_, err = parseProductionConfig([]string{"--max-sessions", "2", "--config", path}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("CLI options preceding configuration file error = %v, want rejection", err)
	}
}

func TestParseProductionConfigRejectsUnknownArgumentsFileFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aurorad.json")
	writeProductionCommandFile(t, path, []byte(`{"arguments": [], "unexpected": true}`), 0o600)

	_, err := parseProductionConfig([]string{"--config", path}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "decode production configuration file") {
		t.Fatalf("unknown configuration file field error = %v, want strict decoding rejection", err)
	}
}

func TestParseProductionConfigHelpDescribesArgumentsFile(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseProductionConfig([]string{"--help"}, &stderr)
	if err == nil {
		t.Fatal("production help did not stop parsing")
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("production help does not describe configuration file mode: %s", stderr.String())
	}
}

func TestNewProductionServiceRejectsMismatchedClassicalSigner(t *testing.T) {
	config := newProductionCommandFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalECPrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	writeProductionCommandFile(t, config.classicalSignerPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0o600)
	if _, caches, err := newProductionService(config); err == nil {
		closeProductionCaches(caches)
		t.Fatal("mismatched classical signer accepted")
	}
}

func TestNewProductionServiceRejectsMalformedDeploymentAndUnsafePrivateKey(t *testing.T) {
	config := newProductionCommandFixture(t)
	config.templatePath = filepath.Join(t.TempDir(), "missing-template.bin")
	if _, caches, err := newProductionService(config); err == nil {
		closeProductionCaches(caches)
		t.Fatal("missing template file accepted")
	}
	config = newProductionCommandFixture(t)
	writeProductionCommandFile(t, config.descriptorPath, []byte{0x01}, 0o644)
	if _, caches, err := newProductionService(config); err == nil {
		closeProductionCaches(caches)
		t.Fatal("malformed relay descriptor accepted")
	}
	if runtime.GOOS != "windows" {
		config = newProductionCommandFixture(t)
		if err := os.Chmod(config.tlsPrivateKeyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, caches, err := newProductionService(config); err == nil {
			closeProductionCaches(caches)
			t.Fatal("world-readable TLS private key accepted")
		}
	}
	config = newProductionCommandFixture(t)
	config.coverOriginURL = ""
	if _, caches, err := newProductionService(config); err == nil {
		closeProductionCaches(caches)
		t.Fatal("missing cover origin accepted")
	}
}

func TestProductionBinaryStartsAndStopsOnSIGTERM(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SIGTERM process lifecycle is Unix-specific")
	}
	config := newProductionCommandFixture(t)
	binary := filepath.Join(t.TempDir(), "aurorad")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build production binary: %v\n%s", err, output)
	}
	var command *exec.Cmd
	var stderr *bytes.Buffer
	for attempt := 0; attempt < 5; attempt++ {
		config.listenAddress = productionCommandListenAddress(t)
		candidate, candidateStderr, started := startProductionCommand(t, binary, productionCommandArguments(config))
		if started {
			command = candidate
			stderr = candidateStderr
			break
		}
		if !strings.Contains(candidateStderr.String(), "address already in use") {
			t.Fatalf("production binary did not start: %s", candidateStderr.String())
		}
	}
	if command == nil {
		t.Fatal("production binary could not obtain a test listen address")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- command.Wait() }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("production binary shutdown: %v stderr=%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("production binary did not stop after SIGTERM")
	}
}

func productionCommandListenAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
}

func startProductionCommand(t *testing.T, binary string, arguments []string) (*exec.Cmd, *bytes.Buffer, bool) {
	t.Helper()
	command := exec.Command(binary, append([]string{"serve"}, arguments...)...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	started := make(chan bool, 1)
	go func() {
		for scanner.Scan() {
			if scanner.Text() == "aurorad production server started" {
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
		t.Fatal("production binary did not report startup")
	}
	return nil, nil, false
}

func newProductionCommandFixture(t *testing.T) productionConfig {
	t.Helper()
	now := uint64(time.Now().Unix())
	longtermClassical := newProductionCommandECDSA(t)
	epochClassical := newProductionCommandECDSA(t)
	templateAuthority := newProductionCommandECDSA(t)
	longtermPQPublic, longtermPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochPQPublic, epochPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       productionCommandBytes(0x31, 16),
		TemplateFamilyID: productionCommandBytes(0x32, 16),
		ValidFromUnix:    now - 60,
		ValidUntilUnix:   now + 3600,
		OriginSPKIHash:   productionCommandBytes(0x33, 48),
		PublicNameHash:   productionCommandBytes(0x34, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             7,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      productionCommandBytes(0x35, 16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{productionCommandBytes(0x36, 48)},
		OriginPassThroughSlotCommitments: [][]byte{productionCommandBytes(0x37, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  productionCommandBytes(0x38, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: productionCommandBytes(0x39, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               productionCommandBytes(0x3a, 16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   productionCommandBytes(0x3b, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile:         protocol.H2CoverProfile{ProfileID: 1, RecordSizeDistributionID: productionCommandBytes(0x3c, 16)},
		H3Profile:         protocol.H3CoverProfile{ProfileID: 2, DatagramSizeDistributionID: productionCommandBytes(0x3d, 16), DatagramRateDistributionID: productionCommandBytes(0x3e, 16)},
		WebSocketProfile:  protocol.WebSocketCoverProfile{ProfileID: 3, FrameSizeDistributionID: productionCommandBytes(0x3f, 16)},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: productionCommandBytes(0x40, 16)},
	}
	var errCommitment error
	template.CoverOriginCommitment, errCommitment = trust.CoverOriginCommitment(template)
	if errCommitment != nil {
		t.Fatal(errCommitment)
	}
	templateHash, err := trust.CoverTemplateHash(template)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:         registry.Version20,
		RelayID:                   productionCommandBytes(0x41, 32),
		RoleFlags:                 1,
		ValidFromUnix:             now - 60,
		ValidUntilUnix:            now + 3600,
		RelayLongtermClassicalKey: productionCommandPublicRecord(t, longtermClassical),
		RelayLongtermPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       longtermPQPublic.Bytes(),
		},
		EpochID:               9,
		EpochAuthClassicalKey: productionCommandPublicRecord(t, epochClassical),
		EpochAuthPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       epochPQPublic.Bytes(),
		},
		EpochValidFromUnix:           now - 60,
		EpochValidUntilUnix:          now + 3600,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    now + 3600,
		ReplayWindowID:               productionCommandBytes(0x42, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: productionCommandBytes(0x43, 48),
		SupportedShapeIDsCommitment:  productionCommandBytes(0x44, 48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         productionCommandBytes(0x45, 48),
		AbusePolicyCommitment:        productionCommandBytes(0x46, 48),
	}
	descriptorInput, err := trust.RelayDescriptorSignatureInput(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermClassical, err = ecdsa.SignASN1(rand.Reader, longtermClassical, descriptorInput)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermPQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(longtermPQPrivate, descriptorInput, nil, false, descriptor.SignatureByLongtermPQ); err != nil {
		t.Fatal(err)
	}
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	familyInput, err := trust.CoverTemplateFamilySignatureInput(template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthority, familyInput)
	if err != nil {
		t.Fatal(err)
	}
	instanceInput, err := trust.CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, instanceInput)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	cacheDirectory := filepath.Join(directory, "replay-state")
	if err := os.Mkdir(cacheDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writeProductionCommandFile(t, filepath.Join(directory, "descriptor.bin"), mustEncodeProductionCommand(t, descriptor), 0o644)
	writeProductionCommandFile(t, filepath.Join(directory, "descriptor.hash"), descriptorHash, 0o644)
	writeProductionCommandFile(t, filepath.Join(directory, "template.bin"), mustEncodeProductionCommand(t, template), 0o644)
	writeProductionCommandFile(t, filepath.Join(directory, "template-authority.bin"), mustEncodeProductionCommand(t, productionCommandPublicRecord(t, templateAuthority)), 0o644)
	classicalPrivate, err := x509.MarshalECPrivateKey(epochClassical)
	if err != nil {
		t.Fatal(err)
	}
	classicalPath := filepath.Join(directory, "epoch-classical.pem")
	writeProductionCommandFile(t, classicalPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: classicalPrivate}), 0o600)
	pqPrivate, err := epochPQPrivate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pqPath := filepath.Join(directory, "epoch-pq.bin")
	writeProductionCommandFile(t, pqPath, pqPrivate, 0o600)
	credentialSet, err := admission.EncodeAccessHintCredentialSet([]admission.AccessHintCredential{{
		HintIssuerID:  productionCommandBytes(0x51, 16),
		RelayBucketID: productionCommandBytes(0x52, 16),
		HintEpochID:   3,
		HintSelector:  productionCommandBytes(0x53, 16),
		HintSecret:    productionCommandBytes(0x54, 32),
		ExpiryUnix:    now + 1800,
		MaxUses:       1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	accessHintsPath := filepath.Join(directory, "access-hints.bin")
	writeProductionCommandFile(t, accessHintsPath, credentialSet, 0o600)
	tokenPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tokenKeyPath := filepath.Join(directory, "token-key.der")
	writeProductionCommandFile(t, tokenKeyPath, productionCommandRSAPSSPublicKey(t, &tokenPrivate.PublicKey), 0o644)
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(certificateServer.Close)
	certificate := certificateServer.TLS.Certificates[0]
	tlsPrivateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "server-cert.pem")
	privateKeyPath := filepath.Join(directory, "server-key.pem")
	writeProductionCommandFile(t, certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o644)
	writeProductionCommandFile(t, privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsPrivateKey}), 0o600)
	coverServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(coverServer.Close)
	return productionConfig{
		listenAddress:             "0.0.0.0:8443",
		authority:                 "cover.example:443",
		path:                      "/assets/upload/42",
		tlsCertificatePath:        certificatePath,
		tlsPrivateKeyPath:         privateKeyPath,
		coverOriginURL:            coverServer.URL,
		descriptorPath:            filepath.Join(directory, "descriptor.bin"),
		trustedDescriptorHashPath: filepath.Join(directory, "descriptor.hash"),
		templatePath:              filepath.Join(directory, "template.bin"),
		templateAuthorityKeyPath:  filepath.Join(directory, "template-authority.bin"),
		requestClassID:            7,
		suite:                     registry.SuiteHybrid768P256AESGCM,
		classicalSignerPath:       classicalPath,
		pqSignerPath:              pqPath,
		accessHintsPath:           accessHintsPath,
		tokenVerificationKeyPath:  tokenKeyPath,
		hintSpentCachePath:        filepath.Join(cacheDirectory, "hint-cache.log"),
		tokenSpentCachePath:       filepath.Join(cacheDirectory, "token-cache.log"),
		bootstrapCachePath:        filepath.Join(cacheDirectory, "bootstrap-cache.log"),
		maxConcurrentSessions:     1,
		policy:                    registry.PolicyBalancedWeb,
		route:                     registry.RouteFast1,
		shape:                     registry.ShapeNormal,
		sessionLimits: session.Limits{
			MaxQueuedPackets:       32,
			MaxQueuedBytes:         256 << 10,
			ControlReservedPackets: 2,
			ControlReservedBytes:   8 << 10,
			ReplayWindow:           1024,
		},
		egressLimits: relay.SocketEgressLimits{
			MaxFlows:            8,
			MaxBufferedBytes:    1 << 20,
			TCPReadBufferBytes:  1024,
			MaxUDPDatagramBytes: 512,
			DialTimeout:         time.Second,
			WriteTimeout:        time.Second,
			IdleTimeout:         time.Second,
			QueueRetryInterval:  time.Millisecond,
		},
		egressResolvedTTL:     60,
		egressMaxFlowOpens:    8,
		exitRateLimit:         relay.ExitRateLimit{WindowSeconds: 60, MaxBytes: 1 << 20},
		udpConfirmTTL:         60,
		dnsUpstream:           "127.0.0.1:53",
		maxTemplateFutureSkew: 120,
	}
}

func productionCommandArguments(config productionConfig) []string {
	return []string{
		"--listen", config.listenAddress,
		"--authority", config.authority,
		"--path", config.path,
		"--tls-cert", config.tlsCertificatePath,
		"--tls-key", config.tlsPrivateKeyPath,
		"--cover-origin-url", config.coverOriginURL,
		"--relay-descriptor", config.descriptorPath,
		"--trusted-descriptor-hash", config.trustedDescriptorHashPath,
		"--cover-template", config.templatePath,
		"--template-authority-key", config.templateAuthorityKeyPath,
		"--request-class", strconv.FormatUint(config.requestClassID, 10),
		"--suite", strconv.FormatUint(config.suite, 10),
		"--classical-signer-key", config.classicalSignerPath,
		"--pq-signer-key", config.pqSignerPath,
		"--access-hints", config.accessHintsPath,
		"--token-verification-key", config.tokenVerificationKeyPath,
		"--hint-spent-cache", config.hintSpentCachePath,
		"--token-spent-cache", config.tokenSpentCachePath,
		"--bootstrap-cache", config.bootstrapCachePath,
		"--max-sessions", strconv.Itoa(config.maxConcurrentSessions),
		"--session-max-queued-packets", strconv.Itoa(config.sessionLimits.MaxQueuedPackets),
		"--session-max-queued-bytes", strconv.Itoa(config.sessionLimits.MaxQueuedBytes),
		"--session-control-reserved-packets", strconv.Itoa(config.sessionLimits.ControlReservedPackets),
		"--session-control-reserved-bytes", strconv.Itoa(config.sessionLimits.ControlReservedBytes),
		"--session-replay-window", strconv.FormatUint(config.sessionLimits.ReplayWindow, 10),
		"--egress-max-flows", strconv.Itoa(config.egressLimits.MaxFlows),
		"--egress-max-buffered-bytes", strconv.Itoa(config.egressLimits.MaxBufferedBytes),
		"--egress-tcp-read-buffer-bytes", strconv.Itoa(config.egressLimits.TCPReadBufferBytes),
		"--egress-max-udp-datagram-bytes", strconv.Itoa(config.egressLimits.MaxUDPDatagramBytes),
		"--egress-dial-timeout", config.egressLimits.DialTimeout.String(),
		"--egress-write-timeout", config.egressLimits.WriteTimeout.String(),
		"--egress-idle-timeout", config.egressLimits.IdleTimeout.String(),
		"--egress-queue-retry", config.egressLimits.QueueRetryInterval.String(),
		"--egress-resolved-ttl", strconv.FormatUint(uint64(config.egressResolvedTTL), 10),
		"--egress-rate-window", strconv.FormatUint(config.exitRateLimit.WindowSeconds, 10),
		"--egress-max-flow-opens", strconv.FormatUint(uint64(config.egressMaxFlowOpens), 10),
		"--egress-max-bytes", strconv.FormatUint(config.exitRateLimit.MaxBytes, 10),
		"--udp-confirm-ttl", strconv.FormatUint(uint64(config.udpConfirmTTL), 10),
		"--dns-upstream", config.dnsUpstream,
		"--max-template-future-skew", strconv.FormatUint(config.maxTemplateFutureSkew, 10),
	}
}

func newProductionCommandECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func productionCommandPublicRecord(t *testing.T, key *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	t.Helper()
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA384DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: encoded}
}

func productionCommandRSAPSSPublicKey(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	raw, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{N: key.N, E: key.E})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}},
		SubjectPublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustEncodeProductionCommand(t *testing.T, value wire.Encodable) []byte {
	t.Helper()
	encoded, err := protocol.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func productionCommandBytes(value byte, length int) []byte {
	return bytes.Repeat([]byte{value}, length)
}

func writeProductionCommandFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func setProductionListenForTest(fn func(string) (net.Listener, error)) func() {
	previous := productionListen
	productionListen = fn
	return func() { productionListen = previous }
}

func setProductionSignalContextForTest(fn func() (context.Context, context.CancelFunc)) func() {
	previous := productionSignalContext
	productionSignalContext = fn
	return func() { productionSignalContext = previous }
}
