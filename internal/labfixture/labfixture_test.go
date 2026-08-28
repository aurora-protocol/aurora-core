package labfixture

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/client"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/issuerd"
)

func mintForTest(t *testing.T, mutate func(*MintOptions)) *Material {
	t.Helper()
	options := MintOptions{Entries: 2, Now: time.Now()}
	if mutate != nil {
		mutate(&options)
	}
	material, err := Mint(options)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func TestMintRejectsInvalidOptions(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*MintOptions)
	}{
		{"blank host", func(o *MintOptions) { o.RelayHost = " " }},
		{"host with whitespace", func(o *MintOptions) { o.RelayHost = "relay .example" }},
		{"relay port negative", func(o *MintOptions) { o.RelayPort = -1 }},
		{"relay port too large", func(o *MintOptions) { o.RelayPort = 70000 }},
		{"issuer port zero conflicts", func(o *MintOptions) { o.IssuerPort = -5 }},
		{"ports equal", func(o *MintOptions) { o.RelayPort = 9443; o.IssuerPort = 9443 }},
		{"entries negative", func(o *MintOptions) { o.Entries = -1 }},
		{"entries too large", func(o *MintOptions) { o.Entries = MaximumEntries + 1 }},
		{"validity too small", func(o *MintOptions) { o.Validity = time.Second }},
		{"validity too large", func(o *MintOptions) { o.Validity = 30 * 24 * time.Hour }},
		{"mint time zero-ish", func(o *MintOptions) { o.Now = time.Unix(0, 0) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := MintOptions{Now: time.Now()}
			testCase.mutate(&options)
			material, err := Mint(options)
			if err == nil {
				material.Zero()
				t.Fatal("invalid mint options were accepted")
			}
		})
	}
}

func TestMintValidationAcceptsDNSAndIPHosts(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "192.168.1.20", "localhost", "relay.lab.example"} {
		if err := validateLabHost(host); err != nil {
			t.Fatalf("host %q rejected: %v", host, err)
		}
	}
	for _, host := range []string{"", " ", "-bad.example", "bad-.example", "bad..example", strings.Repeat("a", 64) + ".example"} {
		if err := validateLabHost(host); err == nil {
			t.Fatalf("host %q accepted", host)
		}
	}
}

func TestMintWriteLoadRoundTrip(t *testing.T) {
	material := mintForTest(t, nil)
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("deployment dir permissions = %o, want 700", info.Mode().Perm())
		}
		for _, name := range manifestFiles() {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("%s permissions = %o, want regular 600", name, info.Mode().Perm())
			}
		}
	}

	loaded, err := Load(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Manifest.Relay.URL != material.Manifest.Relay.URL || loaded.Manifest.Entries != 2 {
		t.Fatalf("loaded manifest mismatch: %+v", loaded.Manifest)
	}
	if !loaded.Deployment.Valid() {
		t.Fatal("loaded deployment did not verify")
	}

	// The minted CA hierarchy: ca.pem is a signing CA, tls-cert.pem is the
	// leaf+CA chain, the leaf verifies against ca.pem for server auth, and
	// the cover template still pins the LEAF subject public key info.
	caCertificate := loaded.CACertificate
	if caCertificate == nil || !caCertificate.IsCA || caCertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("minted ca.pem is not a certificate-signing CA")
	}
	if !strings.Contains(caCertificate.Subject.CommonName, "lab CA") {
		t.Fatalf("lab CA CN = %q", caCertificate.Subject.CommonName)
	}
	if len(loaded.Certificate.Certificate) != 2 {
		t.Fatalf("TLS chain length = %d, want leaf+CA", len(loaded.Certificate.Certificate))
	}
	leaf, err := x509.ParseCertificate(loaded.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Fatal("relay/issuer leaf must not be a CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf does not verify against ca.pem: %v", err)
	}
	chainCA, err := x509.ParseCertificate(loaded.Certificate.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chainCA.Raw, caCertificate.Raw) {
		t.Fatal("tls-cert.pem chain CA does not match ca.pem")
	}
	if got := auroracrypto.PreHash(leaf.RawSubjectPublicKeyInfo); !bytes.Equal(loaded.Deployment.Template().OriginSPKIHash, got) {
		t.Fatal("cover template no longer pins the leaf SPKI after the CA chain change")
	}

	// The minted trust file must round-trip through the production parser.
	trustEncoded, err := os.ReadFile(filepath.Join(dir, FileNativeProvisioningTrust))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := client.ParseNativeProvisioningTrust(trustEncoded)
	if err != nil {
		t.Fatalf("minted trust file rejected: %v", err)
	}
	canonical, err := client.EncodeNativeProvisioningTrust(trusted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(trustEncoded, canonical) {
		t.Fatal("minted trust file is not canonical")
	}
	deployments, err := trusted.DeploymentTrusts()
	if err != nil {
		t.Fatal(err)
	}
	if len(deployments) != 1 {
		t.Fatalf("deployment trusts = %d, want 1 (deployment trust is mandatory)", len(deployments))
	}

	// The minted wallet must parse with the minted trust and reserve entries.
	walletEncoded, err := os.ReadFile(filepath.Join(dir, FileWallet))
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := client.ParseNativeProvisioningWalletWithTrust(walletEncoded, trusted, time.Now().UTC())
	if err != nil {
		t.Fatalf("minted wallet rejected: %v", err)
	}
	defer wallet.Zero()
	reservation, err := wallet.Reserve(nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reservation.Zero()
	second, err := wallet.Reserve(nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	second.Zero()
	if _, err := wallet.Reserve(nil, time.Now().UTC()); err == nil {
		t.Fatal("third reservation from a two-entry wallet succeeded")
	}
}

func TestWriteToRefusesOverwrite(t *testing.T) {
	material := mintForTest(t, nil)
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	second := mintForTest(t, nil)
	defer second.Zero()
	if err := second.WriteTo(dir); err == nil {
		t.Fatal("second mint overwrote an existing deployment")
	}
}

func TestWriteToRejectsInvalidDir(t *testing.T) {
	material := mintForTest(t, nil)
	defer material.Zero()
	for _, dir := range []string{"", "  ", ".", string(filepath.Separator)} {
		if err := material.WriteTo(dir); err == nil {
			t.Fatalf("directory %q was accepted", dir)
		}
	}
}

func TestLoadRejectsMissingAndTamperedMaterial(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing"), time.Now()); err == nil {
		t.Fatal("missing deployment directory loaded")
	}
	material := mintForTest(t, nil)
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	// Tamper: replace the descriptor hash with the template file bytes.
	templateBytes, err := os.ReadFile(filepath.Join(dir, FileCoverTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileRelayDescriptorHash), templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, time.Now()); err == nil {
		t.Fatal("deployment with tampered descriptor hash loaded")
	}
}

// TestLoadRejectsTamperedCA fails closed when the minted CA hierarchy is
// tampered with: serve must never present a chain that does not verify
// against the minted ca.pem.
func TestLoadRejectsTamperedCA(t *testing.T) {
	newDir := func(t *testing.T) string {
		t.Helper()
		material := mintForTest(t, nil)
		defer material.Zero()
		dir := filepath.Join(t.TempDir(), "deployment")
		if err := material.WriteTo(dir); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("ca replaced with a different CA", func(t *testing.T) {
		dir := newDir(t)
		_, foreignCAPEM, foreignKeyPEM, _, foreignKey, err := mintLabCA(time.Now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		zeroLabECDSAKey(foreignKey)
		zeroLabBytes(foreignKeyPEM)
		if err := os.WriteFile(filepath.Join(dir, FileCA), foreignCAPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, time.Now()); err == nil {
			t.Fatal("deployment loaded with a foreign ca.pem")
		}
	})

	t.Run("ca replaced with the leaf certificate", func(t *testing.T) {
		dir := newDir(t)
		chainPEM, err := os.ReadFile(filepath.Join(dir, FileTLSCertificate))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(chainPEM)
		if block == nil {
			t.Fatal("tls-cert.pem did not parse")
		}
		leafOnly := pem.EncodeToMemory(block)
		if err := os.WriteFile(filepath.Join(dir, FileCA), leafOnly, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, time.Now()); err == nil {
			t.Fatal("deployment loaded with a non-CA ca.pem")
		}
	})

	t.Run("chain missing the CA", func(t *testing.T) {
		dir := newDir(t)
		chainPEM, err := os.ReadFile(filepath.Join(dir, FileTLSCertificate))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(chainPEM)
		if block == nil {
			t.Fatal("tls-cert.pem did not parse")
		}
		leafOnly := pem.EncodeToMemory(block)
		if err := os.WriteFile(filepath.Join(dir, FileTLSCertificate), leafOnly, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir, time.Now()); err == nil {
			t.Fatal("deployment loaded with a chain missing the lab CA")
		}
	})
}

func TestLoadRejectsTamperedManifestWarning(t *testing.T) {
	material := mintForTest(t, nil)
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, FileManifest)
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(encoded, []byte("LOCAL LAB TESTING ONLY"), []byte("PRODUCTION READY      "), 1)
	if bytes.Equal(encoded, tampered) {
		t.Fatal("manifest warning replacement failed")
	}
	if err := os.WriteFile(manifestPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, time.Now()); err == nil {
		t.Fatal("manifest without the lab-only warning loaded")
	}
}

func TestNewIssuerCarrierHandlerValidation(t *testing.T) {
	if _, err := NewIssuerCarrierHandler(nil, IssuerCarrierPath); err == nil {
		t.Fatal("nil issuer service was accepted")
	}
	service, err := issuerd.NewHarnessService(uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewIssuerCarrierHandler(service, ""); err == nil {
		t.Fatal("empty carrier path was accepted")
	}
	handler, err := NewIssuerCarrierHandler(service, IssuerCarrierPath)
	if err != nil {
		t.Fatal(err)
	}

	// Unknown paths and wrong methods must be cover-neutral.
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, IssuerCarrierPath, nil),
		httptest.NewRequest(http.MethodPost, "/other", nil),
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", request.Method, request.URL.Path, recorder.Code)
		}
	}

	// A valid carrier issue request must complete against the issuer service.
	nonce := bytes.Repeat([]byte{0x44}, 32)
	redemption := bytes.Repeat([]byte{0x45}, 48)
	expiry := uint64(time.Now().Add(5 * time.Minute).Unix())
	payload, err := carrier.EncodeIssueRequest(nonce, redemption, expiry)
	if err != nil {
		t.Fatal(err)
	}
	body := carrier.Encode(carrier.BlindRSAIssueRequest, payload)
	request := httptest.NewRequest(http.MethodPost, IssuerCarrierPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/octet-stream")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("issue response = status=%d content_type=%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	kind, proofPayload, err := carrier.Decode(recorder.Body.Bytes())
	if err != nil || kind != carrier.BlindRSAIssueResponse || len(proofPayload) == 0 {
		t.Fatalf("issue response carrier = kind=%d err=%v", kind, err)
	}

	// Malformed bodies must fail closed with a bounded error.
	request = httptest.NewRequest(http.MethodPost, IssuerCarrierPath, strings.NewReader("junk"))
	request.Header.Set("Content-Type", "application/octet-stream")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed issue request = %d, want 400", recorder.Code)
	}
}

func TestServerRequiresCompleteMaterial(t *testing.T) {
	if _, err := NewServer(nil, ServerOptions{}); err == nil {
		t.Fatal("nil loaded material was accepted")
	}
	if _, err := NewServer(&Loaded{}, ServerOptions{}); err == nil {
		t.Fatal("empty loaded material was accepted")
	}
	material := mintForTest(t, nil)
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(loaded, ServerOptions{PublicAddress: "127.0.0.1:9443", DNSUpstream: "127.0.0.1:53"}); err == nil {
		t.Fatal("loopback public address was accepted by the production first-hop validation")
	}
	if _, err := NewServer(loaded, ServerOptions{PublicAddress: "0.0.0.0:9443", DNSUpstream: "dns.example:53"}); err == nil {
		t.Fatal("non-numeric DNS upstream was accepted")
	}
}
