package issuerd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/ops"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestHTTPDaemonReadinessHarnessCoversLiveIssuerSurface(t *testing.T) {
	report, err := RunHTTPReadinessHarness(200)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("issuer HTTP readiness failed: %+v", report)
	}
	for name, passed := range map[string]bool{
		"health":              report.HealthEndpoint,
		"metadata":            report.MetadataEndpoint,
		"blind_rsa":           report.BlindRSAIssueEndpoint,
		"voprf":               report.VOPRFVerifyEndpoint,
		"voprf_fail_closed":   report.VOPRFFailClosedEndpoint,
		"binary_mtls":         report.BinaryVerifierMTLSEndpoint,
		"spend":               report.SpendEndpoint,
		"duplicate_rejected":  report.DuplicateSpendRejected,
		"redacted_failures":   report.RedactedFailureBodies,
		"method_restrictions": report.MethodRestrictions,
	} {
		if !passed {
			t.Fatalf("%s endpoint behavior was not covered: %+v", name, report)
		}
	}
	if len(report.Findings) != 0 {
		t.Fatalf("issuer HTTP readiness reported findings: %+v", report.Findings)
	}
}

func TestDecodeVerifierRequestBodyOwnsAndScrubsInput(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	expected := verifierHTTPTestRequest(t, service, verifierService)
	encoded, err := protocol.Encode(expected)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeVerifierRequestBody(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.TokenAuthenticator, expected.TokenAuthenticator) || !bytes.Equal(decoded.RequestNonce, expected.RequestNonce) {
		t.Fatalf("decoded verifier request = %#v", decoded)
	}
	for index, value := range encoded {
		if value != 0 {
			t.Fatalf("verifier request input byte %d = %x after decode, want zero", index, value)
		}
	}
	heldAuthenticator := decoded.TokenAuthenticator
	heldNonce := decoded.RequestNonce
	zeroIssuerVerifierRequest(&decoded)
	for _, field := range [][]byte{heldAuthenticator, heldNonce} {
		for index, value := range field {
			if value != 0 {
				t.Fatalf("decoded verifier request byte %d = %x after release, want zero", index, value)
			}
		}
	}

	malformed := []byte{0xff, 0xee, 0xdd}
	if _, err := decodeVerifierRequestBody(malformed); err == nil {
		t.Fatal("malformed verifier request was accepted")
	}
	for index, value := range malformed {
		if value != 0 {
			t.Fatalf("malformed verifier request byte %d = %x after decode, want zero", index, value)
		}
	}
}

func TestAppendIssuerdOwnedBytesScrubsReplacedBuffer(t *testing.T) {
	original := []byte{0xa1}
	if cap(original) != len(original) {
		t.Fatal("test buffer must grow")
	}
	updated, err := appendIssuerdOwnedBytes(original, []byte{0xb2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(updated, []byte{0xa1, 0xb2}) {
		t.Fatalf("updated owned bytes = %x", updated)
	}
	if original[0] != 0 {
		t.Fatalf("replaced request buffer byte = %x, want zero", original[0])
	}
}

func TestHTTPDaemonPublishesMetadataIssuesVerifiesAndSpends(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)

	health := serveHTTP(t, handler, http.MethodGet, "/healthz", nil)
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"ready":true`) {
		t.Fatalf("health response = %d %s", health.Code, health.Body.String())
	}

	metadataResponse := serveHTTP(t, handler, http.MethodGet, "/issuer-metadata", nil)
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata response = %d %s", metadataResponse.Code, metadataResponse.Body.String())
	}
	var metadataBody MetadataResponse
	decodeJSON(t, metadataResponse.Body.Bytes(), &metadataBody)
	metadata := service.PublishIssuerMetadata()
	if metadataBody.IssuerMetadataHash != hex.EncodeToString(mustIssuerMetadataHash(t, metadata)) {
		t.Fatalf("metadata hash response mismatch: %+v", metadataBody)
	}

	issueBody := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            300,
	})
	issueResponse := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", issueBody)
	if issueResponse.Code != http.StatusOK {
		t.Fatalf("issue response = %d %s", issueResponse.Code, issueResponse.Body.String())
	}
	var issued IssueResponse
	decodeJSON(t, issueResponse.Body.Bytes(), &issued)
	proofBytes, err := hex.DecodeString(issued.AdmissionProof)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := DecodeAdmissionProofBytes(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, 200); err != nil {
		t.Fatalf("issued proof did not verify: %v", err)
	}

	voprfBody := mustJSON(t, VOPRFVerifyRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       hex.EncodeToString(fill(0x81, 16)),
		RequestAuthPolicyID: 9,
	})
	voprfResponse := serveHTTP(t, handler, http.MethodPost, "/voprf/verify", voprfBody)
	if voprfResponse.Code != http.StatusOK || !strings.Contains(voprfResponse.Body.String(), `"verified":true`) {
		t.Fatalf("voprf response = %d %s", voprfResponse.Code, voprfResponse.Body.String())
	}

	spendResponse := serveHTTP(t, handler, http.MethodPost, "/token/spend", mustJSON(t, SpendRequest(issued)))
	if spendResponse.Code != http.StatusOK || !strings.Contains(spendResponse.Body.String(), `"spent":true`) {
		t.Fatalf("spend response = %d %s", spendResponse.Code, spendResponse.Body.String())
	}
	duplicate := serveHTTP(t, handler, http.MethodPost, "/token/spend", mustJSON(t, SpendRequest(issued)))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate spend response = %d %s", duplicate.Code, duplicate.Body.String())
	}
	if strings.Contains(duplicate.Body.String(), issued.AdmissionProof) || strings.Contains(duplicate.Body.String(), hex.EncodeToString(proof.TokenAuthenticator)) {
		t.Fatalf("duplicate failure leaked proof material: %s", duplicate.Body.String())
	}
}

func TestHTTPDaemonFailsClosedAndRestrictsMethods(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	if got := serveHTTP(t, handler, http.MethodPost, "/issuer-metadata", nil); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST metadata response = %d %s", got.Code, got.Body.String())
	}
	service.SetVOPRFVerifierAvailable(false)
	resp := serveHTTP(t, handler, http.MethodPost, "/voprf/verify", mustJSON(t, VOPRFVerifyRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       hex.EncodeToString(fill(0x81, 16)),
		RequestAuthPolicyID: 9,
	}))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("VOPRF outage response = %d %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "verifier unavailable") || strings.Contains(resp.Body.String(), "RelayBucketID") {
		t.Fatalf("VOPRF outage response not sanitized: %s", resp.Body.String())
	}
}

func TestHTTPDaemonRejectsTrailingJSON(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	body := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            300,
	})
	body = append(body, []byte(`{"second":true}`)...)
	resp := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON response = %d %s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "token_nonce") || strings.Contains(resp.Body.String(), "second") {
		t.Fatalf("trailing JSON failure leaked request details: %s", resp.Body.String())
	}
}

func TestHTTPDaemonRejectsOversizedJSONBody(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	body := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            300,
	})
	body = append(body, []byte(strings.Repeat(" ", 1<<20))...)

	resp := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("oversized JSON response = %d %s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "token_nonce") {
		t.Fatalf("oversized JSON failure leaked request details: %s", resp.Body.String())
	}
}

func TestHTTPDaemonRejectsOversizedStreamingJSONBody(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	body := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            300,
	})
	body = append(body, []byte(strings.Repeat(" ", 1<<20))...)
	request := httptest.NewRequest(http.MethodPost, "/blind-rsa/issue", bytes.NewReader(body))
	request.ContentLength = -1
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized streaming JSON response = %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "token_nonce") {
		t.Fatalf("oversized streaming JSON failure leaked request details: %s", response.Body.String())
	}
}

func TestHTTPDaemonDoesNotSpendTokenAfterRequestCancellation(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x46, 32),
		RedemptionContextHash: fill(0x47, 48),
		ExpiryUnix:            300,
	})
	if err != nil {
		t.Fatal(err)
	}
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, SpendRequest{AdmissionProof: hex.EncodeToString(encodedProof)})

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/token/spend", nil).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Body = &cancelAfterIssuerBodyRead{reader: bytes.NewReader(body), cancel: cancel}
	request.ContentLength = -1
	response := httptest.NewRecorder()
	NewHTTPHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("canceled spend response = %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), hex.EncodeToString(proof.TokenAuthenticator)) {
		t.Fatalf("canceled spend response leaked proof material: %s", response.Body.String())
	}

	completed := serveHTTP(t, NewHTTPHandler(service), http.MethodPost, "/token/spend", body)
	if completed.Code != http.StatusOK {
		t.Fatalf("fresh spend after cancellation = %d %s", completed.Code, completed.Body.String())
	}
}

func TestVerifierHTTPHandlerDoesNotSpendRequestAfterCancellation(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	requestBody, err := protocol.Encode(verifierHTTPTestRequest(t, service, verifierService))
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service.AuthorizeRelayClientKey(verifierService.RequestAuthPolicyID, protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       mustECDSAPublicKeyBytes(t, &clientKey.PublicKey),
	})

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	request.Body = &cancelAfterIssuerBodyRead{reader: bytes.NewReader(requestBody), cancel: cancel}
	request.ContentLength = -1
	request.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{PublicKey: &clientKey.PublicKey}},
	}
	response := httptest.NewRecorder()
	NewVerifierHTTPHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("canceled verifier response = %d %s", response.Code, response.Body.String())
	}

	verified, err := service.VerifyIssuerVerifierRequest(verifierHTTPTestRequest(t, service, verifierService))
	if err != nil {
		t.Fatalf("fresh verifier request after cancellation: %v", err)
	}
	if verified.Decision != registry.VerifierDecisionAccept {
		t.Fatalf("fresh verifier decision = 0x%x, want accept", verified.Decision)
	}
}

func TestVerifierHTTPHandlerExchangesSignedBinaryResponseOverMTLS(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	server, client := startVerifierHTTPTestServer(t, service, &verifierService, true, true)
	defer server.Close()

	req := verifierHTTPTestRequest(t, service, verifierService)
	transport := ops.MTLSIssuerVerifierTransport{Client: client}
	resp, err := transport.ExchangeIssuerVerifier(verifierService, req)
	if err != nil {
		t.Fatalf("binary verifier exchange failed: %v", err)
	}
	if err := ops.ValidateIssuerVerifierResponse(verifierService, req, resp, 200); err != nil {
		t.Fatalf("signed binary verifier response did not validate: %v", err)
	}

	replayed, err := transport.ExchangeIssuerVerifier(verifierService, req)
	if err != nil {
		t.Fatalf("duplicate verifier exchange did not return a signed decision: %v", err)
	}
	if replayed.Decision != registry.VerifierDecisionRejectReplayOrSpent {
		t.Fatalf("duplicate token_spent_key decision = 0x%x, want replay reject", replayed.Decision)
	}
}

func TestVerifierHTTPHandlerRejectsDeclaredOversizedBinaryRequest(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	encoded, err := protocol.Encode(verifierHTTPTestRequest(t, service, verifierService))
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encoded))
	request.ContentLength = maximumVerifierRequestBodyBytes + 1
	request.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{PublicKey: &clientKey.PublicKey}},
	}
	response := httptest.NewRecorder()
	NewVerifierHTTPHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("declared oversized verifier request response = %d %s", response.Code, response.Body.String())
	}
}

func TestVerifierHTTPHandlerFailsClosedWithoutService(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	encoded, err := protocol.Encode(verifierHTTPTestRequest(t, service, verifierService))
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encoded))
	request.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{PublicKey: &clientKey.PublicKey}},
	}
	response := httptest.NewRecorder()
	NewVerifierHTTPHandler(nil).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil verifier service response = %d %s", response.Code, response.Body.String())
	}
}

func TestVerifierHTTPHandlerRequiresMTLSClientCertificate(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	server, client := startVerifierHTTPTestServer(t, service, &verifierService, false, false)
	defer server.Close()

	_, err = ops.MTLSIssuerVerifierTransport{Client: client}.ExchangeIssuerVerifier(verifierService, verifierHTTPTestRequest(t, service, verifierService))
	if err == nil {
		t.Fatalf("verifier handler accepted a request without relay mTLS client authentication")
	}
}

func TestVerifierHTTPHandlerRejectsUnauthorizedMTLSClientCertificate(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	server, client := startVerifierHTTPTestServer(t, service, &verifierService, true, false)
	defer server.Close()

	_, err = ops.MTLSIssuerVerifierTransport{Client: client}.ExchangeIssuerVerifier(verifierService, verifierHTTPTestRequest(t, service, verifierService))
	if err == nil {
		t.Fatalf("verifier handler accepted an unauthorized relay mTLS client certificate")
	}
}

func TestVerifierServiceRejectsEmptyAuthenticatorBeforeSpending(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	req := verifierHTTPTestRequest(t, service, verifierService)
	emptyAuthenticator := req
	emptyAuthenticator.TokenAuthenticator = nil
	if _, err := service.VerifyIssuerVerifierRequest(emptyAuthenticator); err == nil {
		t.Fatalf("verifier service accepted an empty token authenticator")
	}
	resp, err := service.VerifyIssuerVerifierRequest(req)
	if err != nil {
		t.Fatalf("valid verifier request was rejected after empty-authenticator attempt: %v", err)
	}
	if resp.Decision != registry.VerifierDecisionAccept {
		t.Fatalf("token_spent_key was consumed by rejected empty-authenticator request: decision=0x%x", resp.Decision)
	}
}

func TestVerifierServiceRejectsExpiredRequestBeforeSpending(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	req := verifierHTTPTestRequest(t, service, verifierService)
	expired := req
	expired.ReplayEpochValidUntilUnix = 199
	if _, err := service.VerifyIssuerVerifierRequest(expired); err == nil {
		t.Fatalf("verifier service accepted an expired replay epoch")
	}
	resp, err := service.VerifyIssuerVerifierRequest(req)
	if err != nil {
		t.Fatalf("valid verifier request was rejected after expired request attempt: %v", err)
	}
	if resp.Decision != registry.VerifierDecisionAccept {
		t.Fatalf("token_spent_key was consumed by rejected expired request: decision=0x%x", resp.Decision)
	}
}

func serveHTTP(t *testing.T, handler http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

type cancelAfterIssuerBodyRead struct {
	reader *bytes.Reader
	cancel context.CancelFunc
	once   sync.Once
}

func (r *cancelAfterIssuerBodyRead) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.once.Do(r.cancel)
	}
	return n, err
}

func (r *cancelAfterIssuerBodyRead) Close() error { return nil }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeJSON(t *testing.T, raw []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode JSON %q: %v", string(raw), err)
	}
}

func mustIssuerMetadataHash(t *testing.T, metadata protocol.IssuerMetadata) []byte {
	t.Helper()
	hash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func startVerifierHTTPTestServer(t *testing.T, service *Service, verifierService *protocol.IssuerVerifierServiceRecord, withClientCertificate bool, authorizeClientCertificate bool) (*httptest.Server, *http.Client) {
	t.Helper()
	signer := service.verifierServiceSigners[string(verifierService.ServiceID)]
	if signer == nil {
		t.Fatal("harness service did not retain verifier service signer")
	}
	serverCert := testVerifierTLSCertificate(t, signer)
	clientSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := testVerifierTLSCertificate(t, clientSigner)
	if authorizeClientCertificate {
		service.AuthorizeRelayClientKey(verifierService.RequestAuthPolicyID, protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       mustECDSAPublicKeyBytes(t, &clientSigner.PublicKey),
		})
	}

	server := httptest.NewUnstartedServer(NewVerifierHTTPHandler(service))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	}
	verifierService.ServiceLocator = protocol.RoutingRecord{
		RoutingRecordID:   fill(0x70, 16),
		TransportFamilyID: registry.IssuerVerifierVOPRFMTLS13,
		LocatorType:       registry.LocatorAuthority,
		LocatorBody:       []byte(server.Listener.Addr().String()),
		Priority:          1,
		NotBeforeUnix:     100,
		NotAfterUnix:      1000,
	}
	roots := x509.NewCertPool()
	roots.AddCert(serverCert.Leaf)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
	}
	if withClientCertificate {
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	server.StartTLS()
	return server, client
}

func mustECDSAPublicKeyBytes(t testing.TB, key *ecdsa.PublicKey) []byte {
	t.Helper()
	encoded, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func verifierHTTPTestRequest(t *testing.T, service *Service, verifierService protocol.IssuerVerifierServiceRecord) protocol.IssuerVerifierRequest {
	t.Helper()
	metadata := service.PublishIssuerMetadata()
	var tokenKeyID []byte
	for _, mapping := range metadata.TokenKeyMappings {
		if mapping.ProofType == registry.ProofVOPRFP384SHA384 {
			tokenKeyID = append([]byte(nil), mapping.TokenKeyID...)
			break
		}
	}
	if tokenKeyID == nil {
		t.Fatal("harness metadata lacks VOPRF token key")
	}
	return protocol.IssuerVerifierRequest{
		RequestVersion:            registry.Version20,
		ServiceID:                 append([]byte(nil), verifierService.ServiceID...),
		IssuerID:                  append([]byte(nil), metadata.IssuerID...),
		IssuerMetadataHash:        mustIssuerMetadataHash(t, metadata),
		RelayDescriptorHash:       fill(0x91, 48),
		RelayBucketID:             append([]byte(nil), metadata.RelayBucketScopes[0].RelayBucketID...),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ProofType:                 registry.ProofVOPRFP384SHA384,
		TokenKeyID:                tokenKeyID,
		TokenNonce:                fill(0x92, 32),
		ChallengeDigest:           fill(0x93, 32),
		AuthenticatorInputHash:    fill(0x94, 48),
		TokenAuthenticator:        []byte("private-voprf-authenticator"),
		TokenSpentKey:             fill(0x95, 48),
		ReplayEpochID:             11,
		ReplayEpochValidUntilUnix: 400,
		RequestNonce:              fill(0x96, 32),
		RequestTimeUnix:           200,
	}
}

func testVerifierTLSCertificate(t *testing.T, priv *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}
