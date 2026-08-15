package issuerd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	maximumJSONRequestBodyBytes     int64 = 1 << 20
	maximumVerifierRequestBodyBytes int64 = 1 << 20
)

var (
	errJSONRequestBodyTooLarge = errors.New("issuerd: JSON request body exceeds limit")
	errVerifierRequestTooLarge = errors.New("issuerd: verifier request body exceeds limit")
)

type HTTPReadinessReport struct {
	Passed                     bool
	HealthEndpoint             bool
	MetadataEndpoint           bool
	BlindRSAIssueEndpoint      bool
	VOPRFVerifyEndpoint        bool
	VOPRFFailClosedEndpoint    bool
	BinaryVerifierMTLSEndpoint bool
	SpendEndpoint              bool
	DuplicateSpendRejected     bool
	RedactedFailureBodies      bool
	MethodRestrictions         bool
	Findings                   []string
}

type MetadataResponse struct {
	IssuerMetadata     string `json:"issuer_metadata"`
	IssuerMetadataHash string `json:"issuer_metadata_hash"`
}

type IssueRequest struct {
	TokenNonce            string `json:"token_nonce"`
	RedemptionContextHash string `json:"redemption_context_hash"`
	ExpiryUnix            uint64 `json:"expiry_unix"`
}

type IssueResponse struct {
	AdmissionProof string `json:"admission_proof"`
}

type VOPRFVerifyRequest struct {
	ProofType           uint64 `json:"proof_type"`
	RelayBucketID       string `json:"relay_bucket_id"`
	RequestAuthPolicyID uint64 `json:"request_auth_policy_id"`
}

type VOPRFVerifyResponse struct {
	Verified bool `json:"verified"`
}

type SpendRequest struct {
	AdmissionProof string `json:"admission_proof"`
}

type SpendResponse struct {
	Spent    bool   `json:"spent"`
	SpentKey string `json:"spent_key"`
}

func NewVerifierHTTPHandler(service *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", methodHandler(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		if service == nil || !service.ready() || !hasMutualTLSClientAuth(r) {
			writeError(w, http.StatusServiceUnavailable, "verifier unavailable")
			return
		}
		req, err := decodeVerifierRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid verifier request")
			return
		}
		defer zeroIssuerVerifierRequest(&req)
		if rejectCanceledRequest(w, r) {
			return
		}
		if err := service.AuthorizeVerifierRequestClient(req, r.TLS.PeerCertificates[0]); err != nil {
			writeError(w, http.StatusServiceUnavailable, "verifier unavailable")
			return
		}
		resp, err := service.VerifyIssuerVerifierRequest(req)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "verifier unavailable")
			return
		}
		encoded, err := protocol.Encode(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "verifier unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	}))
	return mux
}

func NewHTTPHandler(service *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", methodHandler(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ready": service != nil && service.ready()})
	}))
	mux.HandleFunc("/issuer-metadata", methodHandler(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		if service == nil || !service.ready() {
			writeError(w, http.StatusServiceUnavailable, "issuer unavailable")
			return
		}
		metadata := service.PublishIssuerMetadata()
		encoded, err := protocol.Encode(metadata)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "metadata unavailable")
			return
		}
		hash, err := auroratrust.IssuerMetadataHash(metadata)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "metadata unavailable")
			return
		}
		writeJSON(w, http.StatusOK, MetadataResponse{
			IssuerMetadata:     hex.EncodeToString(encoded),
			IssuerMetadataHash: hex.EncodeToString(hash),
		})
	}))
	if service == nil || !service.allowHarnessHTTPEndpoints {
		return mux
	}
	mux.HandleFunc("/blind-rsa/issue", methodHandler(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		if service == nil || !service.ready() {
			writeError(w, http.StatusServiceUnavailable, "issuer unavailable")
			return
		}
		var req IssueRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid issue request")
			return
		}
		if rejectCanceledRequest(w, r) {
			return
		}
		nonce, err := decodeHexFixed(req.TokenNonce, 32)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid issue request")
			return
		}
		redemptionContext, err := decodeHexFixed(req.RedemptionContextHash, 48)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid issue request")
			return
		}
		proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
			TokenNonce:            nonce,
			RedemptionContextHash: redemptionContext,
			ExpiryUnix:            req.ExpiryUnix,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, "issue request rejected")
			return
		}
		encoded, err := protocol.Encode(proof)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "issue request failed")
			return
		}
		writeJSON(w, http.StatusOK, IssueResponse{AdmissionProof: hex.EncodeToString(encoded)})
	}))
	mux.HandleFunc("/voprf/verify", methodHandler(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		if service == nil || !service.ready() {
			writeError(w, http.StatusServiceUnavailable, "verifier unavailable")
			return
		}
		var req VOPRFVerifyRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid verifier request")
			return
		}
		if rejectCanceledRequest(w, r) {
			return
		}
		relayBucketID, err := decodeHexFixed(req.RelayBucketID, 16)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid verifier request")
			return
		}
		err = service.VerifyVOPRFRequest(VOPRFVerifierRequest{
			ProofType:           req.ProofType,
			RelayBucketID:       relayBucketID,
			RequestAuthPolicyID: req.RequestAuthPolicyID,
		})
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "verifier unavailable")
			return
		}
		writeJSON(w, http.StatusOK, VOPRFVerifyResponse{Verified: true})
	}))
	mux.HandleFunc("/token/spend", methodHandler(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		if service == nil || !service.ready() {
			writeError(w, http.StatusServiceUnavailable, "issuer unavailable")
			return
		}
		var req SpendRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid spend request")
			return
		}
		if rejectCanceledRequest(w, r) {
			return
		}
		raw, err := hex.DecodeString(req.AdmissionProof)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid spend request")
			return
		}
		proof, err := DecodeAdmissionProofBytes(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid spend request")
			return
		}
		spentKey, err := service.SpendToken(proof)
		if err != nil {
			writeError(w, http.StatusConflict, "token already spent")
			return
		}
		writeJSON(w, http.StatusOK, SpendResponse{Spent: true, SpentKey: hex.EncodeToString(spentKey)})
	}))
	return mux
}

func RunHTTPReadinessHarness(nowUnix uint64) (HTTPReadinessReport, error) {
	service, err := NewHarnessService(nowUnix)
	if err != nil {
		return HTTPReadinessReport{}, err
	}
	handler := NewHTTPHandler(service)
	report := HTTPReadinessReport{}

	health := serveHarnessRequest(handler, http.MethodGet, "/healthz", nil)
	report.HealthEndpoint = health.status == http.StatusOK && containsAll(health.body, []string{`"ready":true`})
	if !report.HealthEndpoint {
		report.addFinding("issuer HTTP health endpoint failed")
	}

	metadata := serveHarnessRequest(handler, http.MethodGet, "/issuer-metadata", nil)
	report.MetadataEndpoint = metadata.status == http.StatusOK && containsAll(metadata.body, []string{"issuer_metadata_hash"})
	if !report.MetadataEndpoint {
		report.addFinding("issuer HTTP metadata endpoint failed")
	}

	issueRequest := IssueRequest{
		TokenNonce:            hex.EncodeToString(repeatedByte(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(repeatedByte(0x45, 48)),
		ExpiryUnix:            nowUnix + 100,
	}
	issue := serveHarnessRequest(handler, http.MethodPost, "/blind-rsa/issue", mustMarshalJSON(issueRequest))
	var issued IssueResponse
	if issue.status == http.StatusOK && json.Unmarshal(issue.body, &issued) == nil && issued.AdmissionProof != "" {
		proofBytes, err := hex.DecodeString(issued.AdmissionProof)
		if err == nil {
			if proof, err := DecodeAdmissionProofBytes(proofBytes); err == nil {
				report.BlindRSAIssueEndpoint = verifyIssuedProof(service, proof, nowUnix) == nil
			}
		}
	}
	if !report.BlindRSAIssueEndpoint {
		report.addFinding("issuer HTTP Blind RSA issue endpoint failed")
	}

	voprfRequest := VOPRFVerifyRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       hex.EncodeToString(repeatedByte(0x81, 16)),
		RequestAuthPolicyID: 9,
	}
	voprf := serveHarnessRequest(handler, http.MethodPost, "/voprf/verify", mustMarshalJSON(voprfRequest))
	report.VOPRFVerifyEndpoint = voprf.status == http.StatusOK && containsAll(voprf.body, []string{`"verified":true`})
	if !report.VOPRFVerifyEndpoint {
		report.addFinding("issuer HTTP VOPRF verify endpoint failed")
	}

	if err := verifyBinaryVerifierMTLSEndpoint(service, nowUnix); err != nil {
		report.addFinding("issuer binary verifier mTLS endpoint failed: " + err.Error())
	} else {
		report.BinaryVerifierMTLSEndpoint = true
	}

	if issued.AdmissionProof != "" {
		spend := serveHarnessRequest(handler, http.MethodPost, "/token/spend", mustMarshalJSON(SpendRequest(issued)))
		report.SpendEndpoint = spend.status == http.StatusOK && containsAll(spend.body, []string{`"spent":true`})
		duplicate := serveHarnessRequest(handler, http.MethodPost, "/token/spend", mustMarshalJSON(SpendRequest(issued)))
		report.DuplicateSpendRejected = duplicate.status == http.StatusConflict
		report.RedactedFailureBodies = report.DuplicateSpendRejected && !containsAll(duplicate.body, []string{issued.AdmissionProof})
	}
	if !report.SpendEndpoint {
		report.addFinding("issuer HTTP spend endpoint failed")
	}
	if !report.DuplicateSpendRejected {
		report.addFinding("issuer HTTP duplicate spend was not rejected")
	}
	if !report.RedactedFailureBodies {
		report.addFinding("issuer HTTP failure body leaked sensitive material")
	}

	service.SetVOPRFVerifierAvailable(false)
	outage := serveHarnessRequest(handler, http.MethodPost, "/voprf/verify", mustMarshalJSON(voprfRequest))
	report.VOPRFFailClosedEndpoint = outage.status == http.StatusServiceUnavailable && containsAll(outage.body, []string{"verifier unavailable"})
	if !report.VOPRFFailClosedEndpoint {
		report.addFinding("issuer HTTP VOPRF outage did not fail closed")
	}

	wrongMethod := serveHarnessRequest(handler, http.MethodPost, "/issuer-metadata", nil)
	report.MethodRestrictions = wrongMethod.status == http.StatusMethodNotAllowed
	if !report.MethodRestrictions {
		report.addFinding("issuer HTTP method restrictions failed")
	}

	report.Passed = report.HealthEndpoint &&
		report.MetadataEndpoint &&
		report.BlindRSAIssueEndpoint &&
		report.VOPRFVerifyEndpoint &&
		report.VOPRFFailClosedEndpoint &&
		report.BinaryVerifierMTLSEndpoint &&
		report.SpendEndpoint &&
		report.DuplicateSpendRejected &&
		report.RedactedFailureBodies &&
		report.MethodRestrictions
	return report, nil
}

func verifyBinaryVerifierMTLSEndpoint(service *Service, nowUnix uint64) error {
	metadata := service.PublishIssuerMetadata()
	if len(metadata.VerifierServices) == 0 {
		return fmt.Errorf("missing verifier service metadata")
	}
	verifierService := metadata.VerifierServices[0]
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	clientPublicKey, err := clientKey.PublicKey.Bytes()
	if err != nil {
		return err
	}
	service.AuthorizeRelayClientKey(verifierService.RequestAuthPolicyID, protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       clientPublicKey,
	})
	verifierRequest, err := harnessIssuerVerifierRequest(service, verifierService, nowUnix)
	if err != nil {
		return err
	}
	encodedRequest, err := protocol.Encode(verifierRequest)
	if err != nil {
		return err
	}
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encodedRequest))
	request.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{PublicKey: &clientKey.PublicKey}},
	}
	response := httptest.NewRecorder()
	NewVerifierHTTPHandler(service).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		return fmt.Errorf("binary verifier status %d", response.Code)
	}
	reader := wire.NewReader(response.Body.Bytes())
	verifierResponse := protocol.DecodeIssuerVerifierResponse(reader)
	if reader.Err() != nil || !reader.EOF() {
		return fmt.Errorf("binary verifier response decode failed")
	}
	return auroratrust.VerifyIssuerVerifierResponse(verifierRequest, verifierService, verifierResponse, nowUnix, 300)
}

func harnessIssuerVerifierRequest(service *Service, verifierService protocol.IssuerVerifierServiceRecord, nowUnix uint64) (protocol.IssuerVerifierRequest, error) {
	metadata := service.PublishIssuerMetadata()
	var tokenKeyID []byte
	for _, mapping := range metadata.TokenKeyMappings {
		if mapping.ProofType == registry.ProofVOPRFP384SHA384 {
			tokenKeyID = append([]byte(nil), mapping.TokenKeyID...)
			break
		}
	}
	if tokenKeyID == nil {
		return protocol.IssuerVerifierRequest{}, fmt.Errorf("missing VOPRF token key")
	}
	metadataHash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		return protocol.IssuerVerifierRequest{}, err
	}
	return protocol.IssuerVerifierRequest{
		RequestVersion:            registry.Version20,
		ServiceID:                 append([]byte(nil), verifierService.ServiceID...),
		IssuerID:                  append([]byte(nil), metadata.IssuerID...),
		IssuerMetadataHash:        metadataHash,
		RelayDescriptorHash:       repeatedByte(0x91, 48),
		RelayBucketID:             append([]byte(nil), metadata.RelayBucketScopes[0].RelayBucketID...),
		RouteInstanceID:           77,
		HopIndex:                  1,
		ProofType:                 registry.ProofVOPRFP384SHA384,
		TokenKeyID:                tokenKeyID,
		TokenNonce:                repeatedByte(0x92, 32),
		ChallengeDigest:           repeatedByte(0x93, 32),
		AuthenticatorInputHash:    repeatedByte(0x94, 48),
		TokenAuthenticator:        []byte("private-voprf-authenticator"),
		TokenSpentKey:             repeatedByte(0x95, 48),
		ReplayEpochID:             11,
		ReplayEpochValidUntilUnix: nowUnix + 200,
		RequestNonce:              repeatedByte(0x96, 32),
		RequestTimeUnix:           nowUnix,
	}, nil
}

func DecodeAdmissionProofBytes(raw []byte) (protocol.AdmissionProof, error) {
	reader := wire.NewReader(raw)
	proof := protocol.DecodeAdmissionProof(reader)
	if reader.Err() != nil {
		return protocol.AdmissionProof{}, reader.Err()
	}
	if !reader.EOF() {
		return protocol.AdmissionProof{}, fmt.Errorf("issuerd: trailing admission proof bytes")
	}
	return proof, nil
}

func (s *Service) ready() bool {
	nowUnix := s.currentUnix()
	if s == nil || nowUnix == 0 || s.blindRSAKey == nil || s.spentTokens == nil || len(s.metadata.IssuerID) != 16 || nowUnix < s.metadata.ValidFromUnix || nowUnix >= s.metadata.ValidUntilUnix {
		return false
	}
	if err := validateCurrentIssuanceScope(s.metadata, s.issuanceScope, s.issuanceOriginInfoPolicyID, nowUnix); err != nil {
		return false
	}
	return validateProductionBlindRSAKey(s.metadata, s.blindRSATokenKeyDER, nowUnix) == nil
}

func verifyIssuedProof(service *Service, proof protocol.AdmissionProof, nowUnix uint64) error {
	return admission.VerifyBlindRSA2048WithIssuerMetadata(proof, service.PublishIssuerMetadata(), nowUnix)
}

func methodHandler(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if rejectCanceledRequest(w, r) {
			return
		}
		handler(w, r)
	}
}

func rejectCanceledRequest(w http.ResponseWriter, r *http.Request) bool {
	if r != nil && r.Context().Err() == nil {
		return false
	}
	writeError(w, http.StatusRequestTimeout, "request canceled")
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func hasMutualTLSClientAuth(r *http.Request) bool {
	return r != nil &&
		r.TLS != nil &&
		r.TLS.Version == tls.VersionTLS13 &&
		len(r.TLS.PeerCertificates) > 0
}

func decodeVerifierRequest(r *http.Request) (protocol.IssuerVerifierRequest, error) {
	if r == nil || r.Body == nil {
		return protocol.IssuerVerifierRequest{}, fmt.Errorf("issuerd: missing verifier request body")
	}
	if r.ContentLength > maximumVerifierRequestBodyBytes {
		return protocol.IssuerVerifierRequest{}, errVerifierRequestTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumVerifierRequestBodyBytes+1))
	if err != nil {
		zeroIssuerdBytes(body)
		return protocol.IssuerVerifierRequest{}, err
	}
	if len(body) > int(maximumVerifierRequestBodyBytes) {
		zeroIssuerdBytes(body)
		return protocol.IssuerVerifierRequest{}, errVerifierRequestTooLarge
	}
	return decodeVerifierRequestBody(body)
}

func decodeVerifierRequestBody(body []byte) (protocol.IssuerVerifierRequest, error) {
	defer zeroIssuerdBytes(body)
	reader := wire.NewReader(body)
	req := protocol.DecodeIssuerVerifierRequest(reader)
	if reader.Err() != nil || !reader.EOF() {
		zeroIssuerVerifierRequest(&req)
		return protocol.IssuerVerifierRequest{}, fmt.Errorf("issuerd: invalid verifier request")
	}
	return req, nil
}

func zeroIssuerVerifierRequest(request *protocol.IssuerVerifierRequest) {
	if request == nil {
		return
	}
	for _, field := range [][]byte{
		request.ServiceID,
		request.IssuerID,
		request.IssuerMetadataHash,
		request.RelayDescriptorHash,
		request.RelayBucketID,
		request.TokenKeyID,
		request.TokenNonce,
		request.ChallengeDigest,
		request.AuthenticatorInputHash,
		request.TokenAuthenticator,
		request.TokenSpentKey,
		request.RequestNonce,
	} {
		zeroIssuerdBytes(field)
	}
	*request = protocol.IssuerVerifierRequest{}
}

func zeroIssuerdBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func decodeJSONBody(r *http.Request, out any) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("issuerd: missing JSON request body")
	}
	if r.ContentLength > maximumJSONRequestBodyBytes {
		return errJSONRequestBodyTooLarge
	}
	limitedBody := &io.LimitedReader{
		R: r.Body,
		N: maximumJSONRequestBodyBytes + 1,
	}
	decoder := json.NewDecoder(limitedBody)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		if limitedBody.N == 0 {
			return errJSONRequestBodyTooLarge
		}
		return err
	}
	if limitedBody.N == 0 {
		return errJSONRequestBodyTooLarge
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if limitedBody.N == 0 {
			return errJSONRequestBodyTooLarge
		}
		return fmt.Errorf("issuerd: trailing JSON content")
	}
	if limitedBody.N == 0 {
		return errJSONRequestBodyTooLarge
	}
	return nil
}

func decodeHexFixed(value string, length int) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != length {
		return nil, fmt.Errorf("issuerd: hex field length %d, want %d", len(decoded), length)
	}
	return decoded, nil
}

type harnessResponse struct {
	status int
	body   []byte
}

func serveHarnessRequest(handler http.Handler, method, target string, body []byte) harnessResponse {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return harnessResponse{status: response.Code, body: response.Body.Bytes()}
}

func mustMarshalJSON(value any) []byte {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return out
}

func containsAll(body []byte, values []string) bool {
	text := string(body)
	for _, value := range values {
		if !strings.Contains(text, value) {
			return false
		}
	}
	return true
}

func (r *HTTPReadinessReport) addFinding(finding string) {
	r.Findings = append(r.Findings, finding)
}
