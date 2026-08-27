package issuerd

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/protocol"
)

const (
	productionBlindRSABackendRequestBytes    = 1 + carrier.TokenNonceLength + carrier.RedemptionContextLength + 8
	maximumProductionBlindRSABackendResponse = 1 << 20
	productionBlindRSABackendFailureStatus   = http.StatusServiceUnavailable
	// MaximumProductionBlindRSABackendConcurrency is the production ceiling for
	// simultaneous private-key operations in one backend process.
	MaximumProductionBlindRSABackendConcurrency = 64
)

// ProductionBlindRSABackendOptions bounds the private gateway-to-issuer
// backend. This backend is not a public cover-slot admission mechanism.
type ProductionBlindRSABackendOptions struct {
	MaxConcurrentIssues int
}

type productionBlindRSABackendHandler struct {
	service *Service
	issue   func(IssueBlindRSA2048Request) (protocol.AdmissionProof, error)
	slots   chan struct{}
}

// NewProductionBlindRSABackendHandler builds the single-operation private
// Blind-RSA backend used by an authenticated cover gateway. The caller must
// still place the public carrier behind a verified, nontrivial cover-slot
// admission predicate; backend mTLS does not provide that public predicate.
func NewProductionBlindRSABackendHandler(service *Service, options ProductionBlindRSABackendOptions) (http.Handler, error) {
	if service == nil || service.allowHarnessHTTPEndpoints || !service.ready() {
		return nil, fmt.Errorf("issuerd: ready production Blind RSA service is required")
	}
	if err := validateProductionBlindRSAMetadata(service.metadata); err != nil {
		return nil, fmt.Errorf("issuerd: production backend service: %w", err)
	}
	if options.MaxConcurrentIssues <= 0 || options.MaxConcurrentIssues > MaximumProductionBlindRSABackendConcurrency {
		return nil, fmt.Errorf("issuerd: production backend signing concurrency must be between 1 and %d", MaximumProductionBlindRSABackendConcurrency)
	}
	return &productionBlindRSABackendHandler{
		service: service,
		issue:   service.IssueBlindRSA2048,
		slots:   make(chan struct{}, options.MaxConcurrentIssues),
	}, nil
}

func (h *productionBlindRSABackendHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if w == nil {
		return
	}
	if h == nil || h.service == nil || h.issue == nil || h.slots == nil || !isAuthenticatedProductionBackendRequest(request) {
		writeProductionBackendFailure(w)
		return
	}
	body, err := readProductionBackendRequestBody(request)
	if err != nil {
		writeProductionBackendFailure(w)
		return
	}
	defer zeroIssuerdOwnedBytes(body)
	kind, payload, err := carrier.Decode(body)
	if err != nil || kind != carrier.BlindRSAIssueRequest {
		writeProductionBackendFailure(w)
		return
	}
	tokenNonce, redemptionContextHash, expiryUnix, err := carrier.DecodeIssueRequest(payload)
	if err != nil {
		writeProductionBackendFailure(w)
		return
	}
	defer zeroIssuerdOwnedBytes(tokenNonce)
	defer zeroIssuerdOwnedBytes(redemptionContextHash)

	if err := acquireProductionBackendSlot(request.Context(), h.slots); err != nil {
		writeProductionBackendFailure(w)
		return
	}
	defer releaseProductionBackendSlot(h.slots)
	if request.Context().Err() != nil || !h.service.ready() {
		writeProductionBackendFailure(w)
		return
	}
	proof, err := h.issue(IssueBlindRSA2048Request{
		TokenNonce:            tokenNonce,
		RedemptionContextHash: redemptionContextHash,
		ExpiryUnix:            expiryUnix,
	})
	if err != nil {
		zeroProductionBackendAdmissionProof(&proof)
		writeProductionBackendFailure(w)
		return
	}
	defer zeroProductionBackendAdmissionProof(&proof)
	if request.Context().Err() != nil {
		writeProductionBackendFailure(w)
		return
	}
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		writeProductionBackendFailure(w)
		return
	}
	defer zeroIssuerdOwnedBytes(encodedProof)
	if len(encodedProof) == 0 || len(encodedProof) >= maximumProductionBlindRSABackendResponse {
		writeProductionBackendFailure(w)
		return
	}
	response := carrier.Encode(carrier.BlindRSAIssueResponse, encodedProof)
	defer zeroIssuerdOwnedBytes(response)
	if len(response) > maximumProductionBlindRSABackendResponse || request.Context().Err() != nil {
		writeProductionBackendFailure(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func isAuthenticatedProductionBackendRequest(request *http.Request) bool {
	if request == nil || request.Context().Err() != nil || request.Method != http.MethodPost || request.URL == nil || request.Body == nil {
		return false
	}
	if request.URL.Path != "/" || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.RequestURI != "/" {
		return false
	}
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/octet-stream" || len(parameters) != 0 {
		return false
	}
	state := request.TLS
	if request.ProtoMajor != 2 || state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || state.DidResume {
		return false
	}
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return false
	}
	return bytes.Equal(state.PeerCertificates[0].Raw, state.VerifiedChains[0][0].Raw)
}

func readProductionBackendRequestBody(request *http.Request) ([]byte, error) {
	if request == nil || request.Body == nil {
		return nil, fmt.Errorf("issuerd: production backend request body is required")
	}
	if request.ContentLength >= 0 && request.ContentLength != productionBlindRSABackendRequestBytes {
		return nil, fmt.Errorf("issuerd: production backend request length is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, productionBlindRSABackendRequestBytes+1))
	if err != nil {
		zeroIssuerdOwnedBytes(body)
		return nil, fmt.Errorf("issuerd: read production backend request: %w", err)
	}
	if len(body) != productionBlindRSABackendRequestBytes {
		zeroIssuerdOwnedBytes(body)
		return nil, fmt.Errorf("issuerd: production backend request length is invalid")
	}
	return body, nil
}

func acquireProductionBackendSlot(ctx context.Context, slots chan struct{}) error {
	if ctx == nil || slots == nil {
		return fmt.Errorf("issuerd: production backend signing slot is unavailable")
	}
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseProductionBackendSlot(slots chan struct{}) {
	if slots != nil {
		<-slots
	}
}

func writeProductionBackendFailure(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(productionBlindRSABackendFailureStatus)
}

func zeroProductionBackendAdmissionProof(proof *protocol.AdmissionProof) {
	if proof == nil {
		return
	}
	for _, field := range [][]byte{
		proof.IssuerID,
		proof.TokenKeyID,
		proof.RelayBucketID,
		proof.TokenScopeID,
		proof.TokenNonce,
		proof.RedemptionContextHash,
		proof.TokenPublicMetadata,
		proof.TokenAuthenticator,
		proof.BindingProof,
	} {
		zeroIssuerdBytes(field)
	}
	for i := range proof.Extensions {
		zeroIssuerdBytes(proof.Extensions[i].Body)
		proof.Extensions[i] = protocol.Extension{}
	}
	*proof = protocol.AdmissionProof{}
}
