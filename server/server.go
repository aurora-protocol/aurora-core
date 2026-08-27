package server

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/relay"
)

type HarnessOptions struct {
	NowUnix         uint64
	CoverBody       []byte
	CoverOrigin     http.Handler
	PacketExchanger PacketExchanger
	SpentTokenCache admission.ReplayCache
}

type Options struct {
	Issuer             *issuerd.Service
	Origin             relay.Origin
	CoverOrigin        http.Handler
	PacketExchanger    PacketExchanger
	PacketExchangePath string
}

type ReadinessReport struct {
	Passed                  bool
	CoverEndpoint           bool
	CoverNeutralUnknownPath bool
	CoverNeutralIssuerPath  bool
	CoverNeutralHealthPath  bool
	IssuerMetadataCarrier   bool
	BlindRSAIssueCarrier    bool
	PacketExchangeEndpoint  bool
	Findings                []string
}

func NewHarnessHandler(opts HarnessOptions) (http.Handler, error) {
	now := NormalizeHarnessNow(opts.NowUnix)
	service, err := issuerd.NewHarnessServiceWithOptions(now, issuerd.ServiceOptions{
		SpentTokenCache: opts.SpentTokenCache,
	})
	if err != nil {
		return nil, err
	}
	coverBody := append([]byte(nil), opts.CoverBody...)
	if len(coverBody) == 0 {
		coverBody = []byte("<html><body>ok</body></html>")
	}
	packetExchanger := opts.PacketExchanger
	if packetExchanger == nil {
		packetExchanger = LoopbackPacketExchanger{}
	}
	return NewHandler(Options{
		Issuer:          service,
		PacketExchanger: packetExchanger,
		Origin: relay.StaticOrigin{
			Status: http.StatusOK,
			Body:   coverBody,
		},
		CoverOrigin: opts.CoverOrigin,
	}), nil
}

// NewHandler builds the lab/readiness carrier handler used by native adapters
// and interoperability checks. It is not the production first-hop listener and
// MUST NOT be exposed as production cover issuance unless a gateway-owned,
// verified cover-slot admission predicate runs before this handler. Requests
// that fail carrier validation fall through to byte-identical cover behaviour.
func NewHandler(opts Options) http.Handler {
	mux := http.NewServeMux()
	issuer := serviceIssuerCarrier{service: opts.Issuer}
	packetPath := opts.PacketExchangePath
	if packetPath == "" {
		packetPath = DefaultPacketExchangePath
	}
	mux.HandleFunc(packetPath, func(w http.ResponseWriter, r *http.Request) {
		if !isCarrierRequest(r) {
			serveCoverRequest(w, r, opts.Origin, opts.CoverOrigin)
			return
		}
		serveCoverCarrier(w, r, opts.Origin, opts.CoverOrigin, opts.PacketExchanger, issuer)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serveCoverRequest(w, r, opts.Origin, opts.CoverOrigin)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func RunReadinessHarness(nowUnix uint64) (ReadinessReport, error) {
	nowUnix = NormalizeHarnessNow(nowUnix)
	handler, err := NewHarnessHandler(HarnessOptions{NowUnix: nowUnix})
	if err != nil {
		return ReadinessReport{}, err
	}
	report := ReadinessReport{Passed: true}

	cover := serveHarnessRequest(handler, http.MethodGet, "/cover", nil)
	report.CoverEndpoint = cover.status == http.StatusOK && bytes.Contains(cover.body, []byte("<html>"))
	report.require(report.CoverEndpoint, "cover endpoint failed")

	unknown := serveHarnessRequest(handler, http.MethodPost, "/ordinary-origin-path", []byte("probe"))
	report.CoverNeutralUnknownPath = unknown.status == cover.status && bytes.Equal(unknown.body, cover.body)
	report.require(report.CoverNeutralUnknownPath, "unknown path did not map to cover origin")

	// The former fixed public issuer and health paths MUST now be
	// byte-identical to an ordinary origin probe (no distinguishable public
	// Aurora path, Section 8 cover-neutrality).
	legacyIssuer := serveHarnessRequest(handler, http.MethodGet, "/issuer/issuer-metadata", nil)
	report.CoverNeutralIssuerPath = legacyIssuer.status == cover.status && bytes.Equal(legacyIssuer.body, cover.body)
	report.require(report.CoverNeutralIssuerPath, "legacy issuer path is distinguishable from cover")

	legacyHealth := serveHarnessRequest(handler, http.MethodGet, "/healthz", nil)
	report.CoverNeutralHealthPath = legacyHealth.status == cover.status && bytes.Equal(legacyHealth.body, cover.body)
	report.require(report.CoverNeutralHealthPath, "legacy health path is distinguishable from cover")

	// The readiness adapter exercises issuance only over its opaque diagnostic
	// carrier, never over a fixed legacy issuer path. This checks adapter
	// interoperability and probe fallback; it is not evidence that the carrier
	// supplies the verified cover-slot gate required for production issuance.
	metaType, metaPayload, _ := doCarrierExchangeHandler(handler, CarrierIssuerMetadataReq, nil)
	if metaType == CarrierIssuerMetadataResp {
		if encoded, hash, decodeErr := DecodeCarrierMetadataResponse(metaPayload); decodeErr == nil && len(encoded) > 0 && len(hash) == carrierMetadataHashLen {
			report.IssuerMetadataCarrier = true
		}
	}
	report.require(report.IssuerMetadataCarrier, "issuer metadata carrier failed")

	issueRequest, err := EncodeCarrierIssueRequest(repeatedByte(0x44, 32), repeatedByte(0x45, 48), nowUnix+100)
	if err != nil {
		return ReadinessReport{}, err
	}
	issueType, issuePayload, _ := doCarrierExchangeHandler(handler, CarrierBlindRSAIssueReq, issueRequest)
	report.BlindRSAIssueCarrier = issueType == CarrierBlindRSAIssueResp && len(issuePayload) > 0
	report.require(report.BlindRSAIssueCarrier, "Blind RSA issue carrier failed")

	packetRequest, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		return ReadinessReport{}, err
	}
	packetType, packetPayload, _ := doCarrierExchangeHandler(handler, CarrierPacketBatch, packetRequest)
	if packetType == CarrierPacketBatch {
		if packetResponse, decodeErr := DecodePacketBatch(packetPayload); decodeErr == nil &&
			len(packetResponse.Packets) == 1 &&
			bytes.Equal(packetResponse.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) &&
			packetResponse.ProtocolNumbers[0] == 2 {
			report.PacketExchangeEndpoint = true
		}
	}
	report.require(report.PacketExchangeEndpoint, "packet exchange carrier failed")

	return report, nil
}

func ListenAndServe(addr string, handler http.Handler) error {
	if addr == "" {
		return fmt.Errorf("server: listen address is required")
	}
	if handler == nil {
		return fmt.Errorf("server: handler is required")
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func ListenAndServeTLS(addr string, handler http.Handler, certFile, keyFile string) error {
	if addr == "" {
		return fmt.Errorf("server: listen address is required")
	}
	if handler == nil {
		return fmt.Errorf("server: handler is required")
	}
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("server: TLS certificate and key are required")
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	err := server.ListenAndServeTLS(certFile, keyFile)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (r *ReadinessReport) require(ok bool, finding string) {
	if ok {
		return
	}
	r.Passed = false
	r.Findings = append(r.Findings, finding)
}

func serveCoverOrigin(w http.ResponseWriter, origin relay.Origin) {
	if origin == nil {
		http.NotFound(w, nil)
		return
	}
	resp := origin.NormalResponse()
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.WriteHeader(status)
	_, _ = w.Write(resp.Body)
}

func serveCoverRequest(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler) {
	if coverOrigin != nil {
		coverOrigin.ServeHTTP(w, r)
		return
	}
	serveCoverOrigin(w, origin)
}

func serveCoverFailure(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler) {
	if coverOrigin == nil {
		serveCoverOrigin(w, origin)
		return
	}
	sanitized := sanitizedCoverFailureRequest(r)
	if failureOrigin, ok := coverOrigin.(CoverOrigin); ok {
		failureOrigin.ServeFailureHTTP(w, sanitized)
		return
	}
	coverOrigin.ServeHTTP(w, sanitized)
}

func isCarrierRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/octet-stream"
}

type harnessResponse struct {
	status int
	header http.Header
	body   []byte
}

func serveHarnessRequest(handler http.Handler, method, path string, body []byte) harnessResponse {
	return serveHarnessRequestWithContentType(handler, method, path, body, "application/json")
}

func serveHarnessRequestWithContentType(handler http.Handler, method, path string, body []byte, contentType string) harnessResponse {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	out, _ := io.ReadAll(rec.Result().Body)
	return harnessResponse{status: rec.Code, header: rec.Result().Header, body: out}
}

func repeatedByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// NormalizeHarnessNow supplies the deterministic harness time for zero input.
func NormalizeHarnessNow(now uint64) uint64 {
	if now == 0 {
		return 200
	}
	return now
}
