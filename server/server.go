package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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
	HealthEndpoint          bool
	CoverEndpoint           bool
	IssuerMetadataEndpoint  bool
	BlindRSAIssueEndpoint   bool
	PacketExchangeEndpoint  bool
	CoverNeutralUnknownPath bool
	Findings                []string
}

func NewHarnessHandler(opts HarnessOptions) (http.Handler, error) {
	now := normalizeHarnessNow(opts.NowUnix)
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

func NewHandler(opts Options) http.Handler {
	mux := http.NewServeMux()
	issuerHandler := issuerd.NewHTTPHandler(opts.Issuer)
	mux.Handle("/issuer/", http.StripPrefix("/issuer", issuerHandler))
	if opts.PacketExchanger != nil {
		packetPath := opts.PacketExchangePath
		if packetPath == "" {
			packetPath = DefaultPacketExchangePath
		}
		mux.HandleFunc(packetPath, func(w http.ResponseWriter, r *http.Request) {
			if !isPacketExchangeRequest(r) {
				serveCoverRequest(w, r, opts.Origin, opts.CoverOrigin)
				return
			}
			servePacketExchange(w, r, opts.Origin, opts.CoverOrigin, opts.PacketExchanger)
		})
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{
			"ready":  opts.Issuer != nil && coverReady(opts),
			"issuer": opts.Issuer != nil,
			"cover":  coverReady(opts),
		})
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
	nowUnix = normalizeHarnessNow(nowUnix)
	handler, err := NewHarnessHandler(HarnessOptions{NowUnix: nowUnix})
	if err != nil {
		return ReadinessReport{}, err
	}
	report := ReadinessReport{Passed: true}

	health := serveHarnessRequest(handler, http.MethodGet, "/healthz", nil)
	report.HealthEndpoint = health.status == http.StatusOK && bytes.Contains(health.body, []byte(`"ready":true`))
	report.require(report.HealthEndpoint, "health endpoint failed")

	cover := serveHarnessRequest(handler, http.MethodGet, "/cover", nil)
	report.CoverEndpoint = cover.status == http.StatusOK && bytes.Contains(cover.body, []byte("<html>"))
	report.require(report.CoverEndpoint, "cover endpoint failed")

	unknown := serveHarnessRequest(handler, http.MethodPost, "/ordinary-origin-path", []byte("probe"))
	report.CoverNeutralUnknownPath = unknown.status == cover.status && bytes.Equal(unknown.body, cover.body)
	report.require(report.CoverNeutralUnknownPath, "unknown path did not map to cover origin")

	metadata := serveHarnessRequest(handler, http.MethodGet, "/issuer/issuer-metadata", nil)
	report.IssuerMetadataEndpoint = metadata.status == http.StatusOK && bytes.Contains(metadata.body, []byte("issuer_metadata_hash"))
	report.require(report.IssuerMetadataEndpoint, "issuer metadata endpoint failed")

	issue := serveHarnessRequest(handler, http.MethodPost, "/issuer/blind-rsa/issue", mustMarshalJSON(issuerd.IssueRequest{
		TokenNonce:            hex.EncodeToString(repeatedByte(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(repeatedByte(0x45, 48)),
		ExpiryUnix:            nowUnix + 100,
	}))
	var issued issuerd.IssueResponse
	if issue.status == http.StatusOK && json.Unmarshal(issue.body, &issued) == nil && issued.AdmissionProof != "" {
		if raw, err := hex.DecodeString(issued.AdmissionProof); err == nil && len(raw) > 0 {
			report.BlindRSAIssueEndpoint = true
		}
	}
	report.require(report.BlindRSAIssueEndpoint, "Blind RSA issue endpoint failed")

	packetRequest, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		return ReadinessReport{}, err
	}
	packetExchange := serveHarnessRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, packetRequest, "application/octet-stream")
	if packetExchange.status == http.StatusOK && bytes.Equal(packetExchange.contentType(), []byte("application/octet-stream")) {
		if packetResponse, err := DecodePacketBatch(packetExchange.body); err == nil &&
			len(packetResponse.Packets) == 1 &&
			bytes.Equal(packetResponse.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) &&
			packetResponse.ProtocolNumbers[0] == 2 {
			report.PacketExchangeEndpoint = true
		}
	}
	report.require(report.PacketExchangeEndpoint, "packet exchange endpoint failed")

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
	if failureOrigin, ok := coverOrigin.(CoverOrigin); ok {
		failureOrigin.ServeFailureHTTP(w, r)
		return
	}
	coverOrigin.ServeHTTP(w, sanitizedCoverFailureRequest(r))
}

func coverReady(opts Options) bool {
	return opts.Origin != nil || opts.CoverOrigin != nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

const packetExchangeMaxBodyBytes = 1 << 20

func isPacketExchangeRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/octet-stream"
}

func servePacketExchange(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, exchanger PacketExchanger) {
	body, err := io.ReadAll(io.LimitReader(r.Body, packetExchangeMaxBodyBytes+1))
	if err != nil || len(body) > packetExchangeMaxBodyBytes {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	inbound, err := DecodePacketBatch(body)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	outbound, err := exchanger.ExchangePacketBatch(inbound)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	encoded, err := EncodePacketBatch(outbound)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

type harnessResponse struct {
	status int
	header http.Header
	body   []byte
}

func (r harnessResponse) contentType() []byte {
	return []byte(r.header.Get("Content-Type"))
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

func mustMarshalJSON(v any) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return out
}

func repeatedByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func normalizeHarnessNow(now uint64) uint64 {
	if now == 0 {
		return 200
	}
	return now
}
