package issuerd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestProductionBlindRSABackendIssuesExactBinaryCarrier(t *testing.T) {
	service, metadata, nowUnix := productionBackendServiceForTest(t)
	handler, err := NewProductionBlindRSABackendHandler(service, ProductionBlindRSABackendOptions{MaxConcurrentIssues: 2})
	if err != nil {
		t.Fatal(err)
	}
	request := productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, nil)
	if !isAuthenticatedProductionBackendRequest(request) {
		t.Fatalf("test request did not meet the production backend predicate: method=%q url=%+v request_uri=%q content_type=%q proto=%q tls=%+v", request.Method, request.URL, request.RequestURI, request.Header.Get("Content-Type"), request.Proto, request.TLS)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("production backend status = %d body=%q", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/octet-stream" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("production backend headers = %v", response.Header())
	}
	kind, payload, err := carrier.Decode(response.Body.Bytes())
	if err != nil || kind != carrier.BlindRSAIssueResponse {
		t.Fatalf("production backend carrier = kind=%d err=%v", kind, err)
	}
	proof, err := DecodeAdmissionProofBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, nowUnix); err != nil {
		t.Fatalf("production backend proof did not verify: %v", err)
	}
	if !bytes.Equal(proof.TokenNonce, fill(0x44, carrier.TokenNonceLength)) || !bytes.Equal(proof.RedemptionContextHash, fill(0x45, carrier.RedemptionContextLength)) {
		t.Fatal("production backend proof did not retain the exact issue request")
	}
}

func TestProductionBlindRSABackendRejectsEveryOtherSurfaceWithFixedFailure(t *testing.T) {
	service, _, _ := productionBackendServiceForTest(t)
	handler, err := NewProductionBlindRSABackendHandler(service, ProductionBlindRSABackendOptions{MaxConcurrentIssues: 1})
	if err != nil {
		t.Fatal(err)
	}
	validBody := productionBackendBody(t, carrier.BlindRSAIssueRequest)
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "health route", mutate: func(r *http.Request) { r.URL.Path, r.RequestURI = "/healthz", "/healthz" }},
		{name: "metadata route", mutate: func(r *http.Request) { r.URL.Path, r.RequestURI = "/issuer-metadata", "/issuer-metadata" }},
		{name: "JSON issue route", mutate: func(r *http.Request) { r.URL.Path, r.RequestURI = "/blind-rsa/issue", "/blind-rsa/issue" }},
		{name: "spend route", mutate: func(r *http.Request) { r.URL.Path, r.RequestURI = "/token/spend", "/token/spend" }},
		{name: "verifier route", mutate: func(r *http.Request) { r.URL.Path, r.RequestURI = "/voprf/verify", "/voprf/verify" }},
		{name: "packet route", mutate: func(r *http.Request) { r.URL.Path, r.RequestURI = "/packet", "/packet" }},
		{name: "wrong method", mutate: func(r *http.Request) { r.Method = http.MethodGet }},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery, r.RequestURI = "probe=1", "/?probe=1" }},
		{name: "media parameters", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/octet-stream; charset=binary") }},
		{name: "JSON media", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{name: "duplicate media", mutate: func(r *http.Request) { r.Header.Add("Content-Type", "application/octet-stream") }},
		{name: "HTTP 1", mutate: func(r *http.Request) { r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.1", 1, 1 }},
		{name: "TLS 1.2", mutate: func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }},
		{name: "missing ALPN", mutate: func(r *http.Request) { r.TLS.NegotiatedProtocol = "" }},
		{name: "resumed TLS", mutate: func(r *http.Request) { r.TLS.DidResume = true }},
		{name: "unverified client", mutate: func(r *http.Request) { r.TLS.VerifiedChains = nil }},
		{name: "mismatched verified client", mutate: func(r *http.Request) { r.TLS.VerifiedChains = [][]*x509.Certificate{{{Raw: []byte{0x99}}}} }},
		{name: "wrong carrier type", mutate: func(r *http.Request) {
			body := append([]byte(nil), validBody...)
			body[0] = byte(carrier.IssuerMetadataRequest)
			resetProductionBackendBody(r, body)
		}},
		{name: "short body", mutate: func(r *http.Request) { resetProductionBackendBody(r, validBody[:len(validBody)-1]) }},
		{name: "long body", mutate: func(r *http.Request) { resetProductionBackendBody(r, append(append([]byte(nil), validBody...), 0)) }},
		{name: "canceled", mutate: func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, validBody)
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertFixedProductionBackendFailure(t, response)
		})
	}
}

func TestProductionBlindRSABackendConstructorFailsClosed(t *testing.T) {
	production, _, nowUnix := productionBackendServiceForTest(t)
	harness, err := NewHarnessService(nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		service     *Service
		concurrency int
	}{
		{name: "nil service", service: nil, concurrency: 1},
		{name: "harness service", service: harness, concurrency: 1},
		{name: "zero concurrency", service: production, concurrency: 0},
		{name: "excess concurrency", service: production, concurrency: MaximumProductionBlindRSABackendConcurrency + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewProductionBlindRSABackendHandler(test.service, ProductionBlindRSABackendOptions{MaxConcurrentIssues: test.concurrency})
			if err == nil || handler != nil {
				t.Fatalf("production backend constructor accepted unsafe input: handler=%v err=%v", handler, err)
			}
		})
	}
}

func TestProductionBlindRSABackendSigningLimitHonorsCancellationAndReleases(t *testing.T) {
	service, _, _ := productionBackendServiceForTest(t)
	handlerValue, err := NewProductionBlindRSABackendHandler(service, ProductionBlindRSABackendOptions{MaxConcurrentIssues: 1})
	if err != nil {
		t.Fatal(err)
	}
	handler := handlerValue.(*productionBlindRSABackendHandler)
	realIssue := handler.issue
	var issueCalls atomic.Int32
	handler.issue = func(request IssueBlindRSA2048Request) (protocol.AdmissionProof, error) {
		issueCalls.Add(1)
		return realIssue(request)
	}
	handler.slots <- struct{}{}
	waitContext, cancelWait := context.WithCancel(context.Background())
	request := productionBackendRequest(t, waitContext, carrier.BlindRSAIssueRequest, nil)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	cancelWait()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled production backend request remained blocked on signing limit")
	}
	assertFixedProductionBackendFailure(t, response)
	if issueCalls.Load() != 0 {
		t.Fatalf("canceled queued request reached signer %d times", issueCalls.Load())
	}
	<-handler.slots

	next := httptest.NewRecorder()
	handler.ServeHTTP(next, productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, nil))
	if next.Code != http.StatusOK || issueCalls.Load() != 1 {
		t.Fatalf("released production signing slot = status=%d calls=%d", next.Code, issueCalls.Load())
	}
}

func TestProductionBlindRSABackendGloballyBoundsConcurrentSigning(t *testing.T) {
	service, _, _ := productionBackendServiceForTest(t)
	handlerValue, err := NewProductionBlindRSABackendHandler(service, ProductionBlindRSABackendOptions{MaxConcurrentIssues: 2})
	if err != nil {
		t.Fatal(err)
	}
	handler := handlerValue.(*productionBlindRSABackendHandler)
	realIssue := handler.issue
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	handler.issue = func(request IssueBlindRSA2048Request) (protocol.AdmissionProof, error) {
		current := active.Add(1)
		for previous := maximum.Load(); current > previous && !maximum.CompareAndSwap(previous, current); previous = maximum.Load() {
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return realIssue(request)
	}
	responses := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder(), httptest.NewRecorder()}
	requests := []*http.Request{
		productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, nil),
		productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, nil),
		productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, nil),
	}
	done := make(chan struct{}, len(responses))
	for i := 0; i < 2; i++ {
		go func(index int) {
			handler.ServeHTTP(responses[index], requests[index])
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("production backend did not enter the configured signing slots")
		}
	}
	go func() {
		handler.ServeHTTP(responses[2], requests[2])
		done <- struct{}{}
	}()
	select {
	case <-started:
		close(release)
		t.Fatal("production backend exceeded its global signing limit")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	for range responses {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("production backend did not release all bounded signing requests")
		}
	}
	if maximum.Load() != 2 || active.Load() != 0 {
		t.Fatalf("production backend concurrent signing = max=%d active=%d", maximum.Load(), active.Load())
	}
	for i, response := range responses {
		if response.Code != http.StatusOK {
			t.Fatalf("bounded production backend response %d = %d", i, response.Code)
		}
	}
}

func TestProductionBlindRSABackendCancellationDuringSigningFailsAndReleases(t *testing.T) {
	service, _, _ := productionBackendServiceForTest(t)
	handlerValue, err := NewProductionBlindRSABackendHandler(service, ProductionBlindRSABackendOptions{MaxConcurrentIssues: 1})
	if err != nil {
		t.Fatal(err)
	}
	handler := handlerValue.(*productionBlindRSABackendHandler)
	realIssue := handler.issue
	started := make(chan struct{})
	release := make(chan struct{})
	handler.issue = func(request IssueBlindRSA2048Request) (protocol.AdmissionProof, error) {
		close(started)
		<-release
		return realIssue(request)
	}
	requestContext, cancel := context.WithCancel(context.Background())
	request := productionBackendRequest(t, requestContext, carrier.BlindRSAIssueRequest, nil)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("production backend did not begin signing")
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled production signing request did not finish")
	}
	assertFixedProductionBackendFailure(t, response)

	handler.issue = realIssue
	next := httptest.NewRecorder()
	handler.ServeHTTP(next, productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, nil))
	if next.Code != http.StatusOK {
		t.Fatalf("production backend did not release canceled signing slot: status=%d", next.Code)
	}
}

func TestProductionBlindRSABackendClearsOwnedSensitiveBuffers(t *testing.T) {
	service, _, _ := productionBackendServiceForTest(t)
	handlerValue, err := NewProductionBlindRSABackendHandler(service, ProductionBlindRSABackendOptions{MaxConcurrentIssues: 1})
	if err != nil {
		t.Fatal(err)
	}
	handler := handlerValue.(*productionBlindRSABackendHandler)
	realIssue := handler.issue
	var retained [][]byte
	handler.issue = func(request IssueBlindRSA2048Request) (protocol.AdmissionProof, error) {
		retained = append(retained, request.TokenNonce, request.RedemptionContextHash)
		proof, issueErr := realIssue(request)
		retained = append(retained,
			proof.IssuerID,
			proof.TokenKeyID,
			proof.RelayBucketID,
			proof.TokenScopeID,
			proof.TokenNonce,
			proof.RedemptionContextHash,
			proof.TokenPublicMetadata,
			proof.TokenAuthenticator,
			proof.BindingProof,
		)
		return proof, issueErr
	}
	response := &retainingProductionBackendWriter{header: make(http.Header)}
	handler.ServeHTTP(response, productionBackendRequest(t, context.Background(), carrier.BlindRSAIssueRequest, nil))
	if response.status != http.StatusOK || len(response.copied) == 0 || len(response.borrowed) == 0 {
		t.Fatalf("retaining production backend response = status=%d copied=%d borrowed=%d", response.status, len(response.copied), len(response.borrowed))
	}
	if kind, _, err := carrier.Decode(response.copied); err != nil || kind != carrier.BlindRSAIssueResponse {
		t.Fatalf("copied production backend response = kind=%d err=%v", kind, err)
	}
	if !allProductionBackendBytesZero(response.borrowed) {
		t.Fatal("production backend retained encoded proof bytes after response write")
	}
	for i, value := range retained {
		if !allProductionBackendBytesZero(value) {
			t.Fatalf("production backend retained sensitive request/proof buffer %d", i)
		}
	}
}

func productionBackendServiceForTest(t *testing.T) (*Service, protocol.IssuerMetadata, uint64) {
	t.Helper()
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	return service, options.Metadata, *nowUnix
}

func productionBackendRequest(t *testing.T, ctx context.Context, kind carrier.Type, body []byte) *http.Request {
	t.Helper()
	if body == nil {
		body = productionBackendBody(t, kind)
	}
	request := httptest.NewRequest(http.MethodPost, "https://issuer-backend.invalid/", bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Proto = "HTTP/2.0"
	request.ProtoMajor = 2
	request.ProtoMinor = 0
	request.RequestURI = "/"
	clientCertificate := &x509.Certificate{Raw: []byte{0x01, 0x02, 0x03}}
	request.TLS = &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		HandshakeComplete:  true,
		NegotiatedProtocol: "h2",
		PeerCertificates:   []*x509.Certificate{clientCertificate},
		VerifiedChains:     [][]*x509.Certificate{{clientCertificate}},
	}
	return request
}

func productionBackendBody(t *testing.T, kind carrier.Type) []byte {
	t.Helper()
	payload, err := carrier.EncodeIssueRequest(fill(0x44, carrier.TokenNonceLength), fill(0x45, carrier.RedemptionContextLength), 250)
	if err != nil {
		t.Fatal(err)
	}
	return carrier.Encode(kind, payload)
}

func resetProductionBackendBody(request *http.Request, body []byte) {
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
}

func assertFixedProductionBackendFailure(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != productionBlindRSABackendFailureStatus || response.Body.Len() != 0 {
		t.Fatalf("production backend failure = status=%d body=%q", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/octet-stream" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("production backend failure headers = %v", response.Header())
	}
}

type retainingProductionBackendWriter struct {
	header   http.Header
	status   int
	borrowed []byte
	copied   []byte
}

func (w *retainingProductionBackendWriter) Header() http.Header { return w.header }

func (w *retainingProductionBackendWriter) WriteHeader(status int) { w.status = status }

func (w *retainingProductionBackendWriter) Write(body []byte) (int, error) {
	w.borrowed = body
	w.copied = append([]byte(nil), body...)
	return len(body), nil
}

func allProductionBackendBytesZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
