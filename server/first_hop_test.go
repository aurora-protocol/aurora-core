package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/transport"
	"golang.org/x/net/http2"
)

func TestFirstHopWithholdsHeadersUntilBeginCompletes(t *testing.T) {
	beginStarted := make(chan struct{}, 1)
	releaseBegin := make(chan struct{})
	beginErr := errors.New("test admission failure")
	server, client, _, handler := startFirstHopGateTestServer(t, func(ctx context.Context, _ handshake.FirstHopBinding, _ protocol.CoverPrelude0, _ uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		beginStarted <- struct{}{}
		select {
		case <-releaseBegin:
			return nil, protocol.CoverPrelude1{}, beginErr
		case <-ctx.Done():
			return nil, protocol.CoverPrelude1{}, ctx.Err()
		}
	})
	request, err := http.NewRequest(http.MethodPost, server.URL+handler.path, bytes.NewReader(firstHopTestPreludeRecord(t)))
	if err != nil {
		t.Fatal(err)
	}
	responseReady := make(chan firstHopHTTPResult, 1)
	go func() {
		response, requestErr := client.Do(request)
		responseReady <- readFirstHopHTTPResult(response, requestErr)
	}()
	select {
	case <-beginStarted:
	case <-time.After(time.Second):
		t.Fatal("first-hop Begin did not start")
	}
	select {
	case result := <-responseReady:
		t.Fatalf("response headers arrived before Begin completed: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseBegin)
	select {
	case result := <-responseReady:
		assertFirstHopCoverResult(t, result)
		if result.header.Get("X-Carrier-Reply") != "" {
			t.Fatal("pre-header failure leaked configured carrier response headers")
		}
	case <-time.After(time.Second):
		t.Fatal("pre-header cover fallback did not complete")
	}
}

func TestFirstHopCarrierHeaderCommitRejectsConcurrentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	writer := &cancellingFirstHopResponseWriter{cancelOnHeader: cancel}
	var committed atomic.Bool
	err := commitFirstHopCarrierHeaders(ctx, writer, http.Header{"X-Carrier-Reply": {"ordinary"}}, http.StatusCreated, &committed)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("header commit error = %v, want context cancellation", err)
	}
	if committed.Load() || writer.status != 0 || len(writer.header) != 0 {
		t.Fatalf("canceled header commit changed response: committed=%t status=%d header=%v", committed.Load(), writer.status, writer.header)
	}
}

func TestFirstHopPostHeaderDeadlineRejectsConcurrentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	writer := &cancellingFirstHopResponseWriter{cancelOnReadDeadline: cancel}
	postHeaderContext, stopPostHeader, err := beginFirstHopPostHeader(ctx, http.NewResponseController(writer), time.Second)
	if stopPostHeader != nil {
		defer stopPostHeader()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-header deadline error = %v, want context cancellation", err)
	}
	if postHeaderContext != nil {
		t.Fatal("canceled post-header deadline returned a live context")
	}
	if writer.futureWriteDeadlines != 0 {
		t.Fatalf("canceled post-header setup installed %d future write deadlines", writer.futureWriteDeadlines)
	}
}

func TestFirstHopOrdinaryFirstRequestConsumesConnectionClaim(t *testing.T) {
	var beginCalls atomic.Int32
	server, client, connections, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		beginCalls.Add(1)
		return nil, protocol.CoverPrelude1{}, errors.New("unexpected Begin")
	})
	ordinary, err := client.Get(server.URL + "/ordinary")
	if err != nil {
		t.Fatal(err)
	}
	assertFirstHopCoverResult(t, readFirstHopHTTPResult(ordinary, nil))
	candidate, err := http.NewRequest(http.MethodPost, server.URL+handler.path, bytes.NewReader(firstHopTestPreludeRecord(t)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(candidate)
	if err != nil {
		t.Fatal(err)
	}
	assertFirstHopCoverResult(t, readFirstHopHTTPResult(response, nil))
	if got := beginCalls.Load(); got != 0 {
		t.Fatalf("Begin calls after ordinary first request = %d, want 0", got)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("requests used %d connections, want 1", got)
	}
}

func TestFirstHopSecondRequestCancelsActiveCarrier(t *testing.T) {
	beginStarted := make(chan struct{}, 1)
	beginCanceled := make(chan struct{}, 1)
	server, client, connections, handler := startFirstHopGateTestServer(t, func(ctx context.Context, _ handshake.FirstHopBinding, _ protocol.CoverPrelude0, _ uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		beginStarted <- struct{}{}
		<-ctx.Done()
		beginCanceled <- struct{}{}
		return nil, protocol.CoverPrelude1{}, ctx.Err()
	})
	firstRequest, err := http.NewRequest(http.MethodPost, server.URL+handler.path, bytes.NewReader(firstHopTestPreludeRecord(t)))
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan firstHopHTTPResult, 1)
	go func() {
		response, requestErr := client.Do(firstRequest)
		firstResult <- readFirstHopHTTPResult(response, requestErr)
	}()
	select {
	case <-beginStarted:
	case <-time.After(time.Second):
		t.Fatal("active first-hop request did not reach Begin")
	}
	secondResponse, err := client.Get(server.URL + "/ordinary")
	if err != nil {
		t.Fatal(err)
	}
	assertFirstHopCoverResult(t, readFirstHopHTTPResult(secondResponse, nil))
	select {
	case <-beginCanceled:
	case <-time.After(time.Second):
		t.Fatal("second request did not cancel active carrier")
	}
	select {
	case result := <-firstResult:
		assertFirstHopCoverResult(t, result)
	case <-time.After(time.Second):
		t.Fatal("canceled first request did not terminate")
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("concurrent requests used %d connections, want 1", got)
	}
}

func TestFirstHopSecondRequestUnblocksPreludeRead(t *testing.T) {
	server, client, connections, _ := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return nil, protocol.CoverPrelude1{}, errors.New("Begin must not run")
	})
	body := newBlockingFirstHopRequestBody()
	firstRequest, err := http.NewRequest(http.MethodPost, server.URL+"/assets/upload/42", body)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan firstHopHTTPResult, 1)
	go func() {
		response, requestErr := client.Do(firstRequest)
		firstResult <- readFirstHopHTTPResult(response, requestErr)
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("client did not start the partial first-hop body")
	}
	secondResponse, err := client.Get(server.URL + "/ordinary")
	if err != nil {
		_ = body.Close()
		t.Fatal(err)
	}
	assertFirstHopCoverResult(t, readFirstHopHTTPResult(secondResponse, nil))
	select {
	case result := <-firstResult:
		if result.err == nil {
			assertFirstHopCoverResult(t, result)
		}
	case <-time.After(time.Second):
		_ = body.Close()
		t.Fatal("second request did not unblock partial Prelude0 read")
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("partial Prelude0 requests used %d connections, want 1", got)
	}
}

func TestFirstHopPreludeTimeoutUnblocksPartialRead(t *testing.T) {
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return nil, protocol.CoverPrelude1{}, errors.New("Begin must not run")
	})
	handler.preHeaderTimeout = 50 * time.Millisecond
	body := newBlockingFirstHopRequestBody()
	request, err := http.NewRequest(http.MethodPost, server.URL+handler.path, body)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan firstHopHTTPResult, 1)
	go func() {
		response, requestErr := client.Do(request)
		result <- readFirstHopHTTPResult(response, requestErr)
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("client did not start the partial first-hop body")
	}
	select {
	case got := <-result:
		if got.err == nil {
			assertFirstHopCoverResult(t, got)
		}
	case <-time.After(time.Second):
		_ = body.Close()
		t.Fatal("pre-header timeout did not unblock partial Prelude0 read")
	}
}

func TestFirstHopSecondRequestUnblocksPostHeaderRead(t *testing.T) {
	server, client, connections, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return nil, nil, protocol.PolicyAccept{}, errors.New("Finish must not run")
	}
	firstResponse, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer firstResponse.Body.Close()
	defer writer.Close()
	reader, err := transport.NewRecordReader(firstResponse.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := reader.Read()
		readDone <- readErr
	}()
	secondResponse, err := client.Get(server.URL + "/ordinary")
	if err != nil {
		t.Fatal(err)
	}
	assertFirstHopCoverResult(t, readFirstHopHTTPResult(secondResponse, nil))
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("canceled post-header stream produced another record")
		}
	case <-time.After(time.Second):
		t.Fatal("second request did not unblock post-header read")
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("post-header requests used %d connections, want 1", got)
	}
}

func TestFirstHopPostHeaderTimeoutUnblocksCapsule1Read(t *testing.T) {
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	handler.postHeaderTimeout = 50 * time.Millisecond
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return nil, nil, protocol.PolicyAccept{}, errors.New("Finish must not run")
	}
	response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer response.Body.Close()
	defer writer.Close()
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := reader.Read()
		readDone <- readErr
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("timed-out post-header stream produced another record")
		}
	case <-time.After(time.Second):
		t.Fatal("post-header timeout did not unblock Capsule1 read")
	}
}

func TestFirstHopConcurrentRequestsAdmitAtMostOne(t *testing.T) {
	var beginCalls atomic.Int32
	server, client, connections, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		beginCalls.Add(1)
		return nil, protocol.CoverPrelude1{}, errors.New("test rejection")
	})
	const requests = 32
	start := make(chan struct{})
	errorsFound := make(chan error, requests)
	var wait sync.WaitGroup
	for i := 0; i < requests; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request, err := http.NewRequest(http.MethodPost, server.URL+handler.path, bytes.NewReader(firstHopTestPreludeRecord(t)))
			if err != nil {
				errorsFound <- err
				return
			}
			response, err := client.Do(request)
			result := readFirstHopHTTPResult(response, err)
			if result.err != nil || result.status != http.StatusTeapot || string(result.body) != "cover-body" {
				errorsFound <- errors.New("request was not mapped to cover")
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	if got := beginCalls.Load(); got > 1 {
		t.Fatalf("concurrent requests entered Begin %d times, want at most 1", got)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("concurrent requests used %d connections, want 1", got)
	}
}

func TestFirstHopMissingConnectionContextUsesSanitizedCover(t *testing.T) {
	recorder := &recordingFirstHopCoverOrigin{}
	handler := newFirstHopGateTestHandler(t, "cover.example:443", recorder)
	var beginCalls atomic.Int32
	handler.begin = func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		beginCalls.Add(1)
		return nil, protocol.CoverPrelude1{}, errors.New("unexpected")
	}
	request := httptest.NewRequest(http.MethodPost, "https://cover.example:443"+handler.path, bytes.NewReader([]byte("gateway-owned secret")))
	request.Host = handler.authority
	request.Proto = "HTTP/2.0"
	request.ProtoMajor = 2
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTeapot || response.Body.String() != "cover-body" {
		t.Fatalf("unexpected cover fallback: status=%d body=%q", response.Code, response.Body.String())
	}
	method, body := recorder.snapshot()
	if method != http.MethodGet || len(body) != 0 {
		t.Fatalf("failed gateway bytes reached cover origin: method=%s body=%q", method, body)
	}
	if beginCalls.Load() != 0 {
		t.Fatal("request without connection context entered Begin")
	}
}

func TestFirstHopMissingConnectionContextForwardsOrdinaryBody(t *testing.T) {
	recorder := &recordingFirstHopCoverOrigin{}
	handler := newFirstHopGateTestHandler(t, "cover.example:443", recorder)
	request := httptest.NewRequest(http.MethodPost, "https://cover.example:443/ordinary", nil)
	request.Body = &firstHopCloseSensitiveBody{reader: bytes.NewReader([]byte("ordinary request body"))}
	request.Host = handler.authority
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	method, body := recorder.snapshot()
	if response.Code != http.StatusTeapot || response.Body.String() != "cover-body" || method != http.MethodPost || string(body) != "ordinary request body" {
		t.Fatalf("ordinary fallback changed: status=%d response=%q method=%s body=%q", response.Code, response.Body.String(), method, body)
	}
}

func TestFirstHopMalformedRecordUsesSanitizedCover(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "empty record", body: []byte{0, 0, 0}},
		{name: "short record", body: []byte{0, 0, 8, 1, 2}},
		{name: "oversized record", body: []byte{0, 0x20, 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var beginCalls atomic.Int32
			server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
				beginCalls.Add(1)
				return nil, protocol.CoverPrelude1{}, errors.New("unexpected Begin")
			})
			recorder := &recordingFirstHopCoverOrigin{}
			handler.coverOrigin = recorder
			request, err := http.NewRequest(http.MethodPost, server.URL+handler.path, bytes.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			assertFirstHopCoverResult(t, readFirstHopHTTPResult(response, nil))
			method, body := recorder.snapshot()
			if method != http.MethodGet || len(body) != 0 {
				t.Fatalf("malformed bytes reached cover origin: method=%s body=%x", method, body)
			}
			if beginCalls.Load() != 0 {
				t.Fatal("malformed record entered Begin")
			}
		})
	}
}

func TestFirstHopExactTargetWithInvalidTransportUsesSanitizedCover(t *testing.T) {
	recorder := &recordingFirstHopCoverOrigin{}
	handler := newFirstHopGateTestHandler(t, "cover.example:443", recorder)
	request := httptest.NewRequest(http.MethodPost, "https://cover.example:443"+handler.path, bytes.NewReader([]byte("gateway-owned secret")))
	request.Host = handler.authority
	request.Proto = "HTTP/1.1"
	request.ProtoMajor = 1
	request = request.WithContext(context.WithValue(request.Context(), firstHopConnectionContextKey{}, &firstHopConnectionState{}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	method, body := recorder.snapshot()
	if response.Code != http.StatusTeapot || response.Body.String() != "cover-body" || method != http.MethodGet || len(body) != 0 {
		t.Fatalf("invalid transport was not sanitized cover: status=%d response=%q method=%s body=%q", response.Code, response.Body.String(), method, body)
	}
}

func TestFirstHopInvalidTransportOrTargetReceivesCover(t *testing.T) {
	validTLS := &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, NegotiatedProtocol: "h2"}
	tests := []struct {
		name      string
		mutate    func(*http.Request)
		sanitized bool
	}{
		{name: "non TLS", mutate: func(r *http.Request) { r.TLS = nil }, sanitized: true},
		{name: "HTTP1", mutate: func(r *http.Request) { r.Proto = "HTTP/1.1"; r.ProtoMajor = 1 }, sanitized: true},
		{name: "resumed", mutate: func(r *http.Request) { state := *r.TLS; state.DidResume = true; r.TLS = &state }, sanitized: true},
		{name: "wrong authority", mutate: func(r *http.Request) { r.Host = "other.example:443" }},
		{name: "wrong path", mutate: func(r *http.Request) { r.URL.Path = "/ordinary" }},
		{name: "wrong method", mutate: func(r *http.Request) { r.Method = http.MethodPut }, sanitized: true},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "page=1" }, sanitized: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &recordingFirstHopCoverOrigin{}
			handler := newFirstHopGateTestHandler(t, "cover.example:443", recorder)
			var beginCalls atomic.Int32
			handler.begin = func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
				beginCalls.Add(1)
				return nil, protocol.CoverPrelude1{}, errors.New("unexpected Begin")
			}
			request := httptest.NewRequest(http.MethodPost, "https://cover.example:443"+handler.path, bytes.NewReader(firstHopTestPreludeRecord(t)))
			request.Host = handler.authority
			request.Proto = "HTTP/2.0"
			request.ProtoMajor = 2
			request.TLS = validTLS
			request = request.WithContext(context.WithValue(request.Context(), firstHopConnectionContextKey{}, &firstHopConnectionState{}))
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusTeapot || response.Body.String() != "cover-body" {
				t.Fatalf("invalid request did not receive cover: status=%d body=%q", response.Code, response.Body.String())
			}
			if beginCalls.Load() != 0 {
				t.Fatal("invalid request entered Begin")
			}
			method, body := recorder.snapshot()
			if test.sanitized {
				if method != http.MethodGet || len(body) != 0 {
					t.Fatalf("gateway-owned request reached cover origin: method=%s body=%x", method, body)
				}
			} else if method != http.MethodPost || len(body) == 0 {
				t.Fatalf("ordinary request was not forwarded: method=%s body=%x", method, body)
			}
		})
	}
}

func TestFirstHopCandidateTargetRequiresExactWirePath(t *testing.T) {
	handler := newFirstHopGateTestHandler(t, "cover.example:443", nil)
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "encoded path", mutate: func(r *http.Request) { r.URL.RawPath = "/assets/%75pload/42"; r.RequestURI = r.URL.RawPath }},
		{name: "empty query delimiter", mutate: func(r *http.Request) { r.URL.ForceQuery = true; r.RequestURI = handler.path + "?" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://cover.example:443"+handler.path, nil)
			request.Host = handler.authority
			test.mutate(request)
			if handler.isCandidateTarget(request) {
				t.Fatal("non-exact wire target admitted")
			}
		})
	}
}

func TestFirstHopPostHeaderFailureCancelsWithoutCoverBody(t *testing.T) {
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	recorder := &recordingFirstHopCoverOrigin{}
	handler.coverOrigin = recorder
	partialCapsule := []byte("partial Capsule2")
	partialEndpoint := newFirstHopTestEndpoint(nil)
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return partialCapsule, partialEndpoint, protocol.PolicyAccept{}, errors.New("test Capsule1 failure")
	}
	response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer response.Body.Close()
	defer writer.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("X-Carrier-Reply") != "ordinary" {
		t.Fatalf("unexpected committed cover response: status=%d header=%v", response.StatusCode, response.Header)
	}
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if prelude1, err := reader.Read(); err != nil || len(prelude1) == 0 {
		t.Fatalf("read Prelude1: bytes=%d err=%v", len(prelude1), err)
	}
	if err := writer.Write([]byte("malformed capsule")); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := reader.Read()
		readDone <- readErr
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("post-header failure produced another record")
		}
	case <-time.After(time.Second):
		t.Fatal("post-header failure did not cancel response stream")
	}
	method, body := recorder.snapshot()
	if method != "" || len(body) != 0 {
		t.Fatalf("post-header failure invoked cover origin: method=%s body=%q", method, body)
	}
	for _, value := range partialCapsule {
		if value != 0 {
			t.Fatal("post-header failure retained partial Capsule2 bytes")
		}
	}
	select {
	case <-partialEndpoint.Done():
	default:
		t.Fatal("post-header failure did not close partial application")
	}
}

func TestFirstHopHandsAlignedBodiesToPacketDuplex(t *testing.T) {
	frames := make(chan []byte, 1)
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	endpoint := newFirstHopTestEndpoint([]byte("server application packet"))
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return []byte("Capsule2"), endpoint, protocol.PolicyAccept{}, nil
	}
	handler.frameHandler = func(_ context.Context, block protocol.FrameBlock) error {
		frames <- append([]byte(nil), block.Frames[0].Payload...)
		return nil
	}
	response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer response.Body.Close()
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	if err := writer.Write([]byte("Capsule1")); err != nil {
		t.Fatal(err)
	}
	if capsule2, err := reader.Read(); err != nil || string(capsule2) != "Capsule2" {
		t.Fatalf("read Capsule2: record=%q err=%v", capsule2, err)
	}
	if packet, err := reader.Read(); err != nil || string(packet) != "server application packet" {
		t.Fatalf("read server application packet: record=%q err=%v", packet, err)
	}
	if err := writer.Write([]byte("client application packet")); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-frames:
		if string(payload) != "client application packet" {
			t.Fatalf("frame handler payload = %q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("client application packet did not reach frame handler")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-endpoint.Done():
	case <-time.After(time.Second):
		t.Fatal("packet endpoint remained live after request body closed")
	}
}

func TestFirstHopBuildsSessionHandlerBeforeCapsule2(t *testing.T) {
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	endpoint := newFirstHopTestEndpoint([]byte("server packet"))
	selected := protocol.PolicyAccept{
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
		SelectedPolicy:            9,
		FallbackMethods:           []uint64{registry.MethodWebH2Stream},
	}
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return []byte("Capsule2"), endpoint, selected, nil
	}
	handler.frameHandler = nil
	factoryCalled := make(chan protocol.PolicyAccept, 1)
	handledFrames := make(chan []byte, 1)
	releaseFactory := make(chan struct{})
	closer := &signalingFirstHopCloser{closed: make(chan struct{})}
	handler.sessionFactory = func(_ context.Context, application FirstHopSessionApplication, policy protocol.PolicyAccept) (transport.FrameBlockHandler, io.Closer, error) {
		if application != endpoint {
			return nil, nil, errors.New("factory received wrong application")
		}
		policy.FallbackMethods[0] = registry.MethodWebH1WS
		factoryCalled <- policy
		<-releaseFactory
		return func(_ context.Context, block protocol.FrameBlock) error {
			handledFrames <- append([]byte(nil), block.Frames[0].Payload...)
			return nil
		}, closer, nil
	}

	response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer response.Body.Close()
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	if err := writer.Write([]byte("Capsule1")); err != nil {
		t.Fatal(err)
	}
	capsuleResult := make(chan error, 1)
	go func() {
		capsule, err := reader.Read()
		if err == nil && string(capsule) != "Capsule2" {
			err = errors.New("wrong Capsule2")
		}
		capsuleResult <- err
	}()
	select {
	case policy := <-factoryCalled:
		if policy.SelectedPolicy != selected.SelectedPolicy || policy.SelectedTunnelPersonality != registry.PersonalityProxyFlow {
			t.Fatalf("factory policy = %+v", policy)
		}
	case <-time.After(time.Second):
		t.Fatal("session factory was not called")
	}
	if selected.FallbackMethods[0] != registry.MethodWebH2Stream {
		t.Fatal("session factory mutated retained selected policy")
	}
	select {
	case err := <-capsuleResult:
		t.Fatalf("Capsule2 was released before session factory completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFactory)
	if err := <-capsuleResult; err != nil {
		t.Fatalf("read Capsule2: %v", err)
	}
	if err := writer.Write([]byte("factory application packet")); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-handledFrames:
		if string(payload) != "factory application packet" {
			t.Fatalf("factory handler payload = %q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("application packet did not reach factory handler")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closer.closed:
	case <-time.After(time.Second):
		t.Fatal("session closer was not called after duplex shutdown")
	}
}

func TestFirstHopDoesNotReleaseCapsule2AfterSessionFactoryTimeout(t *testing.T) {
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	handler.postHeaderTimeout = 200 * time.Millisecond
	endpoint := newFirstHopTestEndpoint([]byte("server packet"))
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return []byte("Capsule2"), endpoint, protocol.PolicyAccept{SelectedTunnelPersonality: registry.PersonalityProxyFlow}, nil
	}
	handler.frameHandler = nil
	closer := &signalingFirstHopCloser{closed: make(chan struct{})}
	handler.sessionFactory = func(context.Context, FirstHopSessionApplication, protocol.PolicyAccept) (transport.FrameBlockHandler, io.Closer, error) {
		time.Sleep(400 * time.Millisecond)
		return func(context.Context, protocol.FrameBlock) error { return nil }, closer, nil
	}
	response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer response.Body.Close()
	defer writer.Close()
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	if err := writer.Write([]byte("Capsule1")); err != nil {
		t.Fatal(err)
	}
	if capsule, err := reader.Read(); err == nil {
		t.Fatalf("factory timeout released Capsule2 %q", capsule)
	}
	select {
	case <-closer.closed:
	case <-time.After(time.Second):
		t.Fatal("timed-out session factory closer was not called")
	}
}

func TestFirstHopSessionFactoryFailureClosesPartialOwnership(t *testing.T) {
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	endpoint := newFirstHopTestEndpoint(nil)
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return []byte("Capsule2"), endpoint, protocol.PolicyAccept{SelectedTunnelPersonality: registry.PersonalityProxyFlow}, nil
	}
	handler.frameHandler = nil
	closer := &signalingFirstHopCloser{closed: make(chan struct{})}
	handler.sessionFactory = func(context.Context, FirstHopSessionApplication, protocol.PolicyAccept) (transport.FrameBlockHandler, io.Closer, error) {
		return nil, closer, errors.New("session construction failed")
	}

	response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer response.Body.Close()
	defer writer.Close()
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	if err := writer.Write([]byte("Capsule1")); err != nil {
		t.Fatal(err)
	}
	if capsule, err := reader.Read(); err == nil {
		t.Fatalf("failed session factory released Capsule2 %q", capsule)
	}
	select {
	case <-closer.closed:
	case <-time.After(time.Second):
		t.Fatal("failed session factory did not close partial ownership")
	}
	select {
	case <-endpoint.Done():
	case <-time.After(time.Second):
		t.Fatal("failed session factory did not close application")
	}
}

func TestFirstHopRejectsInvalidSessionFactoryOwnership(t *testing.T) {
	tests := []struct {
		name       string
		build      func(*signalingFirstHopCloser) (transport.FrameBlockHandler, io.Closer)
		wantClosed bool
	}{
		{
			name: "nil handler",
			build: func(closer *signalingFirstHopCloser) (transport.FrameBlockHandler, io.Closer) {
				return nil, closer
			},
			wantClosed: true,
		},
		{
			name: "typed nil closer",
			build: func(*signalingFirstHopCloser) (transport.FrameBlockHandler, io.Closer) {
				var closer *signalingFirstHopCloser
				return func(context.Context, protocol.FrameBlock) error { return nil }, closer
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
				return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
			})
			endpoint := newFirstHopTestEndpoint(nil)
			handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
				return []byte("Capsule2"), endpoint, protocol.PolicyAccept{SelectedTunnelPersonality: registry.PersonalityProxyFlow}, nil
			}
			handler.frameHandler = nil
			closer := &signalingFirstHopCloser{closed: make(chan struct{})}
			handler.sessionFactory = func(context.Context, FirstHopSessionApplication, protocol.PolicyAccept) (transport.FrameBlockHandler, io.Closer, error) {
				handler, owner := test.build(closer)
				return handler, owner, nil
			}

			response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
			defer response.Body.Close()
			defer writer.Close()
			reader, err := transport.NewRecordReader(response.Body, 8192)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(); err != nil {
				t.Fatalf("read Prelude1: %v", err)
			}
			if err := writer.Write([]byte("Capsule1")); err != nil {
				t.Fatal(err)
			}
			if capsule, err := reader.Read(); err == nil {
				t.Fatalf("invalid session ownership released Capsule2 %q", capsule)
			}
			if test.wantClosed {
				select {
				case <-closer.closed:
				case <-time.After(time.Second):
					t.Fatal("invalid session owner was not closed")
				}
			}
			select {
			case <-endpoint.Done():
			case <-time.After(time.Second):
				t.Fatal("invalid session ownership did not close application")
			}
		})
	}
}

func TestFirstHopDoesNotBuildSessionAfterFinishFailure(t *testing.T) {
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	})
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return nil, nil, protocol.PolicyAccept{}, errors.New("Finish failed")
	}
	handler.frameHandler = nil
	var factoryCalls atomic.Int32
	handler.sessionFactory = func(context.Context, FirstHopSessionApplication, protocol.PolicyAccept) (transport.FrameBlockHandler, io.Closer, error) {
		factoryCalls.Add(1)
		return func(context.Context, protocol.FrameBlock) error { return nil }, io.NopCloser(bytes.NewReader(nil)), nil
	}

	response, writer := openFirstHopStreamingRequest(t, client, server.URL+handler.path)
	defer response.Body.Close()
	defer writer.Close()
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	if err := writer.Write([]byte("Capsule1")); err != nil {
		t.Fatal(err)
	}
	if capsule, err := reader.Read(); err == nil {
		t.Fatalf("Finish failure released Capsule2 %q", capsule)
	}
	if got := factoryCalls.Load(); got != 0 {
		t.Fatalf("session factory called %d times after Finish failure", got)
	}
}

func TestFirstHopHandlerRejectsInvalidOptions(t *testing.T) {
	base := FirstHopOptions{
		Driver:    &handshake.RelayDriver{},
		Authority: "cover.example:443",
		Path:      "/assets/upload/42",
		BindingMetadata: handshake.HTTP2BindingMetadata{
			NormalizedAuthorityHash: make([]byte, 48),
			PathTemplateID:          make([]byte, 16),
			RequestClassID:          7,
			MethodFamilyID:          registry.MethodWebH2Stream,
		},
		CoverStatus:        http.StatusOK,
		CoverHeader:        http.Header{"Content-Type": {"application/octet-stream"}},
		Origin:             testFirstHopOrigin{},
		MaxRecordBodyBytes: 8192,
		FrameHandler:       func(context.Context, protocol.FrameBlock) error { return nil },
		PostHeaderTimeout:  time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*FirstHopOptions)
	}{
		{name: "nil driver", mutate: func(o *FirstHopOptions) { o.Driver = nil }},
		{name: "empty authority", mutate: func(o *FirstHopOptions) { o.Authority = "" }},
		{name: "invalid path", mutate: func(o *FirstHopOptions) { o.Path = "upload" }},
		{name: "bad authority hash", mutate: func(o *FirstHopOptions) { o.BindingMetadata.NormalizedAuthorityHash = []byte{1} }},
		{name: "bad path ID", mutate: func(o *FirstHopOptions) { o.BindingMetadata.PathTemplateID = []byte{1} }},
		{name: "bad class", mutate: func(o *FirstHopOptions) { o.BindingMetadata.RequestClassID = 0 }},
		{name: "bad method", mutate: func(o *FirstHopOptions) { o.BindingMetadata.MethodFamilyID = registry.MethodWebH1WS }},
		{name: "bad status", mutate: func(o *FirstHopOptions) { o.CoverStatus = 199 }},
		{name: "fixed content length", mutate: func(o *FirstHopOptions) { o.CoverHeader.Set("Content-Length", "8192") }},
		{name: "connection header", mutate: func(o *FirstHopOptions) { o.CoverHeader.Set("Connection", "keep-alive") }},
		{name: "invalid header name", mutate: func(o *FirstHopOptions) { o.CoverHeader["Bad Header"] = []string{"value"} }},
		{name: "invalid header value", mutate: func(o *FirstHopOptions) { o.CoverHeader.Set("X-Cover", "value\r\nleak") }},
		{name: "client-forbidden marker", mutate: func(o *FirstHopOptions) { o.CoverHeader.Set("X-Relay-Mode", "ordinary") }},
		{name: "oversized record", mutate: func(o *FirstHopOptions) { o.MaxRecordBodyBytes = 1 << 24 }},
		{name: "missing origin", mutate: func(o *FirstHopOptions) { o.Origin = nil }},
		{name: "typed nil origin", mutate: func(o *FirstHopOptions) {
			o.Origin = (*testFirstHopOrigin)(nil)
			o.CoverOrigin = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		}},
		{name: "typed nil cover origin", mutate: func(o *FirstHopOptions) { o.CoverOrigin = (*recordingFirstHopCoverOrigin)(nil) }},
		{name: "nil frame handler", mutate: func(o *FirstHopOptions) { o.FrameHandler = nil }},
		{name: "both frame handler sources", mutate: func(o *FirstHopOptions) {
			o.SessionFactory = func(context.Context, FirstHopSessionApplication, protocol.PolicyAccept) (transport.FrameBlockHandler, io.Closer, error) {
				return func(context.Context, protocol.FrameBlock) error { return nil }, io.NopCloser(bytes.NewReader(nil)), nil
			}
		}},
		{name: "bad post-header timeout", mutate: func(o *FirstHopOptions) { o.PostHeaderTimeout = -time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			options.BindingMetadata.NormalizedAuthorityHash = append([]byte(nil), base.BindingMetadata.NormalizedAuthorityHash...)
			options.BindingMetadata.PathTemplateID = append([]byte(nil), base.BindingMetadata.PathTemplateID...)
			options.CoverHeader = base.CoverHeader.Clone()
			test.mutate(&options)
			if _, err := NewFirstHopHandler(options); err == nil {
				t.Fatal("invalid first-hop options accepted")
			}
		})
	}
}

func TestFirstHopHandlerAcceptsSessionFactoryWithoutStaticHandler(t *testing.T) {
	options := FirstHopOptions{
		Driver:    &handshake.RelayDriver{},
		Authority: "cover.example:443",
		Path:      "/assets/upload/42",
		BindingMetadata: handshake.HTTP2BindingMetadata{
			NormalizedAuthorityHash: make([]byte, 48),
			PathTemplateID:          make([]byte, 16),
			RequestClassID:          7,
			MethodFamilyID:          registry.MethodWebH2Stream,
		},
		CoverStatus: http.StatusOK,
		CoverHeader: http.Header{"Content-Type": {"application/octet-stream"}},
		Origin:      testFirstHopOrigin{},
		SessionFactory: func(context.Context, FirstHopSessionApplication, protocol.PolicyAccept) (transport.FrameBlockHandler, io.Closer, error) {
			return func(context.Context, protocol.FrameBlock) error { return nil }, io.NopCloser(bytes.NewReader(nil)), nil
		},
	}
	if _, err := NewFirstHopHandler(options); err != nil {
		t.Fatalf("NewFirstHopHandler rejected session factory: %v", err)
	}
}

func TestNewFirstHopProxySessionFactoryRejectsInvalidOptions(t *testing.T) {
	var typedNilDialer *net.Dialer
	tests := []struct {
		name    string
		options FirstHopProxySessionOptions
	}{
		{name: "nil dialer", options: FirstHopProxySessionOptions{Resolver: net.DefaultResolver}},
		{name: "typed nil dialer", options: FirstHopProxySessionOptions{Dialer: typedNilDialer, Resolver: net.DefaultResolver}},
		{name: "nil resolver", options: FirstHopProxySessionOptions{Dialer: &net.Dialer{}}},
		{
			name: "invalid limits",
			options: FirstHopProxySessionOptions{
				Dialer:   &net.Dialer{},
				Resolver: net.DefaultResolver,
				Limits:   relay.SocketEgressLimits{MaxFlows: -1},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewFirstHopProxySessionFactory(test.options); err == nil {
				t.Fatal("NewFirstHopProxySessionFactory accepted invalid options")
			}
		})
	}
}

func TestFirstHopProxySessionFactoryRejectsUnsupportedPersonality(t *testing.T) {
	factory, err := NewFirstHopProxySessionFactory(FirstHopProxySessionOptions{
		Dialer:   &net.Dialer{},
		Resolver: net.DefaultResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	application := newFirstHopTestEndpoint(nil)
	handler, owner, err := factory(context.Background(), application, protocol.PolicyAccept{
		SelectedTunnelPersonality: registry.PersonalityIPLite,
	})
	if !errors.Is(err, ErrFirstHopUnsupportedPersonality) || handler != nil || owner != nil {
		t.Fatalf("unsupported personality result: handler=%v owner=%v err=%v", handler, owner, err)
	}
	select {
	case <-application.Done():
		t.Fatal("rejected personality closed caller-owned application")
	default:
	}
}

func TestFirstHopProxySessionFactoryBuildsOwnedExitSession(t *testing.T) {
	factory, err := NewFirstHopProxySessionFactory(FirstHopProxySessionOptions{
		ExitPolicy: relay.ExitPolicy{AllowPrivate: true},
		Dialer:     &net.Dialer{},
		Resolver:   net.DefaultResolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	application := newFirstHopTestEndpoint(nil)
	handler, owner, err := factory(context.Background(), application, protocol.PolicyAccept{
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil || owner == nil {
		t.Fatal("proxy session factory returned incomplete ownership")
	}
	if err := handler(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}); err != nil {
		t.Fatalf("handle padding frame: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	select {
	case <-application.Done():
		t.Fatal("session owner closed separately-owned application")
	default:
	}
}

func TestFirstHopHTTPServerRejectsInvalidConfiguration(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	type serverInput struct {
		address   string
		handler   *FirstHopHandler
		tlsConfig *tls.Config
	}
	base := serverInput{
		address:   "127.0.0.1:0",
		handler:   &FirstHopHandler{},
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
	}
	tests := []struct {
		name   string
		mutate func(*serverInput)
	}{
		{name: "empty address", mutate: func(in *serverInput) { in.address = "" }},
		{name: "nil handler", mutate: func(in *serverInput) { in.handler = nil }},
		{name: "nil TLS", mutate: func(in *serverInput) { in.tlsConfig = nil }},
		{name: "no certificate", mutate: func(in *serverInput) { in.tlsConfig.Certificates = nil }},
		{name: "empty certificate", mutate: func(in *serverInput) { in.tlsConfig.Certificates = []tls.Certificate{{}} }},
		{name: "old minimum", mutate: func(in *serverInput) { in.tlsConfig.MinVersion = tls.VersionTLS12 }},
		{name: "old maximum", mutate: func(in *serverInput) { in.tlsConfig.MaxVersion = tls.VersionTLS12 }},
		{name: "HTTP1 ALPN", mutate: func(in *serverInput) { in.tlsConfig.NextProtos = []string{"http/1.1"} }},
		{name: "client certificates", mutate: func(in *serverInput) { in.tlsConfig.ClientAuth = tls.RequireAnyClientCert }},
		{name: "certificate callback", mutate: func(in *serverInput) {
			in.tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &certificate, nil }
		}},
		{name: "dynamic config", mutate: func(in *serverInput) {
			in.tlsConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return in.tlsConfig, nil }
		}},
		{name: "dynamic ECH keys", mutate: func(in *serverInput) {
			in.tlsConfig.GetEncryptedClientHelloKeys = func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { return nil, nil }
		}},
		{name: "connection verifier", mutate: func(in *serverInput) {
			in.tlsConfig.VerifyConnection = func(tls.ConnectionState) error { return nil }
		}},
		{name: "peer verifier", mutate: func(in *serverInput) {
			in.tlsConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		}},
		{name: "custom randomness", mutate: func(in *serverInput) { in.tlsConfig.Rand = bytes.NewReader(make([]byte, 4096)) }},
		{name: "custom time", mutate: func(in *serverInput) { in.tlsConfig.Time = func() time.Time { return time.Unix(1, 0) } }},
		{name: "deprecated certificate map", mutate: func(in *serverInput) {
			//lint:ignore SA1019 Setting the deprecated map to trip the :285 forbidden-field guard.
			in.tlsConfig.NameToCertificate = map[string]*tls.Certificate{}
		}},
		{name: "TLS session callbacks", mutate: func(in *serverInput) {
			in.tlsConfig.UnwrapSession = func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil }
		}},
		{name: "key log", mutate: func(in *serverInput) { in.tlsConfig.KeyLogWriter = io.Discard }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.tlsConfig = base.tlsConfig.Clone()
			input.tlsConfig.Certificates = append([]tls.Certificate(nil), base.tlsConfig.Certificates...)
			test.mutate(&input)
			if _, err := NewFirstHopHTTPServer(input.address, input.handler, input.tlsConfig); err == nil {
				t.Fatal("invalid first-hop server configuration accepted")
			}
		})
	}
}

func TestFirstHopHTTPServerOwnsHardenedTLSConfiguration(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	handler := newFirstHopGateTestHandler(t, "cover.example:443", nil)
	input := &tls.Config{Certificates: []tls.Certificate{certificate}}
	server, err := NewFirstHopHTTPServer("127.0.0.1:0", handler, input)
	if err != nil {
		t.Fatal(err)
	}
	if server.TLSConfig == input || server.TLSConfig.MinVersion != tls.VersionTLS13 || server.TLSConfig.MaxVersion != tls.VersionTLS13 || !server.TLSConfig.SessionTicketsDisabled || len(server.TLSConfig.NextProtos) != 1 || server.TLSConfig.NextProtos[0] != "h2" {
		t.Fatalf("first-hop TLS configuration is not hardened: %+v", server.TLSConfig)
	}
	if server.Protocols == nil || !server.Protocols.HTTP2() || server.Protocols.HTTP1() || server.Protocols.UnencryptedHTTP2() {
		t.Fatalf("first-hop server protocols are not HTTP/2-only: %v", server.Protocols)
	}
	if server.ConnContext == nil || server.ReadHeaderTimeout <= 0 || server.IdleTimeout <= 0 || server.WriteTimeout <= 0 || server.MaxHeaderBytes <= 0 {
		t.Fatalf("first-hop server bounds are incomplete: %+v", server)
	}
	input.NextProtos = []string{"http/1.1"}
	if server.TLSConfig.NextProtos[0] != "h2" {
		t.Fatal("caller mutation changed server TLS configuration")
	}
	serverCertificateByte := server.TLSConfig.Certificates[0].Certificate[0][0]
	input.Certificates[0].Certificate[0][0] ^= 0xff
	if server.TLSConfig.Certificates[0].Certificate[0][0] != serverCertificateByte {
		t.Fatal("caller certificate mutation changed server identity")
	}
	if server.TLSConfig.Certificates[0].Leaf == nil {
		t.Fatal("owned server certificate does not cache a parsed leaf")
	}
}

func TestFirstHopHTTPServerLimitsConcurrentHTTP2Streams(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	clientTLS := certificateServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := newFirstHopGateTestHandler(t, listener.Addr().String(), nil)
	server, err := NewFirstHopHTTPServer(listener.Addr().String(), handler, &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serveResult:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("first-hop server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("first-hop server did not stop")
		}
	})

	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.MaxVersion = tls.VersionTLS13
	clientTLS.NextProtos = []string{"h2"}
	clientTLS.InsecureSkipVerify = true //nolint:gosec // The test uses a local self-signed identity.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsConnection := tls.Client(connection, clientTLS)
	defer tlsConnection.Close()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if tlsConnection.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", tlsConnection.ConnectionState().NegotiatedProtocol)
	}
	if _, err := io.WriteString(tlsConnection, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(tlsConnection, tlsConnection)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := tlsConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	defer tlsConnection.SetReadDeadline(time.Time{})
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("first HTTP/2 frame = %T, want SETTINGS", frame)
	}
	maximum, ok := settings.Value(http2.SettingMaxConcurrentStreams)
	if !ok {
		t.Fatal("HTTP/2 settings omit MAX_CONCURRENT_STREAMS")
	}
	if maximum != 1 {
		t.Fatalf("HTTP/2 MAX_CONCURRENT_STREAMS = %d, want 1", maximum)
	}
}

func TestFirstHopHTTPServerServesTLS13H2WithoutResumption(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	clientTLS := certificateServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := newFirstHopGateTestHandler(t, listener.Addr().String(), nil)
	server, err := NewFirstHopHTTPServer(listener.Addr().String(), handler, &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	t.Cleanup(func() {
		_ = server.Close()
		<-serveResult
	})
	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.MaxVersion = tls.VersionTLS13
	clientTLS.NextProtos = []string{"h2"}
	clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		TLSClientConfig:   clientTLS,
		Protocols:         protocols,
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for i := 0; i < 2; i++ {
		response, err := client.Get("https://" + listener.Addr().String() + "/ordinary")
		if err != nil {
			t.Fatal(err)
		}
		result := readFirstHopHTTPResult(response, nil)
		assertFirstHopCoverResult(t, result)
		if response.ProtoMajor != 2 || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.NegotiatedProtocol != "h2" || response.TLS.DidResume {
			t.Fatalf("unexpected live first-hop transport state: proto=%s tls=%+v", response.Proto, response.TLS)
		}
		transport.CloseIdleConnections()
	}
}

func TestFirstHopHandlerShutdownWaitsForActiveCarrier(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	clientTLS := certificateServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := newFirstHopGateTestHandler(t, listener.Addr().String(), nil)
	handler.begin = func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), nil
	}
	handler.finish = func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, protocol.PolicyAccept, error) {
		return nil, nil, protocol.PolicyAccept{}, errors.New("Finish must not run")
	}
	server, err := NewFirstHopHTTPServer(listener.Addr().String(), handler, &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-serveResult:
		case <-time.After(time.Second):
			t.Error("first-hop server did not stop during cleanup")
		}
	})
	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.MaxVersion = tls.VersionTLS13
	clientTLS.NextProtos = []string{"h2"}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	clientTransport := &http.Transport{TLSClientConfig: clientTLS, Protocols: protocols, ForceAttemptHTTP2: true, MaxConnsPerHost: 1}
	t.Cleanup(clientTransport.CloseIdleConnections)
	client := &http.Client{Transport: clientTransport, Timeout: 2 * time.Second}
	response, writer := openFirstHopStreamingRequest(t, client, "https://"+listener.Addr().String()+handler.path)
	defer response.Body.Close()
	defer writer.Close()
	reader, err := transport.NewRecordReader(response.Body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(); err != nil {
		t.Fatalf("read Prelude1: %v", err)
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShutdown()
	if err := handler.shutdownAndWait(shutdownContext); err != nil {
		t.Fatalf("first-hop handler shutdown: %v", err)
	}
	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- server.Shutdown(shutdownContext) }()
	select {
	case err := <-shutdownResult:
		if err != nil {
			t.Fatalf("graceful shutdown did not cancel active carrier: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("graceful shutdown remained blocked on active carrier")
	}
	if _, err := reader.Read(); err == nil {
		t.Fatal("active carrier remained readable after server shutdown")
	}
}

func TestFirstHopReadsLiveHTTP2StreamIdentifiers(t *testing.T) {
	streamIDs := make(chan uint32, 2)
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		streamID, ok := firstHopHTTP2StreamID(w)
		if !ok {
			t.Error("HTTP/2 response writer did not expose a fail-closed stream identifier")
			return
		}
		streamIDs <- streamID
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		connections.Add(1)
		return ctx
	}
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	baseTransport := server.Client().Transport.(*http.Transport)
	clientTransport := baseTransport.Clone()
	clientTransport.ForceAttemptHTTP2 = true
	clientTransport.MaxConnsPerHost = 1
	clientTransport.MaxIdleConnsPerHost = 1
	t.Cleanup(clientTransport.CloseIdleConnections)
	client := &http.Client{Transport: clientTransport, Timeout: time.Second}
	for i := 0; i < 2; i++ {
		response, err := client.Get(server.URL + "/ordinary")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	first := <-streamIDs
	second := <-streamIDs
	if first != 1 || second != 3 {
		t.Fatalf("live HTTP/2 stream identifiers = %d, %d; want 1, 3", first, second)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("stream identifier requests used %d connections, want 1", got)
	}
}

func TestFirstHopSkippedHTTP2StreamPoisonsConnectionClaim(t *testing.T) {
	state := &firstHopConnectionState{}
	if claimed, _ := state.enterStream(3, func() {}); claimed {
		t.Fatal("HTTP/2 stream 3 claimed a fresh first-hop connection")
	}
	if claimed, _ := state.enterStream(1, func() {}); claimed {
		t.Fatal("HTTP/2 stream 1 claimed a connection after a higher stream was observed")
	}
}

type firstHopHTTPResult struct {
	status int
	header http.Header
	body   []byte
	err    error
}

func startFirstHopGateTestServer(t *testing.T, begin firstHopBeginFunc) (*httptest.Server, *http.Client, *atomic.Int32, *FirstHopHandler) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	handler := newFirstHopGateTestHandler(t, server.Listener.Addr().String(), nil)
	handler.begin = begin
	connections := &atomic.Int32{}
	server.Config.Handler = handler
	server.Config.ConnContext = func(ctx context.Context, connection net.Conn) context.Context {
		connections.Add(1)
		return handler.ConnContext(ctx, connection)
	}
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	baseTransport := server.Client().Transport.(*http.Transport)
	clientTransport := baseTransport.Clone()
	clientTransport.ForceAttemptHTTP2 = true
	clientTransport.MaxConnsPerHost = 1
	clientTransport.MaxIdleConnsPerHost = 1
	client := &http.Client{Transport: clientTransport, Timeout: 3 * time.Second}
	t.Cleanup(clientTransport.CloseIdleConnections)
	return server, client, connections, handler
}

func newFirstHopGateTestHandler(t *testing.T, authority string, coverOrigin http.Handler) *FirstHopHandler {
	t.Helper()
	handler, err := NewFirstHopHandler(FirstHopOptions{
		Driver:    &handshake.RelayDriver{},
		Authority: authority,
		Path:      "/assets/upload/42",
		BindingMetadata: handshake.HTTP2BindingMetadata{
			NormalizedAuthorityHash: bytes.Repeat([]byte{0x21}, 48),
			PathTemplateID:          bytes.Repeat([]byte{0x22}, 16),
			RequestClassID:          7,
			MethodFamilyID:          registry.MethodWebH2Stream,
		},
		CoverStatus:        http.StatusCreated,
		CoverHeader:        http.Header{"Content-Type": {"application/octet-stream"}, "X-Carrier-Reply": {"ordinary"}},
		Origin:             relay.StaticOrigin{Status: http.StatusTeapot, Body: []byte("cover-body")},
		CoverOrigin:        coverOrigin,
		MaxRecordBodyBytes: 8192,
		FrameHandler:       func(context.Context, protocol.FrameBlock) error { return nil },
		PostHeaderTimeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func firstHopTestPreludeRecord(t *testing.T) []byte {
	t.Helper()
	prelude, err := protocol.Encode(protocol.CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{registry.SuiteHybrid768P256AESGCM},
		ClientNonce:                 bytes.Repeat([]byte{0x31}, 32),
		ClientClassicalEphPub:       []byte{0x01},
		ClientMLKEMEncapsulationKey: []byte{0x02},
		RelayDescriptorHash:         bytes.Repeat([]byte{0x32}, 48),
		CoverTemplateHash:           bytes.Repeat([]byte{0x33}, 48),
		RequestClassID:              7,
		HintIssuerID:                bytes.Repeat([]byte{0x34}, 16),
		RelayBucketID:               bytes.Repeat([]byte{0x35}, 16),
		HintEpochID:                 1,
		HintSelector:                bytes.Repeat([]byte{0x36}, 16),
		AccessHint:                  bytes.Repeat([]byte{0x37}, 16),
		ClientCoverRandom:           bytes.Repeat([]byte{0x38}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	var record bytes.Buffer
	writer, err := transport.NewRecordWriter(&record, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(prelude); err != nil {
		t.Fatal(err)
	}
	return record.Bytes()
}

func firstHopTestPrelude1() protocol.CoverPrelude1 {
	return protocol.CoverPrelude1{
		MsgType:                         registry.MsgCoverPrelude1,
		Version:                         registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768P256AESGCM,
		RelayDescriptorHash:             bytes.Repeat([]byte{0x41}, 48),
		CoverTemplateHash:               bytes.Repeat([]byte{0x42}, 48),
		RelayEpochID:                    1,
		ServerNonce:                     bytes.Repeat([]byte{0x43}, 32),
		ServerClassicalEphPub:           []byte{0x44},
		ServerMLKEMCiphertextToClient:   []byte{0x45},
		SelectedCoverProfileID:          bytes.Repeat([]byte{0x46}, 16),
		SelectedBootstrapEnvelopeID:     bytes.Repeat([]byte{0x47}, 16),
		ServerPreludeSignatureClassical: []byte{0x48},
		ServerPreludeSignaturePQ:        []byte{0x49},
	}
}

type firstHopStreamingWriter struct {
	records *transport.RecordWriter
	pipe    *io.PipeWriter
}

type cancellingFirstHopResponseWriter struct {
	header                 http.Header
	status                 int
	cancelOnHeader         context.CancelFunc
	cancelOnReadDeadline   context.CancelFunc
	futureWriteDeadlines   int
	headerCancellationOnce sync.Once
	readCancellationOnce   sync.Once
}

func (w *cancellingFirstHopResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	w.headerCancellationOnce.Do(func() {
		if w.cancelOnHeader != nil {
			w.cancelOnHeader()
		}
	})
	return w.header
}

func (*cancellingFirstHopResponseWriter) Write(payload []byte) (int, error) { return len(payload), nil }
func (w *cancellingFirstHopResponseWriter) WriteHeader(status int)          { w.status = status }
func (w *cancellingFirstHopResponseWriter) SetReadDeadline(time.Time) error {
	w.readCancellationOnce.Do(func() {
		if w.cancelOnReadDeadline != nil {
			w.cancelOnReadDeadline()
		}
	})
	return nil
}
func (w *cancellingFirstHopResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if deadline.After(time.Now()) {
		w.futureWriteDeadlines++
	}
	return nil
}
func (*cancellingFirstHopResponseWriter) FlushError() error { return nil }

type blockingFirstHopRequestBody struct {
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingFirstHopRequestBody() *blockingFirstHopRequestBody {
	return &blockingFirstHopRequestBody{started: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockingFirstHopRequestBody) Read([]byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.release
	return 0, io.EOF
}

func (b *blockingFirstHopRequestBody) Close() error {
	b.closeOnce.Do(func() { close(b.release) })
	return nil
}

func (w *firstHopStreamingWriter) Write(record []byte) error { return w.records.Write(record) }
func (w *firstHopStreamingWriter) Close() error              { return w.pipe.Close() }

func openFirstHopStreamingRequest(t *testing.T, client *http.Client, target string) (*http.Response, *firstHopStreamingWriter) {
	t.Helper()
	requestReader, requestWriter := io.Pipe()
	request, err := http.NewRequest(http.MethodPost, target, requestReader)
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	responses := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, requestErr := client.Do(request)
		responses <- struct {
			response *http.Response
			err      error
		}{response: response, err: requestErr}
	}()
	records, err := transport.NewRecordWriter(requestWriter, 8192)
	if err != nil {
		t.Fatal(err)
	}
	writer := &firstHopStreamingWriter{records: records, pipe: requestWriter}
	if _, err := requestWriter.Write(firstHopTestPreludeRecord(t)); err != nil {
		_ = writer.Close()
		t.Fatal(err)
	}
	select {
	case result := <-responses:
		if result.err != nil {
			_ = writer.Close()
			t.Fatal(result.err)
		}
		return result.response, writer
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("first-hop response headers did not arrive")
		return nil, nil
	}
}

type firstHopCloseSensitiveBody struct {
	reader *bytes.Reader
	closed bool
}

func (b *firstHopCloseSensitiveBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, errors.New("test request body closed")
	}
	return b.reader.Read(p)
}

func (b *firstHopCloseSensitiveBody) Close() error {
	b.closed = true
	return nil
}

type firstHopTestEndpoint struct {
	outgoing chan []byte
	done     chan struct{}
	once     sync.Once
}

func newFirstHopTestEndpoint(outgoing []byte) *firstHopTestEndpoint {
	endpoint := &firstHopTestEndpoint{outgoing: make(chan []byte, 1), done: make(chan struct{})}
	endpoint.outgoing <- append([]byte(nil), outgoing...)
	return endpoint
}

func (e *firstHopTestEndpoint) NextPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-e.outgoing:
		return packet, nil
	case <-e.done:
		return nil, errors.New("test endpoint closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*firstHopTestEndpoint) HandlePacket(_ context.Context, _ time.Time, packet []byte) ([]protocol.FrameBlock, error) {
	return []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: append([]byte(nil), packet...)}}}}, nil
}

func (*firstHopTestEndpoint) QueueFrames(context.Context, protocol.FrameBlock) error { return nil }

func (e *firstHopTestEndpoint) Done() <-chan struct{} { return e.done }
func (*firstHopTestEndpoint) Err() error              { return errors.New("test endpoint closed") }
func (e *firstHopTestEndpoint) Close() error {
	e.once.Do(func() { close(e.done) })
	return nil
}

type signalingFirstHopCloser struct {
	once   sync.Once
	closed chan struct{}
}

func (c *signalingFirstHopCloser) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func readFirstHopHTTPResult(response *http.Response, err error) firstHopHTTPResult {
	if err != nil {
		return firstHopHTTPResult{err: err}
	}
	if response == nil {
		return firstHopHTTPResult{err: errors.New("nil HTTP response")}
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(response.Body)
	return firstHopHTTPResult{status: response.StatusCode, header: response.Header.Clone(), body: body, err: readErr}
}

func assertFirstHopCoverResult(t *testing.T, result firstHopHTTPResult) {
	t.Helper()
	if result.err != nil || result.status != http.StatusTeapot || string(result.body) != "cover-body" {
		t.Fatalf("unexpected cover response: status=%d body=%q err=%v", result.status, result.body, result.err)
	}
}

type recordingFirstHopCoverOrigin struct {
	mu     sync.Mutex
	method string
	body   []byte
}

func (o *recordingFirstHopCoverOrigin) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	o.recordAndServe(w, request)
}

func (o *recordingFirstHopCoverOrigin) ServeFailureHTTP(w http.ResponseWriter, request *http.Request) {
	o.recordAndServe(w, request)
}

func (o *recordingFirstHopCoverOrigin) recordAndServe(w http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	o.mu.Lock()
	o.method = request.Method
	o.body = append([]byte(nil), body...)
	o.mu.Unlock()
	w.WriteHeader(http.StatusTeapot)
	_, _ = w.Write([]byte("cover-body"))
}

func (o *recordingFirstHopCoverOrigin) snapshot() (string, []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.method, append([]byte(nil), o.body...)
}

type testFirstHopOrigin struct{}

func (testFirstHopOrigin) NormalResponse() relay.Response {
	return relay.Response{Status: http.StatusOK, Body: []byte("cover")}
}
