package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestHTTP2ClientCarrierStreamsBootstrapBeforeResponseHeaders(t *testing.T) {
	const authorityHashByte = 0x21
	const pathIDByte = 0x11
	coverRandom := bytes.Repeat([]byte{0x31}, 32)
	requestRecord := bytes.Repeat([]byte{0x41}, 4097)
	responseRecord := bytes.Repeat([]byte{0x52}, 5003)
	applicationRequest := []byte("application request")
	applicationResponse := []byte("application response")

	type observation struct {
		requestRecord      []byte
		applicationRequest []byte
		binding            handshake.FirstHopBinding
		remoteAddr         string
		err                error
	}
	observed := make(chan observation, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := observation{remoteAddr: r.RemoteAddr}
		defer func() { observed <- result }()
		if r.ProtoMajor != 2 || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || r.TLS.DidResume {
			result.err = fmt.Errorf("unexpected carrier connection: proto=%s tls=%+v", r.Proto, r.TLS)
			return
		}
		if r.Method != http.MethodPost || r.Host != r.URL.Host && r.URL.Host != "" || r.URL.Path != "/assets/upload/42" || r.Header.Get("X-Cover-Mode") != "ordinary" {
			result.err = fmt.Errorf("unexpected visible request: method=%s host=%s path=%s header=%v", r.Method, r.Host, r.URL.Path, r.Header)
			return
		}
		reader, err := NewRecordReader(r.Body, 8192)
		if err != nil {
			result.err = err
			return
		}
		result.requestRecord, err = reader.Read()
		if err != nil {
			result.err = fmt.Errorf("read bootstrap request: %w", err)
			return
		}
		metadata := handshake.HTTP2BindingMetadata{
			NormalizedAuthorityHash: bytes.Repeat([]byte{authorityHashByte}, 48),
			PathTemplateID:          bytes.Repeat([]byte{pathIDByte}, 16),
			RequestClassID:          1,
			MethodFamilyID:          registry.MethodWebH2Stream,
		}
		result.binding, err = handshake.DeriveHTTP2FirstHopBinding(*r.TLS, metadata, coverRandom)
		if err != nil {
			result.err = fmt.Errorf("derive server binding: %w", err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Cover-Reply", "ordinary")
		w.WriteHeader(http.StatusOK)
		writer, err := NewRecordWriter(w, 8192)
		if err != nil {
			result.err = err
			return
		}
		if err := writer.Write(responseRecord); err != nil {
			result.err = fmt.Errorf("write bootstrap response: %w", err)
			return
		}
		w.(http.Flusher).Flush()
		result.applicationRequest = make([]byte, len(applicationRequest))
		if _, err := io.ReadFull(r.Body, result.applicationRequest); err != nil {
			result.err = fmt.Errorf("read application request: %w", err)
			return
		}
		if _, err := w.Write(applicationResponse); err != nil {
			result.err = fmt.Errorf("write application response: %w", err)
			return
		}
		w.(http.Flusher).Flush()
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	tpl := transportTemplate(registry.MethodWebH2Stream)
	tpl.PublicNameHash = bytes.Repeat([]byte{authorityHashByte}, 48)
	built, err := BuildStreamingH2CarrierRequest(CarrierRequestInput{
		Plan:           CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream}, UDPMode: UDPOverStreamFallback},
		Template:       tpl,
		RequestClassID: 1,
		Scheme:         "https",
		Authority:      server.Listener.Addr().String(),
		Path:           "/assets/upload/42",
		Header:         http.Header{"X-Cover-Mode": {"ordinary"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := validHTTP2ClientCarrierConfig(built.Request, tpl)
	config.TLSConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.TLSConfig.MaxVersion = tls.VersionTLS13
	config.TLSConfig.NextProtos = []string{"h2"}
	config.TLSConfig.ClientSessionCache = nil
	config.ExpectedHeader = http.Header{
		"Content-Type":  {"application/octet-stream"},
		"X-Cover-Reply": {"ordinary"},
	}
	config.MaxRecordBodyBytes = 8192
	opener, err := NewHTTP2ClientCarrierOpener(config)
	if err != nil {
		t.Fatal(err)
	}

	type openResult struct {
		carrier handshake.BootstrapCarrier
		err     error
	}
	opened := make(chan openResult, 1)
	go func() {
		carrier, err := opener.Open(context.Background(), coverRandom)
		opened <- openResult{carrier: carrier, err: err}
	}()
	var carrier handshake.BootstrapCarrier
	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatal(result.err)
		}
		carrier = result.carrier
	case <-time.After(2 * time.Second):
		t.Fatal("Open waited for response headers instead of returning after the TLS handshake")
	}
	t.Cleanup(func() { _ = carrier.Close() })
	select {
	case result := <-observed:
		t.Fatalf("server completed before the client wrote Prelude0: %+v", result)
	default:
	}
	if err := carrier.WriteRecord(requestRecord); err != nil {
		t.Fatal(err)
	}
	gotResponseRecord, err := carrier.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotResponseRecord, responseRecord) {
		t.Fatalf("response record mismatch: got %d bytes", len(gotResponseRecord))
	}
	readStream, writeStream, err := carrier.ApplicationStreams()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := carrier.ApplicationStreams(); err == nil {
		t.Fatal("duplicate application stream acquisition succeeded")
	}
	if err := carrier.WriteRecord([]byte("late record")); err == nil {
		t.Fatal("bootstrap write succeeded after application upgrade")
	}
	if _, err := carrier.ReadRecord(); err == nil {
		t.Fatal("bootstrap read succeeded after application upgrade")
	}
	if _, err := writeStream.Write(applicationRequest); err != nil {
		t.Fatal(err)
	}
	gotApplicationResponse := make([]byte, len(applicationResponse))
	if _, err := io.ReadFull(readStream, gotApplicationResponse); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotApplicationResponse, applicationResponse) {
		t.Fatalf("application response mismatch: %q", gotApplicationResponse)
	}
	select {
	case result := <-observed:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !bytes.Equal(result.requestRecord, requestRecord) || !bytes.Equal(result.applicationRequest, applicationRequest) {
			t.Fatalf("server stream alignment mismatch: record=%d application=%q", len(result.requestRecord), result.applicationRequest)
		}
		clientBinding := carrier.Binding()
		if !reflect.DeepEqual(clientBinding, result.binding) {
			t.Fatal("client and server derived different first-hop bindings")
		}
		clientBinding.CoverStreamBinding[0] ^= 0xff
		if reflect.DeepEqual(clientBinding, carrier.Binding()) {
			t.Fatal("Binding returned aliased carrier state")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not complete the streaming exchange")
	}
}

func TestHTTP2ClientCarrierUsesFreshConnectionPerOpen(t *testing.T) {
	remoteAddresses := make(chan string, 2)
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteAddresses <- r.RemoteAddr
		if r.ProtoMajor != 2 || r.TLS == nil || r.TLS.DidResume {
			t.Errorf("unexpected transport state: proto=%s tls=%+v", r.Proto, r.TLS)
			return
		}
		for name, values := range r.Header {
			if containsForbiddenWireMarker(name) {
				t.Errorf("visible request header contains forbidden marker: %q", name)
			}
			for _, value := range values {
				if containsForbiddenWireMarker(value) {
					t.Errorf("visible request header value contains forbidden marker: %q", value)
				}
			}
		}
		reader, _ := NewRecordReader(r.Body, 1024)
		if _, err := reader.Read(); err != nil {
			t.Errorf("read request record: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		writer, _ := NewRecordWriter(w, 1024)
		if err := writer.Write([]byte("response")); err != nil {
			t.Errorf("write response record: %v", err)
		}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	opener := newLiveHTTP2TestOpener(t, server, http.StatusOK, http.Header{"Content-Type": {"application/octet-stream"}}, 1024)

	for i := 0; i < 2; i++ {
		carrier, err := opener.Open(context.Background(), bytes.Repeat([]byte{byte(0x41 + i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if err := carrier.WriteRecord([]byte("request")); err != nil {
			t.Fatal(err)
		}
		if record, err := carrier.ReadRecord(); err != nil || string(record) != "response" {
			t.Fatalf("read response: record=%q err=%v", record, err)
		}
		if err := carrier.Close(); err != nil {
			t.Fatal(err)
		}
	}
	first := <-remoteAddresses
	second := <-remoteAddresses
	if first == second {
		t.Fatalf("two Open calls reused one TCP connection: %q", first)
	}
	if got := newConnections.Load(); got != 2 {
		t.Fatalf("new TCP connection count = %d, want 2", got)
	}
}

func TestHTTP2ClientCarrierRejectsCoverResponseMismatch(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		responseHeader http.Header
		expectedStatus int
		expectedHeader http.Header
	}{
		{
			name:           "status",
			status:         http.StatusAccepted,
			responseHeader: http.Header{"Content-Type": {"application/octet-stream"}},
			expectedStatus: http.StatusOK,
			expectedHeader: http.Header{"Content-Type": {"application/octet-stream"}},
		},
		{
			name:           "header",
			status:         http.StatusOK,
			responseHeader: http.Header{"Content-Type": {"text/plain"}},
			expectedStatus: http.StatusOK,
			expectedHeader: http.Header{"Content-Type": {"application/octet-stream"}},
		},
		{
			name:   "visible marker",
			status: http.StatusOK,
			responseHeader: http.Header{
				"Content-Type": {"application/octet-stream"},
				"X-Service":    {"aurora"},
			},
			expectedStatus: http.StatusOK,
			expectedHeader: http.Header{"Content-Type": {"application/octet-stream"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reader, _ := NewRecordReader(r.Body, 1024)
				_, _ = reader.Read()
				for name, values := range test.responseHeader {
					w.Header()[name] = append([]string(nil), values...)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte{0, 0, 1, 1})
			}))
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			server.StartTLS()
			t.Cleanup(server.Close)
			opener := newLiveHTTP2TestOpener(t, server, test.expectedStatus, test.expectedHeader, 1024)
			carrier, err := opener.Open(context.Background(), bytes.Repeat([]byte{0x51}, 32))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = carrier.Close() })
			if err := carrier.WriteRecord([]byte("request")); err != nil {
				t.Fatal(err)
			}
			if _, err := carrier.ReadRecord(); err == nil {
				t.Fatal("mismatched cover response accepted")
			}
		})
	}
}

func TestHTTP2ClientCarrierCancellationClosesStalledTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	peerClosed := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			peerClosed <- acceptErr
			return
		}
		accepted <- connection
		buffer := make([]byte, 4096)
		for {
			_, readErr := connection.Read(buffer)
			if readErr != nil {
				peerClosed <- readErr
				_ = connection.Close()
				return
			}
		}
	}()
	opener := newRawHTTP2TestOpener(t, listener.Addr().String())
	//lint:ignore SA1012 This call verifies that the public API rejects a nil context.
	if _, err := opener.Open(nil, bytes.Repeat([]byte{0x61}, 32)); err == nil {
		t.Fatal("nil context accepted")
	}
	canceledContext, cancelBeforeDial := context.WithCancel(context.Background())
	cancelBeforeDial()
	if _, err := opener.Open(canceledContext, bytes.Repeat([]byte{0x61}, 32)); err == nil {
		t.Fatal("canceled context accepted before dial")
	}
	ctx, cancel := context.WithCancel(context.Background())
	opened := make(chan error, 1)
	go func() {
		_, openErr := opener.Open(ctx, bytes.Repeat([]byte{0x61}, 32))
		opened <- openErr
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("client did not connect to stalled TLS peer")
	}
	cancel()
	select {
	case openErr := <-opened:
		if openErr == nil {
			t.Fatal("canceled TLS handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Open did not return after cancellation")
	}
	select {
	case readErr := <-peerClosed:
		if readErr == nil {
			t.Fatal("stalled TLS peer did not observe socket closure")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled TLS socket remained open")
	}
}

func TestHTTP2ClientCarrierTimesOutStalledTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	peerClosed := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			peerClosed <- acceptErr
			return
		}
		_, copyErr := io.Copy(io.Discard, connection)
		peerClosed <- copyErr
		_ = connection.Close()
	}()
	opener := newRawHTTP2TestOpener(t, listener.Addr().String())
	opener.(*http2ClientCarrierOpener).config.Dialer.Timeout = 50 * time.Millisecond
	started := time.Now()
	if _, err := opener.Open(context.Background(), bytes.Repeat([]byte{0x62}, 32)); err == nil {
		t.Fatal("stalled TLS handshake succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled TLS handshake exceeded deadline: %v", elapsed)
	}
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("timed-out TLS socket remained open")
	}
}

func TestHTTP2ClientCarrierCancellationUnblocksLiveStreamOperations(t *testing.T) {
	handlerStarted := make(chan struct{}, 1)
	handlerStopped := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerStarted <- struct{}{}
		<-r.Context().Done()
		handlerStopped <- struct{}{}
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	opener := newLiveHTTP2TestOpener(t, server, http.StatusOK, nil, maxRecordBodyBytes)
	ctx, cancel := context.WithCancel(context.Background())
	carrier, err := opener.Open(ctx, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("server did not receive live HTTP/2 stream")
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := carrier.ReadRecord()
		readDone <- readErr
	}()
	writeDone := make(chan error, 1)
	largeRecord := bytes.Repeat([]byte{0x72}, int(maxRecordBodyBytes))
	go func() { writeDone <- carrier.WriteRecord(largeRecord) }()
	select {
	case err := <-readDone:
		t.Fatalf("response read returned before cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case err := <-writeDone:
		t.Fatalf("flow-controlled request write returned before cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	if err := carrier.Close(); err != nil {
		t.Fatalf("second Close changed result: %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("canceled response read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("response read remained blocked after cancellation")
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("canceled request write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request write remained blocked after cancellation")
	}
	select {
	case <-handlerStopped:
	case <-time.After(time.Second):
		t.Fatal("server stream context remained live after cancellation")
	}
}

func TestHTTP2ClientCarrierCancellationAfterApplicationUpgrade(t *testing.T) {
	handlerStopped := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader, _ := NewRecordReader(r.Body, 1024)
		if _, err := reader.Read(); err != nil {
			t.Errorf("read bootstrap record: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		writer, _ := NewRecordWriter(w, 1024)
		if err := writer.Write([]byte("ready")); err != nil {
			t.Errorf("write bootstrap record: %v", err)
			return
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		handlerStopped <- struct{}{}
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	opener := newLiveHTTP2TestOpener(t, server, http.StatusOK, http.Header{"Content-Type": {"application/octet-stream"}}, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	carrier, err := opener.Open(ctx, bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.WriteRecord([]byte("bootstrap")); err != nil {
		t.Fatal(err)
	}
	if record, err := carrier.ReadRecord(); err != nil || string(record) != "ready" {
		t.Fatalf("read bootstrap response: record=%q err=%v", record, err)
	}
	readStream, writeStream, err := carrier.ApplicationStreams()
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := readStream.Read(make([]byte, 1))
		readDone <- readErr
	}()
	cancel()
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := writeStream.Write([]byte("late")); err == nil {
		t.Fatal("application write succeeded after cancellation")
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("application read succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("application read remained blocked after cancellation")
	}
	select {
	case <-handlerStopped:
	case <-time.After(time.Second):
		t.Fatal("upgraded server stream remained live after cancellation")
	}
}

func TestHTTP2ClientCarrierRejectsNonH2TLS(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("non-H2 server received carrier request")
	}))
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	opener := newLiveHTTP2TestOpener(t, server, http.StatusOK, nil, 1024)
	if _, err := opener.Open(context.Background(), bytes.Repeat([]byte{0x74}, 32)); err == nil {
		t.Fatal("carrier accepted TLS without h2 ALPN")
	}
}

func TestHTTP2ClientCarrierLifecycleSettlesAfterRepeatedClose(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reader, _ := NewRecordReader(r.Body, 128)
		if _, err := reader.Read(); err != nil {
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		writer, _ := NewRecordWriter(w, 128)
		_ = writer.Write([]byte{0x01})
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	opener := newLiveHTTP2TestOpener(t, server, http.StatusOK, http.Header{"Content-Type": {"application/octet-stream"}}, 128)
	baseline := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		carrier, err := opener.Open(context.Background(), bytes.Repeat([]byte{byte(i)}, 32))
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := carrier.WriteRecord([]byte{byte(i + 1)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := carrier.ReadRecord(); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if err := carrier.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}
	server.Close()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline+12 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+12 {
		t.Fatalf("goroutine count did not settle: baseline=%d current=%d", baseline, got)
	}
}

func TestHTTP2ClientCarrierClearsBindingAfterClose(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	opener := newLiveHTTP2TestOpener(t, server, http.StatusOK, nil, 1024)
	carrier, err := opener.Open(context.Background(), bytes.Repeat([]byte{0x75}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if binding := carrier.Binding(); len(binding.HandshakeBindingContext) == 0 {
		t.Fatal("open carrier did not expose its handshake binding")
	}
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	if binding := carrier.Binding(); len(binding.OuterExporterValue) != 0 || len(binding.TLSExporterChannelID) != 0 || len(binding.ConnectionIDHash) != 0 || len(binding.CoverStreamBinding) != 0 || len(binding.HandshakeBindingContext) != 0 {
		t.Fatal("closed carrier retained handshake binding material")
	}
}

func TestHTTP2ClientCarrierBuildsAuthenticatedStreamingRequest(t *testing.T) {
	tpl := transportTemplate(registry.MethodWebH2Stream)
	tpl.PublicNameHash = bytes.Repeat([]byte{0x21}, 48)
	in := CarrierRequestInput{
		Plan: CarrierPlan{
			Carrier: Carrier{MethodID: registry.MethodWebH2Stream, Name: "web.h2.stream"},
			UDPMode: UDPOverStreamFallback,
		},
		Template:       tpl,
		RequestClassID: 1,
		Scheme:         "https",
		Authority:      "cover.example:443",
		Path:           "/assets/upload/42",
		Header: http.Header{
			"Accept":       {"application/octet-stream"},
			"X-Cover-Mode": {"ordinary"},
		},
	}

	built, err := BuildStreamingH2CarrierRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	if built.MethodID != registry.MethodWebH2Stream || built.RequestClassID != 1 {
		t.Fatalf("unexpected request metadata: %+v", built)
	}
	request := built.Request
	if request.Method != http.MethodPost || request.URL.Scheme != "https" || request.Host != in.Authority || request.URL.Path != in.Path {
		t.Fatalf("unexpected streaming request: %+v", request)
	}
	if request.Body != nil || request.ContentLength != -1 {
		t.Fatalf("streaming request body state = (%T, %d), want (nil, -1)", request.Body, request.ContentLength)
	}
	if request.Header.Get("Content-Type") != "" || request.Header.Get("Accept") != "application/octet-stream" {
		t.Fatalf("streaming builder invented or lost visible headers: %v", request.Header)
	}
	in.Header.Set("Accept", "mutated")
	if request.Header.Get("Accept") != "application/octet-stream" {
		t.Fatal("streaming request aliases caller headers")
	}

	config := validHTTP2ClientCarrierConfig(request, tpl)
	if _, err := NewHTTP2ClientCarrierOpener(config); err != nil {
		t.Fatalf("valid streaming request rejected: %v", err)
	}

	wrong := config
	wrong.BindingMetadata.PathTemplateID = bytes.Repeat([]byte{0x55}, 16)
	if _, err := NewHTTP2ClientCarrierOpener(wrong); err == nil {
		t.Fatal("opener accepted request whose path binding metadata did not match the builder")
	}
}

func TestHTTP2ClientCarrierStreamingBuilderRejectsInvalidInputs(t *testing.T) {
	validInput := func() CarrierRequestInput {
		tpl := transportTemplate(registry.MethodWebH2Stream)
		tpl.PublicNameHash = bytes.Repeat([]byte{0x21}, 48)
		return CarrierRequestInput{
			Plan:           CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream}, UDPMode: UDPOverStreamFallback},
			Template:       tpl,
			RequestClassID: 1,
			Scheme:         "https",
			Authority:      "cover.example:443",
			Path:           "/upload",
			Header:         http.Header{"X-Cover-Mode": {"ordinary"}},
		}
	}
	tests := []struct {
		name   string
		mutate func(*CarrierRequestInput)
	}{
		{name: "wrong method", mutate: func(in *CarrierRequestInput) { in.Plan.Carrier.MethodID = registry.MethodWebH1WS }},
		{name: "wrong UDP mode", mutate: func(in *CarrierRequestInput) { in.Plan.UDPMode = UDPNativeDatagram }},
		{name: "staged payload", mutate: func(in *CarrierRequestInput) { in.Payload = []byte{1} }},
		{name: "class without capsule", mutate: func(in *CarrierRequestInput) { in.Template.RequestClasses[0].MayCarryCapsule = false }},
		{name: "authority hash", mutate: func(in *CarrierRequestInput) { in.Template.PublicNameHash = []byte{1} }},
		{name: "path ID", mutate: func(in *CarrierRequestInput) { in.Template.RequestClasses[0].PathTemplateID = []byte{1} }},
		{name: "HTTP URL", mutate: func(in *CarrierRequestInput) { in.Scheme = "http" }},
		{name: "query delimiter in path", mutate: func(in *CarrierRequestInput) { in.Path = "/upload?" }},
		{name: "fragment delimiter in path", mutate: func(in *CarrierRequestInput) { in.Path = "/upload#fragment" }},
		{name: "visible marker", mutate: func(in *CarrierRequestInput) { in.Header.Set("X-Service", "aurora") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validInput()
			test.mutate(&input)
			if _, err := BuildStreamingH2CarrierRequest(input); err == nil {
				t.Fatal("invalid streaming request accepted")
			}
		})
	}
}

func TestHTTP2ClientCarrierRejectsUnsafeConfiguration(t *testing.T) {
	tpl := transportTemplate(registry.MethodWebH2Stream)
	tpl.PublicNameHash = bytes.Repeat([]byte{0x21}, 48)
	built, err := BuildStreamingH2CarrierRequest(CarrierRequestInput{
		Plan:           CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream}, UDPMode: UDPOverStreamFallback},
		Template:       tpl,
		RequestClassID: 1,
		Scheme:         "https",
		Authority:      "cover.example:443",
		Path:           "/upload",
		Header:         http.Header{"Accept": {"application/octet-stream"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := validHTTP2ClientCarrierConfig(built.Request, tpl)

	tests := []struct {
		name   string
		mutate func(*HTTP2ClientCarrierConfig)
	}{
		{name: "nil request", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request = nil }},
		{name: "http URL", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.URL.Scheme = "http" }},
		{name: "non POST", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.Method = http.MethodGet }},
		{name: "empty authority", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.Host = "" }},
		{name: "changed authority", mutate: func(c *HTTP2ClientCarrierConfig) {
			c.Request.Host = "other.example:443"
			c.Request.URL.Host = "other.example:443"
		}},
		{name: "empty path", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.URL.Path = "" }},
		{name: "changed path", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.URL.Path = "/other" }},
		{name: "encoded path", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.URL.RawPath = "/%75pload" }},
		{name: "query delimiter in path", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.URL.Path = "/upload?" }},
		{name: "fragment delimiter in path", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.URL.Path = "/upload#fragment" }},
		{name: "query", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.URL.RawQuery = "page=1" }},
		{name: "request trailer", mutate: func(c *HTTP2ClientCarrierConfig) { c.Request.Trailer = http.Header{"X-End": {"yes"}} }},
		{name: "unbuilt request", mutate: func(c *HTTP2ClientCarrierConfig) {
			request, err := http.NewRequest(http.MethodPost, "https://cover.example:443/upload", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "cover.example:443"
			c.Request = request
		}},
		{name: "nil TLS", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig = nil }},
		{name: "system roots", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.RootCAs = nil }},
		{name: "insecure", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.InsecureSkipVerify = true }},
		{name: "old TLS", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.MinVersion = tls.VersionTLS12 }},
		{name: "future maximum", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.MaxVersion = tls.VersionTLS12 }},
		{name: "session cache", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1) }},
		{name: "key log", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.KeyLogWriter = io.Discard }},
		{name: "wrong ALPN", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.NextProtos = []string{"http/1.1"} }},
		{name: "wrong server name", mutate: func(c *HTTP2ClientCarrierConfig) { c.TLSConfig.ServerName = "other.example" }},
		{name: "wrong method metadata", mutate: func(c *HTTP2ClientCarrierConfig) { c.BindingMetadata.MethodFamilyID = registry.MethodWebH1WS }},
		{name: "wrong class metadata", mutate: func(c *HTTP2ClientCarrierConfig) { c.BindingMetadata.RequestClassID++ }},
		{name: "wrong authority metadata", mutate: func(c *HTTP2ClientCarrierConfig) { c.BindingMetadata.NormalizedAuthorityHash[0] ^= 0xff }},
		{name: "wrong path metadata", mutate: func(c *HTTP2ClientCarrierConfig) { c.BindingMetadata.PathTemplateID[0] ^= 0xff }},
		{name: "bad status", mutate: func(c *HTTP2ClientCarrierConfig) { c.ExpectedStatus = 99 }},
		{name: "informational status", mutate: func(c *HTTP2ClientCarrierConfig) { c.ExpectedStatus = 199 }},
		{name: "visible response marker", mutate: func(c *HTTP2ClientCarrierConfig) { c.ExpectedHeader.Set("X-Service", "aurora") }},
		{name: "oversized record", mutate: func(c *HTTP2ClientCarrierConfig) { c.MaxRecordBodyBytes = 1 << 24 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := cloneHTTP2ClientCarrierConfig(base)
			test.mutate(&config)
			if _, err := NewHTTP2ClientCarrierOpener(config); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestHTTP2ClientCarrierOpenerOwnsConfiguration(t *testing.T) {
	tpl := transportTemplate(registry.MethodWebH2Stream)
	tpl.PublicNameHash = bytes.Repeat([]byte{0x21}, 48)
	built, err := BuildStreamingH2CarrierRequest(CarrierRequestInput{
		Plan:           CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream}, UDPMode: UDPOverStreamFallback},
		Template:       tpl,
		RequestClassID: 1,
		Scheme:         "https",
		Authority:      "cover.example:443",
		Path:           "/upload",
		Header:         http.Header{"X-Cover-Mode": {"ordinary"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := validHTTP2ClientCarrierConfig(built.Request, tpl)
	config.Dialer = &net.Dialer{Timeout: time.Second}
	opener, err := NewHTTP2ClientCarrierOpener(config)
	if err != nil {
		t.Fatal(err)
	}
	owned := opener.(*http2ClientCarrierOpener).config
	if owned.Request == config.Request || owned.TLSConfig == config.TLSConfig || owned.TLSConfig.RootCAs == config.TLSConfig.RootCAs || owned.Dialer == config.Dialer {
		t.Fatal("opener retained mutable caller configuration")
	}

	config.Request.Header.Set("X-Cover-Mode", "mutated")
	config.TLSConfig.NextProtos[0] = "http/1.1"
	config.BindingMetadata.NormalizedAuthorityHash[0] ^= 0xff
	config.ExpectedHeader.Set("Content-Type", "text/plain")
	config.Dialer.Timeout = 9 * time.Second
	if owned.Request.Header.Get("X-Cover-Mode") != "ordinary" || owned.TLSConfig.NextProtos[0] != "h2" || owned.BindingMetadata.NormalizedAuthorityHash[0] != 0x21 || owned.ExpectedHeader.Get("Content-Type") != "application/octet-stream" || owned.Dialer.Timeout != time.Second {
		t.Fatal("caller mutation changed opener configuration")
	}
}

func TestHTTP2ClientCarrierTLSStateRejectsResumptionAndDowngrade(t *testing.T) {
	valid := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		HandshakeComplete:  true,
		NegotiatedProtocol: "h2",
	}
	if err := validateHTTP2TLSState(valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*tls.ConnectionState)
	}{
		{name: "incomplete", mutate: func(s *tls.ConnectionState) { s.HandshakeComplete = false }},
		{name: "old TLS", mutate: func(s *tls.ConnectionState) { s.Version = tls.VersionTLS12 }},
		{name: "wrong ALPN", mutate: func(s *tls.ConnectionState) { s.NegotiatedProtocol = "http/1.1" }},
		{name: "resumed", mutate: func(s *tls.ConnectionState) { s.DidResume = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := valid
			test.mutate(&state)
			if err := validateHTTP2TLSState(state); err == nil {
				t.Fatal("unsafe TLS state accepted")
			}
		})
	}
}

func validHTTP2ClientCarrierConfig(request *http.Request, template protocol.CoverTemplate) HTTP2ClientCarrierConfig {
	return HTTP2ClientCarrierConfig{
		Request: request,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			RootCAs:    x509.NewCertPool(),
			NextProtos: []string{"h2"},
		},
		BindingMetadata: handshake.HTTP2BindingMetadata{
			NormalizedAuthorityHash: append([]byte(nil), template.PublicNameHash...),
			PathTemplateID:          append([]byte(nil), template.RequestClasses[0].PathTemplateID...),
			RequestClassID:          template.RequestClasses[0].ClassID,
			MethodFamilyID:          template.RequestClasses[0].AllowedMethodFamily,
		},
		ExpectedStatus: http.StatusOK,
		ExpectedHeader: http.Header{"Content-Type": {"application/octet-stream"}},
	}
}

func cloneHTTP2ClientCarrierConfig(in HTTP2ClientCarrierConfig) HTTP2ClientCarrierConfig {
	out := in
	if in.Request != nil {
		out.Request = in.Request.Clone(in.Request.Context())
	}
	if in.TLSConfig != nil {
		out.TLSConfig = in.TLSConfig.Clone()
	}
	out.BindingMetadata = handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), in.BindingMetadata.NormalizedAuthorityHash...),
		PathTemplateID:          append([]byte(nil), in.BindingMetadata.PathTemplateID...),
		RequestClassID:          in.BindingMetadata.RequestClassID,
		MethodFamilyID:          in.BindingMetadata.MethodFamilyID,
	}
	out.ExpectedHeader = cloneHeader(in.ExpectedHeader)
	return out
}

func newLiveHTTP2TestOpener(t *testing.T, server *httptest.Server, status int, header http.Header, maximum uint32) handshake.ClientCarrierOpener {
	t.Helper()
	tpl := transportTemplate(registry.MethodWebH2Stream)
	tpl.PublicNameHash = bytes.Repeat([]byte{0x21}, 48)
	built, err := BuildStreamingH2CarrierRequest(CarrierRequestInput{
		Plan:           CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream}, UDPMode: UDPOverStreamFallback},
		Template:       tpl,
		RequestClassID: 1,
		Scheme:         "https",
		Authority:      server.Listener.Addr().String(),
		Path:           "/assets/upload/42",
		Header:         http.Header{"X-Cover-Mode": {"ordinary"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := validHTTP2ClientCarrierConfig(built.Request, tpl)
	config.TLSConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.TLSConfig.MaxVersion = tls.VersionTLS13
	config.TLSConfig.NextProtos = []string{"h2"}
	config.TLSConfig.ClientSessionCache = nil
	config.ExpectedStatus = status
	config.ExpectedHeader = cloneHeader(header)
	config.MaxRecordBodyBytes = maximum
	opener, err := NewHTTP2ClientCarrierOpener(config)
	if err != nil {
		t.Fatal(err)
	}
	return opener
}

func newRawHTTP2TestOpener(t *testing.T, address string) handshake.ClientCarrierOpener {
	t.Helper()
	tpl := transportTemplate(registry.MethodWebH2Stream)
	tpl.PublicNameHash = bytes.Repeat([]byte{0x21}, 48)
	built, err := BuildStreamingH2CarrierRequest(CarrierRequestInput{
		Plan:           CarrierPlan{Carrier: Carrier{MethodID: registry.MethodWebH2Stream}, UDPMode: UDPOverStreamFallback},
		Template:       tpl,
		RequestClassID: 1,
		Scheme:         "https",
		Authority:      address,
		Path:           "/assets/upload/42",
		Header:         http.Header{"X-Cover-Mode": {"ordinary"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := validHTTP2ClientCarrierConfig(built.Request, tpl)
	opener, err := NewHTTP2ClientCarrierOpener(config)
	if err != nil {
		t.Fatal(err)
	}
	return opener
}
