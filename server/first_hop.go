package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	defaultFirstHopPostHeaderTimeout = time.Second
	defaultFirstHopPreHeaderTimeout  = 5 * time.Second
	defaultFirstHopReadHeaderTimeout = 5 * time.Second
	defaultFirstHopIdleTimeout       = 2 * time.Minute
	minimumFirstHopWriteTimeout      = 5 * time.Second
	maximumFirstHopPostHeaderTimeout = 30 * time.Second
	maximumFirstHopRecordBodyBytes   = 0xffffff
)

// FirstHopOptions defines one authenticated HTTP/2 gateway-owned request slot.
type FirstHopOptions struct {
	Driver             *handshake.RelayDriver
	Authority          string
	Path               string
	BindingMetadata    handshake.HTTP2BindingMetadata
	CoverStatus        int
	CoverHeader        http.Header
	Origin             relay.Origin
	CoverOrigin        http.Handler
	MaxRecordBodyBytes uint32
	FrameHandler       transport.FrameBlockHandler
	PostHeaderTimeout  time.Duration
}

// FirstHopHandler admits at most the first request on each HTTP/2 connection.
type FirstHopHandler struct {
	driver             *handshake.RelayDriver
	authority          string
	path               string
	bindingMetadata    handshake.HTTP2BindingMetadata
	coverStatus        int
	coverHeader        http.Header
	origin             relay.Origin
	coverOrigin        http.Handler
	maxRecordBodyBytes uint32
	frameHandler       transport.FrameBlockHandler
	preHeaderTimeout   time.Duration
	postHeaderTimeout  time.Duration
	begin              firstHopBeginFunc
	finish             firstHopFinishFunc
	sessionMu          sync.Mutex
	sessions           map[uint64]context.CancelFunc
	nextSessionID      uint64
	shuttingDown       bool
}

type firstHopBeginFunc func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error)
type firstHopFinishFunc func(context.Context, *handshake.RelayHandshake, []byte, uint64) ([]byte, transport.PacketEndpoint, error)

type firstHopConnectionContextKey struct{}

type firstHopConnectionState struct {
	mu              sync.Mutex
	stream1Observed bool
	poisoned        bool
	activeCancel    context.CancelFunc
}

// NewFirstHopHandler validates and takes an owned snapshot of options.
func NewFirstHopHandler(options FirstHopOptions) (*FirstHopHandler, error) {
	if options.Driver == nil {
		return nil, fmt.Errorf("server: first-hop relay driver is required")
	}
	authority := strings.TrimSpace(options.Authority)
	if authority == "" || authority != options.Authority || strings.ContainsAny(authority, "/?#") {
		return nil, fmt.Errorf("server: first-hop authority is invalid")
	}
	if options.Path == "" || options.Path[0] != '/' || strings.ContainsAny(options.Path, "?#") {
		return nil, fmt.Errorf("server: first-hop path is invalid")
	}
	metadata := options.BindingMetadata
	if len(metadata.NormalizedAuthorityHash) != 48 || len(metadata.PathTemplateID) != 16 {
		return nil, fmt.Errorf("server: first-hop binding metadata length is invalid")
	}
	if metadata.RequestClassID == 0 || metadata.RequestClassID > wire.MaxVarint || metadata.MethodFamilyID != registry.MethodWebH2Stream {
		return nil, fmt.Errorf("server: first-hop binding metadata identifiers are invalid")
	}
	if options.CoverStatus < 200 || options.CoverStatus > 599 || options.CoverStatus == http.StatusNoContent || options.CoverStatus == http.StatusResetContent || options.CoverStatus == http.StatusNotModified {
		return nil, fmt.Errorf("server: first-hop cover status cannot carry a response body")
	}
	if err := validateFirstHopVisibleHeader(options.CoverHeader); err != nil {
		return nil, err
	}
	if options.Origin != nil && isNilFirstHopInterface(options.Origin) {
		return nil, fmt.Errorf("server: first-hop cover origin is typed nil")
	}
	if options.CoverOrigin != nil && isNilFirstHopInterface(options.CoverOrigin) {
		return nil, fmt.Errorf("server: first-hop HTTP cover origin is typed nil")
	}
	if options.Origin == nil && options.CoverOrigin == nil {
		return nil, fmt.Errorf("server: first-hop cover origin is required")
	}
	maximum := options.MaxRecordBodyBytes
	if maximum == 0 {
		maximum = transport.DefaultMaxRecordBodyBytes
	}
	if maximum > maximumFirstHopRecordBodyBytes {
		return nil, fmt.Errorf("server: first-hop record maximum exceeds unsigned-24 limit")
	}
	if options.FrameHandler == nil {
		return nil, fmt.Errorf("server: first-hop frame handler is required")
	}
	postHeaderTimeout := options.PostHeaderTimeout
	if postHeaderTimeout == 0 {
		postHeaderTimeout = defaultFirstHopPostHeaderTimeout
	}
	if postHeaderTimeout < 0 || postHeaderTimeout > maximumFirstHopPostHeaderTimeout {
		return nil, fmt.Errorf("server: first-hop post-header timeout is invalid")
	}
	metadata = handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), metadata.NormalizedAuthorityHash...),
		PathTemplateID:          append([]byte(nil), metadata.PathTemplateID...),
		RequestClassID:          metadata.RequestClassID,
		MethodFamilyID:          metadata.MethodFamilyID,
	}
	handler := &FirstHopHandler{
		driver:             options.Driver,
		authority:          authority,
		path:               options.Path,
		bindingMetadata:    metadata,
		coverStatus:        options.CoverStatus,
		coverHeader:        options.CoverHeader.Clone(),
		origin:             options.Origin,
		coverOrigin:        options.CoverOrigin,
		maxRecordBodyBytes: maximum,
		frameHandler:       options.FrameHandler,
		preHeaderTimeout:   defaultFirstHopPreHeaderTimeout,
		postHeaderTimeout:  postHeaderTimeout,
		sessions:           make(map[uint64]context.CancelFunc),
	}
	handler.begin = handler.driver.Begin
	handler.finish = func(ctx context.Context, state *handshake.RelayHandshake, capsule1 []byte, nowUnix uint64) ([]byte, transport.PacketEndpoint, error) {
		capsule2, application, _, err := state.Finish(ctx, capsule1, nowUnix)
		return capsule2, application, err
	}
	return handler, nil
}

// ConnContext attaches fresh request-ownership state to one accepted connection.
func (h *FirstHopHandler) ConnContext(ctx context.Context, connection net.Conn) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if h == nil || connection == nil {
		return ctx
	}
	return context.WithValue(ctx, firstHopConnectionContextKey{}, &firstHopConnectionState{})
}

// NewFirstHopHTTPServer constructs a TLS 1.3, HTTP/2-only server. A valid
// carrier clears the ordinary response write deadline after authentication.
func NewFirstHopHTTPServer(address string, handler *FirstHopHandler, tlsConfig *tls.Config) (*http.Server, error) {
	if strings.TrimSpace(address) == "" {
		return nil, fmt.Errorf("server: first-hop listen address is required")
	}
	if handler == nil {
		return nil, fmt.Errorf("server: first-hop handler is required")
	}
	if tlsConfig == nil {
		return nil, fmt.Errorf("server: first-hop TLS configuration is required")
	}
	if len(tlsConfig.Certificates) == 0 {
		return nil, fmt.Errorf("server: first-hop TLS certificate is required")
	}
	for _, certificate := range tlsConfig.Certificates {
		if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return nil, fmt.Errorf("server: first-hop TLS certificate chain or private key is missing")
		}
	}
	if tlsConfig.GetConfigForClient != nil {
		return nil, fmt.Errorf("server: first-hop dynamic TLS configuration is forbidden")
	}
	if tlsConfig.GetCertificate != nil {
		return nil, fmt.Errorf("server: first-hop dynamic TLS certificate is forbidden")
	}
	if tlsConfig.GetEncryptedClientHelloKeys != nil {
		return nil, fmt.Errorf("server: first-hop dynamic ECH keys are forbidden")
	}
	if tlsConfig.VerifyPeerCertificate != nil || tlsConfig.VerifyConnection != nil {
		return nil, fmt.Errorf("server: first-hop dynamic TLS verification is forbidden")
	}
	if tlsConfig.Rand != nil {
		return nil, fmt.Errorf("server: first-hop custom TLS randomness is forbidden")
	}
	if tlsConfig.Time != nil {
		return nil, fmt.Errorf("server: first-hop custom TLS time is forbidden")
	}
	//lint:ignore SA1019 Reject the deprecated map so it cannot bypass owned certificate selection.
	if tlsConfig.NameToCertificate != nil {
		return nil, fmt.Errorf("server: first-hop deprecated certificate map is forbidden")
	}
	if tlsConfig.WrapSession != nil || tlsConfig.UnwrapSession != nil {
		return nil, fmt.Errorf("server: first-hop TLS session callbacks are forbidden")
	}
	if tlsConfig.MinVersion != 0 && tlsConfig.MinVersion != tls.VersionTLS13 {
		return nil, fmt.Errorf("server: first-hop TLS minimum must be TLS 1.3")
	}
	if tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion != tls.VersionTLS13 {
		return nil, fmt.Errorf("server: first-hop TLS maximum must be TLS 1.3")
	}
	if len(tlsConfig.NextProtos) != 0 && (len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "h2") {
		return nil, fmt.Errorf("server: first-hop ALPN must be h2 only")
	}
	if tlsConfig.KeyLogWriter != nil {
		return nil, fmt.Errorf("server: first-hop TLS key logging is forbidden")
	}
	if tlsConfig.ClientAuth != tls.NoClientCert || tlsConfig.ClientCAs != nil {
		return nil, fmt.Errorf("server: first-hop TLS client certificates are forbidden")
	}
	ownedCertificates, err := cloneFirstHopCertificates(tlsConfig.Certificates)
	if err != nil {
		return nil, err
	}
	ownedTLS := tlsConfig.Clone()
	ownedTLS.Certificates = ownedCertificates
	ownedTLS.GetCertificate = nil
	ownedTLS.GetClientCertificate = nil
	ownedTLS.GetConfigForClient = nil
	ownedTLS.GetEncryptedClientHelloKeys = nil
	ownedTLS.VerifyPeerCertificate = nil
	ownedTLS.VerifyConnection = nil
	ownedTLS.Rand = nil
	ownedTLS.Time = nil
	ownedTLS.RootCAs = nil
	ownedTLS.ClientCAs = nil
	ownedTLS.ClientSessionCache = nil
	ownedTLS.UnwrapSession = nil
	ownedTLS.WrapSession = nil
	ownedTLS.CipherSuites = append([]uint16(nil), tlsConfig.CipherSuites...)
	ownedTLS.CurvePreferences = append([]tls.CurveID(nil), tlsConfig.CurvePreferences...)
	ownedTLS.EncryptedClientHelloConfigList = nil
	ownedTLS.EncryptedClientHelloRejectionVerify = nil
	ownedTLS.EncryptedClientHelloKeys = cloneFirstHopECHKeys(tlsConfig.EncryptedClientHelloKeys)
	ownedTLS.MinVersion = tls.VersionTLS13
	ownedTLS.MaxVersion = tls.VersionTLS13
	ownedTLS.NextProtos = []string{"h2"}
	ownedTLS.SessionTicketsDisabled = true
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	writeTimeout := minimumFirstHopWriteTimeout
	if candidate := 2 * handler.postHeaderTimeout; candidate > writeTimeout {
		writeTimeout = candidate
	}
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		TLSConfig:         ownedTLS,
		ReadHeaderTimeout: defaultFirstHopReadHeaderTimeout,
		IdleTimeout:       defaultFirstHopIdleTimeout,
		WriteTimeout:      writeTimeout,
		MaxHeaderBytes:    1 << 20,
		ConnContext:       handler.ConnContext,
		Protocols:         protocols,
	}
	server.RegisterOnShutdown(handler.shutdown)
	return server, nil
}

func cloneFirstHopCertificates(certificates []tls.Certificate) ([]tls.Certificate, error) {
	owned := make([]tls.Certificate, len(certificates))
	for i, certificate := range certificates {
		owned[i] = tls.Certificate{
			Certificate:                  cloneFirstHopByteSlices(certificate.Certificate),
			PrivateKey:                   certificate.PrivateKey,
			SupportedSignatureAlgorithms: append([]tls.SignatureScheme(nil), certificate.SupportedSignatureAlgorithms...),
			OCSPStaple:                   append([]byte(nil), certificate.OCSPStaple...),
			SignedCertificateTimestamps:  cloneFirstHopByteSlices(certificate.SignedCertificateTimestamps),
		}
		leaf, err := x509.ParseCertificate(owned[i].Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("server: parse first-hop TLS leaf certificate: %w", err)
		}
		owned[i].Leaf = leaf
	}
	return owned, nil
}

func cloneFirstHopECHKeys(keys []tls.EncryptedClientHelloKey) []tls.EncryptedClientHelloKey {
	owned := make([]tls.EncryptedClientHelloKey, len(keys))
	for i, key := range keys {
		owned[i] = tls.EncryptedClientHelloKey{
			Config:      append([]byte(nil), key.Config...),
			PrivateKey:  append([]byte(nil), key.PrivateKey...),
			SendAsRetry: key.SendAsRetry,
		}
	}
	return owned
}

func cloneFirstHopByteSlices(values [][]byte) [][]byte {
	owned := make([][]byte, len(values))
	for i, value := range values {
		owned[i] = append([]byte(nil), value...)
	}
	return owned
}

func (h *FirstHopHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if h == nil || request == nil {
		return
	}
	state, hasConnectionState := request.Context().Value(firstHopConnectionContextKey{}).(*firstHopConnectionState)
	sessionContext, cancel := context.WithCancel(request.Context())
	if !hasConnectionState {
		cancel()
		h.serveUnclaimedCover(w, request)
		return
	}
	streamID, hasStreamID := firstHopHTTP2StreamID(w)
	if !hasStreamID {
		cancel()
		h.serveUnclaimedCover(w, request)
		return
	}
	claimed, priorCancel := state.enterStream(streamID, cancel)
	if !claimed {
		cancel()
		if priorCancel != nil {
			priorCancel()
		}
		h.serveUnclaimedCover(w, request)
		return
	}
	defer state.clearActive()
	defer cancel()
	if request.Body == nil {
		request.Body = http.NoBody
	}
	defer request.Body.Close()
	if !h.isCandidate(request) {
		if h.isGatewayTarget(request) {
			h.servePreHeaderFailure(w, request)
			return
		}
		serveCoverRequest(w, request, h.origin, h.coverOrigin)
		return
	}
	sessionID, registered := h.registerSession(cancel)
	if !registered {
		h.servePreHeaderFailure(w, request)
		return
	}
	defer h.unregisterSession(sessionID)
	if err := h.serveCandidate(sessionContext, cancel, w, request); err != nil {
		return
	}
}

func (h *FirstHopHandler) registerSession(cancel context.CancelFunc) (uint64, bool) {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	if h.shuttingDown || h.nextSessionID == ^uint64(0) {
		return 0, false
	}
	h.nextSessionID++
	sessionID := h.nextSessionID
	h.sessions[sessionID] = cancel
	return sessionID, true
}

func (h *FirstHopHandler) unregisterSession(sessionID uint64) {
	h.sessionMu.Lock()
	delete(h.sessions, sessionID)
	h.sessionMu.Unlock()
}

func (h *FirstHopHandler) shutdown() {
	h.sessionMu.Lock()
	h.shuttingDown = true
	cancels := make([]context.CancelFunc, 0, len(h.sessions))
	for sessionID, cancel := range h.sessions {
		cancels = append(cancels, cancel)
		delete(h.sessions, sessionID)
	}
	h.sessionMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (h *FirstHopHandler) serveCandidate(ctx context.Context, cancel context.CancelFunc, w http.ResponseWriter, request *http.Request) error {
	controller := http.NewResponseController(w)
	var headersCommitted atomic.Bool
	cancellationDeadlineDone := make(chan struct{})
	stopCancellationDeadline := context.AfterFunc(ctx, func() {
		defer close(cancellationDeadlineDone)
		now := time.Now()
		_ = controller.SetReadDeadline(now)
		if headersCommitted.Load() {
			_ = controller.SetWriteDeadline(now)
		}
	})
	defer func() {
		if stopCancellationDeadline() {
			close(cancellationDeadlineDone)
		}
		<-cancellationDeadlineDone
	}()
	preHeaderContext, stopPreHeader := context.WithTimeout(ctx, h.preHeaderTimeout)
	defer stopPreHeader()
	if err := controller.SetReadDeadline(time.Now().Add(h.preHeaderTimeout)); err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	recordReader, err := transport.NewRecordReader(request.Body, h.maxRecordBodyBytes)
	if err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	preludeRecord, err := recordReader.Read()
	if err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	defer zeroFirstHopBytes(preludeRecord)
	prelude0, err := decodeFirstHopPrelude0(preludeRecord)
	if err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	defer zeroFirstHopPrelude0(&prelude0)
	binding, err := handshake.DeriveHTTP2FirstHopBinding(*request.TLS, h.bindingMetadata, prelude0.ClientCoverRandom)
	if err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	defer zeroFirstHopBinding(&binding)
	handshakeState, prelude1, err := h.begin(preHeaderContext, binding, prelude0, uint64(time.Now().Unix()))
	if err != nil {
		if handshakeState != nil {
			_ = handshakeState.Close()
		}
		zeroFirstHopPrelude1(&prelude1)
		h.servePreHeaderFailure(w, request)
		return err
	}
	if handshakeState == nil {
		zeroFirstHopPrelude1(&prelude1)
		h.servePreHeaderFailure(w, request)
		return fmt.Errorf("server: first-hop Begin returned nil handshake state")
	}
	defer handshakeState.Close()
	defer zeroFirstHopPrelude1(&prelude1)
	prelude1Record, err := protocol.Encode(prelude1)
	if err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	defer zeroFirstHopBytes(prelude1Record)
	if len(prelude1Record) == 0 || uint64(len(prelude1Record)) > uint64(h.maxRecordBodyBytes) {
		h.servePreHeaderFailure(w, request)
		return fmt.Errorf("server: first-hop Prelude1 exceeds record boundary")
	}
	if err := preHeaderContext.Err(); err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	stopPreHeader()

	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	if err := commitFirstHopCarrierHeaders(ctx, w, h.coverHeader, h.coverStatus, &headersCommitted); err != nil {
		h.servePreHeaderFailure(w, request)
		return err
	}
	postHeaderContext, stopPostHeader, err := beginFirstHopPostHeader(ctx, controller, h.postHeaderTimeout)
	if err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	defer stopPostHeader()
	recordWriter, err := transport.NewRecordWriter(w, h.maxRecordBodyBytes)
	if err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	if err := recordWriter.Write(prelude1Record); err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	if err := controller.Flush(); err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}

	capsule1Record, err := recordReader.Read()
	if err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	defer zeroFirstHopBytes(capsule1Record)
	capsule2Record, application, err := h.finish(postHeaderContext, handshakeState, capsule1Record, uint64(time.Now().Unix()))
	if err != nil {
		zeroFirstHopBytes(capsule2Record)
		if !isNilFirstHopInterface(application) {
			_ = application.Close()
		}
		abortFirstHopAfterHeader(cancel)
		return err
	}
	if isNilFirstHopInterface(application) {
		zeroFirstHopBytes(capsule2Record)
		abortFirstHopAfterHeader(cancel)
		return fmt.Errorf("server: first-hop Finish returned nil application")
	}
	defer zeroFirstHopBytes(capsule2Record)
	defer application.Close()
	if err := recordWriter.Write(capsule2Record); err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	if err := controller.Flush(); err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	if err := postHeaderContext.Err(); err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	stopPostHeader()
	if err := controller.SetReadDeadline(time.Time{}); err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		abortFirstHopAfterHeader(cancel)
		return err
	}
	writeStream := &firstHopResponseWriteCloser{writer: w, controller: controller, cancel: cancel}
	return transport.RunPacketDuplex(ctx, request.Body, writeStream, application, h.frameHandler, h.maxRecordBodyBytes)
}

func commitFirstHopCarrierHeaders(ctx context.Context, writer http.ResponseWriter, header http.Header, status int, committed *atomic.Bool) error {
	destination := writer.Header()
	if err := ctx.Err(); err != nil {
		return err
	}
	copyFirstHopHeader(destination, header)
	if err := ctx.Err(); err != nil {
		copyFirstHopHeader(destination, nil)
		return err
	}
	committed.Store(true)
	writer.WriteHeader(status)
	return nil
}

func beginFirstHopPostHeader(ctx context.Context, controller *http.ResponseController, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	postHeaderContext, stopPostHeader := context.WithTimeout(ctx, timeout)
	fail := func(err error) (context.Context, context.CancelFunc, error) {
		stopPostHeader()
		return nil, nil, err
	}
	deadline := time.Now().Add(timeout)
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := controller.SetReadDeadline(deadline); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := controller.SetWriteDeadline(deadline); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return postHeaderContext, stopPostHeader, nil
}

func (h *FirstHopHandler) isCandidate(request *http.Request) bool {
	if !h.isCandidateTarget(request) || request.TLS == nil || request.ProtoMajor != 2 {
		return false
	}
	state := request.TLS
	return state.HandshakeComplete && state.Version == tls.VersionTLS13 && state.NegotiatedProtocol == "h2" && !state.DidResume
}

func (h *FirstHopHandler) isCandidateTarget(request *http.Request) bool {
	return request.Method == http.MethodPost && h.isGatewayTarget(request) && request.URL.RawPath == "" && request.URL.RawQuery == "" && !request.URL.ForceQuery && request.RequestURI == h.path

}

func (h *FirstHopHandler) isGatewayTarget(request *http.Request) bool {
	return request.Host == h.authority && request.URL != nil && request.URL.Path == h.path
}

func (h *FirstHopHandler) serveUnclaimedCover(w http.ResponseWriter, request *http.Request) {
	if h.isGatewayTarget(request) {
		h.servePreHeaderFailure(w, request)
		return
	}
	serveCoverRequest(w, request, h.origin, h.coverOrigin)
}

func (h *FirstHopHandler) servePreHeaderFailure(w http.ResponseWriter, request *http.Request) {
	serveCoverFailure(w, request, h.origin, h.coverOrigin)
}

func abortFirstHopAfterHeader(cancel context.CancelFunc) {
	cancel()
}

func (s *firstHopConnectionState) enterStream(streamID uint32, cancel context.CancelFunc) (bool, context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if streamID != 1 {
		s.poisoned = true
		prior := s.activeCancel
		s.activeCancel = nil
		return false, prior
	}
	if s.stream1Observed || s.poisoned {
		return false, nil
	}
	s.stream1Observed = true
	s.activeCancel = cancel
	return true, nil
}

func (s *firstHopConnectionState) clearActive() {
	s.mu.Lock()
	s.activeCancel = nil
	s.mu.Unlock()
}

// net/http does not publish server-side HTTP/2 stream identifiers. Inspect the
// supported response-writer shape and fail closed if that implementation changes.
func firstHopHTTP2StreamID(writer http.ResponseWriter) (streamID uint32, ok bool) {
	defer func() {
		if recover() != nil {
			streamID = 0
			ok = false
		}
	}()
	value := reflect.ValueOf(writer)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		return 0, false
	}
	value = value.Elem()
	if value.Kind() != reflect.Struct || value.Type().PkgPath() != "net/http" || value.Type().Name() != "http2responseWriter" {
		return 0, false
	}
	state := value.FieldByName("rws")
	if !state.IsValid() || state.Kind() != reflect.Ptr || state.IsNil() {
		return 0, false
	}
	stream := state.Elem().FieldByName("stream")
	if !stream.IsValid() || stream.Kind() != reflect.Ptr || stream.IsNil() {
		return 0, false
	}
	id := stream.Elem().FieldByName("id")
	if !id.IsValid() || id.Kind() != reflect.Uint32 {
		return 0, false
	}
	streamID = uint32(id.Uint())
	return streamID, streamID != 0
}

type firstHopResponseWriteCloser struct {
	mu         sync.Mutex
	writer     io.Writer
	controller *http.ResponseController
	cancel     context.CancelFunc
	once       sync.Once
	remaining  uint32
}

func (w *firstHopResponseWriteCloser) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.remaining == 0 {
		if len(p) != 3 {
			return 0, fmt.Errorf("server: application record prefix length %d, want 3", len(p))
		}
		n, err := w.writer.Write(p)
		if err != nil {
			return n, err
		}
		if n != len(p) {
			return n, io.ErrShortWrite
		}
		w.remaining = uint32(p[0])<<16 | uint32(p[1])<<8 | uint32(p[2])
		if w.remaining == 0 {
			return n, transport.ErrEmptyRecord
		}
		return n, nil
	}
	if uint32(len(p)) > w.remaining {
		return 0, fmt.Errorf("server: application record body exceeds declared length")
	}
	n, err := w.writer.Write(p)
	if n < 0 || n > len(p) {
		return 0, io.ErrShortWrite
	}
	w.remaining -= uint32(n)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	if w.remaining == 0 {
		if err := w.controller.Flush(); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (w *firstHopResponseWriteCloser) Close() error {
	w.once.Do(func() {
		w.cancel()
	})
	return nil
}

func decodeFirstHopPrelude0(encoded []byte) (protocol.CoverPrelude0, error) {
	reader := wire.NewReader(encoded)
	prelude := protocol.DecodeCoverPrelude0(reader)
	if reader.Err() != nil {
		zeroFirstHopPrelude0(&prelude)
		return protocol.CoverPrelude0{}, reader.Err()
	}
	if !reader.EOF() {
		zeroFirstHopPrelude0(&prelude)
		return protocol.CoverPrelude0{}, fmt.Errorf("server: trailing first-hop Prelude0 bytes")
	}
	return prelude, nil
}

func copyFirstHopHeader(destination, source http.Header) {
	for name := range destination {
		delete(destination, name)
	}
	for name, values := range source {
		destination[name] = append([]string(nil), values...)
	}
}

func validateFirstHopVisibleHeader(header http.Header) error {
	for name, values := range header {
		if !validFirstHopHeaderName(name) {
			return fmt.Errorf("server: first-hop cover header name is invalid")
		}
		switch strings.ToLower(name) {
		case "connection", "content-length", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
			return fmt.Errorf("server: first-hop cover header controls response framing")
		}
		if containsFirstHopMarker(name) {
			return fmt.Errorf("server: first-hop cover header contains protocol marker")
		}
		if len(values) == 0 {
			return fmt.Errorf("server: first-hop cover header has no values")
		}
		for _, value := range values {
			if !validFirstHopHeaderValue(value) {
				return fmt.Errorf("server: first-hop cover header value is invalid")
			}
			if containsFirstHopMarker(value) {
				return fmt.Errorf("server: first-hop cover header value contains protocol marker")
			}
		}
	}
	return nil
}

func containsFirstHopMarker(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"aurora", "proxy", "vpn", "gfw", "china", "auth", "tunnel", "bridge", "relay", "policy", "adversarial", "dpi"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func validFirstHopHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		character := name[i]
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(character)) {
			return false
		}
	}
	return true
}

func validFirstHopHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		character := value[i]
		if character == 0 || character == '\r' || character == '\n' || character == 0x7f || (character < 0x20 && character != '\t') {
			return false
		}
	}
	return true
}

func isNilFirstHopInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func zeroFirstHopBinding(binding *handshake.FirstHopBinding) {
	if binding == nil {
		return
	}
	zeroFirstHopBytes(binding.OuterExporterValue)
	zeroFirstHopBytes(binding.TLSExporterChannelID)
	zeroFirstHopBytes(binding.ConnectionIDHash)
	zeroFirstHopBytes(binding.CoverStreamBinding)
	zeroFirstHopBytes(binding.HandshakeBindingContext)
	*binding = handshake.FirstHopBinding{}
}

func zeroFirstHopPrelude0(prelude *protocol.CoverPrelude0) {
	if prelude == nil {
		return
	}
	zeroFirstHopBytes(prelude.ClientNonce)
	zeroFirstHopBytes(prelude.ClientClassicalEphPub)
	zeroFirstHopBytes(prelude.ClientMLKEMEncapsulationKey)
	zeroFirstHopBytes(prelude.RelayDescriptorHash)
	zeroFirstHopBytes(prelude.CoverTemplateHash)
	zeroFirstHopBytes(prelude.HintIssuerID)
	zeroFirstHopBytes(prelude.RelayBucketID)
	zeroFirstHopBytes(prelude.HintSelector)
	zeroFirstHopBytes(prelude.AccessHint)
	zeroFirstHopBytes(prelude.ClientCoverRandom)
	zeroFirstHopBytes(prelude.Padding)
	zeroFirstHopExtensions(prelude.Extensions)
	*prelude = protocol.CoverPrelude0{}
}

func zeroFirstHopPrelude1(prelude *protocol.CoverPrelude1) {
	if prelude == nil {
		return
	}
	zeroFirstHopBytes(prelude.ServerNonce)
	zeroFirstHopBytes(prelude.ServerClassicalEphPub)
	zeroFirstHopBytes(prelude.ServerMLKEMCiphertextToClient)
	zeroFirstHopBytes(prelude.RelayDescriptorHash)
	zeroFirstHopBytes(prelude.CoverTemplateHash)
	zeroFirstHopBytes(prelude.ServerPreludeSignatureClassical)
	zeroFirstHopBytes(prelude.ServerPreludeSignaturePQ)
	zeroFirstHopBytes(prelude.SelectedCoverProfileID)
	zeroFirstHopBytes(prelude.SelectedBootstrapEnvelopeID)
	zeroFirstHopBytes(prelude.ResponsePadding)
	zeroFirstHopExtensions(prelude.Extensions)
	*prelude = protocol.CoverPrelude1{}
}

func zeroFirstHopExtensions(extensions []protocol.Extension) {
	for i := range extensions {
		zeroFirstHopBytes(extensions[i].Body)
		extensions[i] = protocol.Extension{}
	}
}

func zeroFirstHopBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
