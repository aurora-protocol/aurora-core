package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
)

// HTTP2ClientCarrierConfig defines one immutable cover request template and its
// authenticated response expectations.
type HTTP2ClientCarrierConfig struct {
	Request            *http.Request
	TLSConfig          *tls.Config
	BindingMetadata    handshake.HTTP2BindingMetadata
	ExpectedStatus     int
	ExpectedHeader     http.Header
	MaxRecordBodyBytes uint32
	Dialer             *net.Dialer
}

// HTTP2ClientCarrier owns one fresh TLS connection and its first HTTP/2 stream.
type HTTP2ClientCarrier struct {
	stateMu sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex

	binding        handshake.FirstHopBinding
	transport      *http.Transport
	cancel         context.CancelFunc
	stopParent     func() bool
	requestReader  *io.PipeReader
	requestWriter  *io.PipeWriter
	recordReader   *RecordReader
	recordWriter   *RecordWriter
	result         <-chan http2RoundTripResult
	resultOnce     sync.Once
	response       *http.Response
	responseErr    error
	expectedStatus int
	expectedHeader http.Header
	maxRecordBytes uint32
	responseClosed bool
	upgraded       bool
	closed         bool
	closeOnce      sync.Once
	closeErr       error
}

type http2RoundTripResult struct {
	response *http.Response
	err      error
}

const defaultHTTP2TLSHandshakeTimeout = 10 * time.Second

type http2ClientCarrierOpener struct {
	config HTTP2ClientCarrierConfig
}

// NewHTTP2ClientCarrierOpener validates and takes an owned snapshot of config.
func NewHTTP2ClientCarrierOpener(config HTTP2ClientCarrierConfig) (handshake.ClientCarrierOpener, error) {
	validated, err := validateHTTP2ClientCarrierConfig(config)
	if err != nil {
		return nil, err
	}
	return &http2ClientCarrierOpener{config: validated}, nil
}

func (o *http2ClientCarrierOpener) Open(ctx context.Context, clientCoverRandom []byte) (handshake.BootstrapCarrier, error) {
	if ctx == nil {
		return nil, fmt.Errorf("transport: HTTP/2 carrier context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config := o.config
	runContext, cancel := context.WithCancel(ctx)
	requestReader, requestWriter := io.Pipe()
	recordWriter, err := NewRecordWriter(requestWriter, config.MaxRecordBodyBytes)
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		return nil, err
	}

	request := config.Request.Clone(runContext)
	request.Body = requestReader
	request.GetBody = nil
	request.ContentLength = -1
	request.TransferEncoding = nil
	tlsStates := make(chan tls.ConnectionState, 1)
	var dialMu sync.Mutex
	dialed := false
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 0,
		Protocols:           protocols,
	}
	dialer := *config.Dialer
	transport.DialTLSContext = func(_ context.Context, network, address string) (net.Conn, error) {
		dialMu.Lock()
		if dialed {
			dialMu.Unlock()
			return nil, fmt.Errorf("transport: HTTP/2 carrier attempted a second connection")
		}
		dialed = true
		dialMu.Unlock()

		plain, err := dialer.DialContext(runContext, network, address)
		if err != nil {
			return nil, err
		}
		stopCancellationClose := context.AfterFunc(runContext, func() { _ = plain.Close() })
		defer stopCancellationClose()
		tlsConfig := config.TLSConfig.Clone()
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = request.URL.Hostname()
		}
		connection := tls.Client(plain, tlsConfig)
		handshakeContext, cancelHandshake := context.WithTimeout(runContext, http2TLSHandshakeTimeout(dialer))
		err = connection.HandshakeContext(handshakeContext)
		cancelHandshake()
		if err != nil {
			_ = plain.Close()
			return nil, err
		}
		state := connection.ConnectionState()
		if err := validateHTTP2TLSState(state); err != nil {
			_ = connection.Close()
			return nil, err
		}
		select {
		case tlsStates <- state:
			return connection, nil
		case <-runContext.Done():
			_ = connection.Close()
			return nil, runContext.Err()
		}
	}

	results := make(chan http2RoundTripResult, 1)
	go func() {
		response, roundTripErr := transport.RoundTrip(request)
		results <- http2RoundTripResult{response: response, err: roundTripErr}
	}()
	var resultSource <-chan http2RoundTripResult = results

	failOpen := func(openErr error) (handshake.BootstrapCarrier, error) {
		cancel()
		_ = requestWriter.CloseWithError(openErr)
		_ = requestReader.CloseWithError(openErr)
		transport.CloseIdleConnections()
		result := <-results
		if result.response != nil {
			_ = result.response.Body.Close()
		}
		return nil, openErr
	}

	var earlyResult *http2RoundTripResult
	for {
		select {
		case state := <-tlsStates:
			if err := ctx.Err(); err != nil {
				if earlyResult != nil {
					results <- *earlyResult
				}
				return failOpen(err)
			}
			binding, err := handshake.DeriveHTTP2FirstHopBinding(state, config.BindingMetadata, clientCoverRandom)
			if err != nil {
				if earlyResult != nil {
					results <- *earlyResult
				}
				return failOpen(err)
			}
			carrier := &HTTP2ClientCarrier{
				binding:        binding,
				transport:      transport,
				cancel:         cancel,
				requestReader:  requestReader,
				requestWriter:  requestWriter,
				recordWriter:   recordWriter,
				result:         results,
				expectedStatus: config.ExpectedStatus,
				expectedHeader: cloneHeader(config.ExpectedHeader),
				maxRecordBytes: config.MaxRecordBodyBytes,
			}
			if earlyResult != nil {
				results <- *earlyResult
			}
			carrier.stopParent = context.AfterFunc(ctx, func() { _ = carrier.Close() })
			select {
			case result := <-resultSource:
				results <- result
				if result.err != nil {
					_ = carrier.Close()
					return nil, result.err
				}
			default:
			}
			if err := ctx.Err(); err != nil {
				_ = carrier.Close()
				return nil, err
			}
			return carrier, nil
		case result := <-results:
			if result.err != nil {
				if result.response != nil {
					_ = result.response.Body.Close()
				}
				cancel()
				_ = requestWriter.CloseWithError(result.err)
				_ = requestReader.CloseWithError(result.err)
				transport.CloseIdleConnections()
				return nil, result.err
			}
			earlyResult = &result
			resultSource = nil
		case <-ctx.Done():
			if earlyResult != nil {
				_ = earlyResult.response.Body.Close()
				cancel()
				_ = requestWriter.CloseWithError(ctx.Err())
				_ = requestReader.CloseWithError(ctx.Err())
				transport.CloseIdleConnections()
				return nil, ctx.Err()
			}
			return failOpen(ctx.Err())
		}
	}
}

func (c *HTTP2ClientCarrier) Binding() handshake.FirstHopBinding {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return cloneFirstHopBinding(c.binding)
}

func (c *HTTP2ClientCarrier) WriteRecord(body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return net.ErrClosed
	}
	if c.upgraded {
		c.stateMu.Unlock()
		return fmt.Errorf("transport: HTTP/2 carrier already upgraded to application streams")
	}
	writer := c.recordWriter
	c.stateMu.Unlock()
	return writer.Write(body)
}

func (c *HTTP2ClientCarrier) ReadRecord() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil, net.ErrClosed
	}
	if c.upgraded {
		c.stateMu.Unlock()
		return nil, fmt.Errorf("transport: HTTP/2 carrier already upgraded to application streams")
	}
	c.stateMu.Unlock()
	response, err := c.awaitResponse()
	if err != nil {
		return nil, err
	}
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil, net.ErrClosed
	}
	if c.recordReader == nil {
		c.recordReader, err = NewRecordReader(response.Body, c.maxRecordBytes)
	}
	reader := c.recordReader
	c.stateMu.Unlock()
	if err != nil {
		return nil, err
	}
	return reader.Read()
}

func (c *HTTP2ClientCarrier) ApplicationStreams() (io.ReadCloser, io.WriteCloser, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	response, err := c.awaitResponse()
	if err != nil {
		return nil, nil, err
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return nil, nil, net.ErrClosed
	}
	if c.upgraded {
		return nil, nil, fmt.Errorf("transport: HTTP/2 application streams already acquired")
	}
	c.upgraded = true
	return &http2ApplicationReader{body: response.Body}, &http2ApplicationWriter{pipe: c.requestWriter}, nil
}

func (c *HTTP2ClientCarrier) Close() error {
	c.closeOnce.Do(func() {
		if c.stopParent != nil {
			c.stopParent()
		}
		c.stateMu.Lock()
		c.closed = true
		c.stateMu.Unlock()
		c.cancel()
		pipeErr := c.requestWriter.CloseWithError(net.ErrClosed)
		readerErr := c.requestReader.CloseWithError(net.ErrClosed)
		c.transport.CloseIdleConnections()
		c.loadRoundTripResult()
		c.stateMu.Lock()
		var responseErr error
		if c.response != nil && !c.responseClosed {
			responseErr = c.response.Body.Close()
			c.responseClosed = true
		}
		c.stateMu.Unlock()
		c.closeErr = errors.Join(pipeErr, readerErr, responseErr)
	})
	return c.closeErr
}

func (c *HTTP2ClientCarrier) awaitResponse() (*http.Response, error) {
	c.loadRoundTripResult()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.responseErr != nil {
		return nil, c.responseErr
	}
	if c.response == nil {
		return nil, fmt.Errorf("transport: HTTP/2 response is unavailable")
	}
	return c.response, nil
}

func (c *HTTP2ClientCarrier) loadRoundTripResult() {
	c.resultOnce.Do(func() {
		c.storeRoundTripResult(<-c.result)
	})
}

func (c *HTTP2ClientCarrier) storeRoundTripResult(result http2RoundTripResult) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if result.err != nil {
		c.responseErr = result.err
		if result.response != nil {
			_ = result.response.Body.Close()
			c.responseClosed = true
		}
		return
	}
	if result.response == nil {
		c.responseErr = fmt.Errorf("transport: HTTP/2 round trip returned no response")
		return
	}
	if err := validateHTTP2Response(result.response, c.expectedStatus, c.expectedHeader); err != nil {
		c.responseErr = err
		_ = result.response.Body.Close()
		c.responseClosed = true
		return
	}
	c.response = result.response
}

type http2ApplicationReader struct {
	body io.ReadCloser
}

func (r *http2ApplicationReader) Read(p []byte) (int, error) { return r.body.Read(p) }
func (r *http2ApplicationReader) Close() error               { return r.body.Close() }

type http2ApplicationWriter struct {
	pipe *io.PipeWriter
}

func (w *http2ApplicationWriter) Write(p []byte) (int, error) { return w.pipe.Write(p) }
func (w *http2ApplicationWriter) Close() error                { return w.pipe.Close() }

func validateHTTP2TLSState(state tls.ConnectionState) error {
	if !state.HandshakeComplete {
		return fmt.Errorf("transport: HTTP/2 TLS handshake is incomplete")
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("transport: HTTP/2 carrier requires TLS 1.3")
	}
	if state.NegotiatedProtocol != "h2" {
		return fmt.Errorf("transport: HTTP/2 carrier did not negotiate h2")
	}
	if state.DidResume {
		return fmt.Errorf("transport: HTTP/2 carrier forbids resumed TLS")
	}
	return nil
}

func validateHTTP2Response(response *http.Response, expectedStatus int, expectedHeader http.Header) error {
	if response.ProtoMajor != 2 || response.TLS == nil {
		return fmt.Errorf("transport: carrier response is not authenticated HTTP/2")
	}
	if err := validateHTTP2TLSState(*response.TLS); err != nil {
		return err
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("transport: carrier response status %d, want %d", response.StatusCode, expectedStatus)
	}
	if err := validateVisibleHeaders(response.Header); err != nil {
		return err
	}
	for name, values := range expectedHeader {
		if actual := response.Header.Values(name); !reflect.DeepEqual(actual, values) {
			return fmt.Errorf("transport: carrier response header %q mismatch", name)
		}
	}
	return nil
}

func cloneFirstHopBinding(in handshake.FirstHopBinding) handshake.FirstHopBinding {
	return handshake.FirstHopBinding{
		OuterExporterValue:      append([]byte(nil), in.OuterExporterValue...),
		TLSExporterChannelID:    append([]byte(nil), in.TLSExporterChannelID...),
		ConnectionIDHash:        append([]byte(nil), in.ConnectionIDHash...),
		CoverStreamBinding:      append([]byte(nil), in.CoverStreamBinding...),
		HandshakeBindingContext: append([]byte(nil), in.HandshakeBindingContext...),
	}
}

func http2TLSHandshakeTimeout(dialer net.Dialer) time.Duration {
	timeout := defaultHTTP2TLSHandshakeTimeout
	if dialer.Timeout > 0 && dialer.Timeout < timeout {
		timeout = dialer.Timeout
	}
	if !dialer.Deadline.IsZero() {
		remaining := time.Until(dialer.Deadline)
		if remaining <= 0 {
			return time.Nanosecond
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	return timeout
}

func validateHTTP2ClientCarrierConfig(config HTTP2ClientCarrierConfig) (HTTP2ClientCarrierConfig, error) {
	if config.Request == nil || config.Request.URL == nil {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier request is nil")
	}
	request := config.Request
	if request.URL.Scheme != "https" {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier request requires HTTPS")
	}
	if request.Method != http.MethodPost {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier request requires POST")
	}
	if request.Host == "" || request.URL.Host == "" {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier authority is empty")
	}
	if request.Host != request.URL.Host {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 request authority mismatch")
	}
	if request.URL.Path == "" || request.URL.Path[0] != '/' {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier path is invalid")
	}
	if request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.User != nil || request.URL.Opaque != "" || request.URL.ForceQuery {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier target contains unsupported URL components")
	}
	if request.RequestURI != "" || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier request contains unsupported wire state")
	}
	if request.Body != nil && request.Body != http.NoBody {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier request already has a body")
	}
	if err := validateVisibleHeaders(request.Header); err != nil {
		return HTTP2ClientCarrierConfig{}, err
	}
	attestation, ok := request.Context().Value(streamingH2BindingContextKey{}).(streamingH2BindingAttestation)
	if !ok {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 request was not produced by the streaming builder")
	}
	metadata := config.BindingMetadata
	if !bytes.Equal(attestation.authorityHash, metadata.NormalizedAuthorityHash) ||
		!bytes.Equal(attestation.pathID, metadata.PathTemplateID) ||
		attestation.authority != request.Host ||
		attestation.authority != request.URL.Host ||
		attestation.path != request.URL.Path ||
		attestation.classID != metadata.RequestClassID ||
		attestation.methodID != metadata.MethodFamilyID {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 request binding metadata mismatch")
	}
	if config.TLSConfig == nil {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 TLS configuration is nil")
	}
	tlsConfig := config.TLSConfig
	if tlsConfig.RootCAs == nil {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier requires explicit root trust")
	}
	if tlsConfig.InsecureSkipVerify {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier forbids disabled certificate verification")
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier requires TLS 1.3 minimum")
	}
	if tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion != tls.VersionTLS13 {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier requires TLS 1.3 maximum")
	}
	if tlsConfig.ClientSessionCache != nil {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier forbids TLS session resumption")
	}
	if tlsConfig.KeyLogWriter != nil {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier forbids TLS key logging")
	}
	if len(tlsConfig.NextProtos) != 0 && (len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "h2") {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 carrier ALPN must be h2 only")
	}
	if tlsConfig.ServerName != "" && !strings.EqualFold(strings.TrimSuffix(tlsConfig.ServerName, "."), strings.TrimSuffix(request.URL.Hostname(), ".")) {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: HTTP/2 TLS server name does not match request authority")
	}
	if config.ExpectedStatus < 200 || config.ExpectedStatus > 599 {
		return HTTP2ClientCarrierConfig{}, fmt.Errorf("transport: invalid expected HTTP status")
	}
	if err := validateVisibleHeaders(config.ExpectedHeader); err != nil {
		return HTTP2ClientCarrierConfig{}, err
	}
	maximum, err := normalizeRecordMaximum(config.MaxRecordBodyBytes)
	if err != nil {
		return HTTP2ClientCarrierConfig{}, err
	}

	attestation = cloneStreamingH2Attestation(attestation)
	requestContext := context.WithValue(context.Background(), streamingH2BindingContextKey{}, attestation)
	request = request.Clone(requestContext)
	request.Body = nil
	request.GetBody = nil
	request.ContentLength = -1
	tlsConfig = tlsConfig.Clone()
	tlsConfig.RootCAs = tlsConfig.RootCAs.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{"h2"}
	tlsConfig.ClientSessionCache = nil
	metadata = handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), metadata.NormalizedAuthorityHash...),
		PathTemplateID:          append([]byte(nil), metadata.PathTemplateID...),
		RequestClassID:          metadata.RequestClassID,
		MethodFamilyID:          metadata.MethodFamilyID,
	}
	dialer := net.Dialer{}
	if config.Dialer != nil {
		dialer = *config.Dialer
	}
	return HTTP2ClientCarrierConfig{
		Request:            request,
		TLSConfig:          tlsConfig,
		BindingMetadata:    metadata,
		ExpectedStatus:     config.ExpectedStatus,
		ExpectedHeader:     cloneHeader(config.ExpectedHeader),
		MaxRecordBodyBytes: maximum,
		Dialer:             &dialer,
	}, nil
}

func cloneStreamingH2Attestation(in streamingH2BindingAttestation) streamingH2BindingAttestation {
	return streamingH2BindingAttestation{
		authorityHash: append([]byte(nil), in.authorityHash...),
		pathID:        append([]byte(nil), in.pathID...),
		authority:     in.authority,
		path:          in.path,
		classID:       in.classID,
		methodID:      in.methodID,
	}
}
