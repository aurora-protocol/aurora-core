package labfixture

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
)

const (
	labMaxConcurrentSessions = 64
	labShutdownTimeout       = 10 * time.Second
	labReplayCacheDir        = "runtime"
	labHintSpentCache        = "hint-spent.cache"
	labTokenSpentCache       = "token-spent.cache"
	labBootstrapCache        = "bootstrap.cache"
	labIssuerSpentCache      = "issuer-spent-tokens.cache"

	maximumLabIssuerRequestBytes = 1 << 20
)

// labCoverBody is served by the in-process cover origin. It intentionally
// identifies itself so lab traffic is never mistaken for a real site.
const labCoverBody = "auroralab cover origin (local lab testing only)\n"

// ServerOptions controls lab relay/issuer assembly from loaded material.
type ServerOptions struct {
	// PublicAddress is the non-loopback public address recorded on the
	// production first-hop server. The production server type forbids
	// loopback listen addresses; the actual listener is supplied to
	// ServeFirstHop and may be loopback in the lab. Typically
	// "0.0.0.0:<minted relay port>".
	PublicAddress string
	// DNSUpstream selects the egress mode. Empty (the default) wires lab
	// loopback egress: every DNS answer is 127.0.0.1/::1, every TCP flow lands
	// on the in-process cover origin, and every UDP flow lands on an
	// in-process echo endpoint, so no lab flow can fail and the production
	// fail-closed carrier is never reset by unreachable targets. When set to a
	// numeric UDP resolver address, the relay performs real internet egress
	// with that DNS upstream.
	DNSUpstream string
	// MaxSessions bounds concurrent authenticated sessions.
	MaxSessions int
	// NowUnix overrides the server clock; nil uses the current time.
	NowUnix func() uint64
}

func (options ServerOptions) normalized() (ServerOptions, error) {
	if options.MaxSessions == 0 {
		options.MaxSessions = labMaxConcurrentSessions
	}
	if options.NowUnix == nil {
		options.NowUnix = func() uint64 {
			nowUnix := time.Now().Unix()
			if nowUnix <= 0 {
				return 0
			}
			return uint64(nowUnix)
		}
	}
	if err := server.ValidateProductionFirstHopListenAddress(options.PublicAddress); err != nil {
		return ServerOptions{}, err
	}
	if options.MaxSessions <= 0 || options.MaxSessions > 4096 {
		return ServerOptions{}, fmt.Errorf("labfixture: session limit is invalid")
	}
	if options.DNSUpstream != "" {
		if _, err := relay.NewUDPDNSMessageResolver(options.DNSUpstream); err != nil {
			return ServerOptions{}, fmt.Errorf("labfixture: DNS upstream: %w", err)
		}
	}
	return options, nil
}

// Server owns a lab first-hop relay, its bound lab issuer backend, an
// in-process loopback cover origin, and the durable replay caches.
type Server struct {
	firstHop    *server.ProductionFirstHopServer
	issuer      *issuerd.Service
	issuerHTTP  http.Handler
	tlsConfig   *tls.Config
	coverServer *http.Server
	coverListen net.Listener
	coverAddr   string
	udpEcho     *net.UDPConn
	labEgress   bool
	caches      []io.Closer
}

// NewServer assembles the lab relay and issuer from loaded minted material.
// On success the caller owns Shutdown/Close; on failure all state is released.
func NewServer(loaded *Loaded, options ServerOptions) (serverOut *Server, err error) {
	if loaded == nil || !loaded.Deployment.Valid() || loaded.BlindRSAKey == nil {
		return nil, fmt.Errorf("labfixture: loaded deployment is unavailable")
	}
	options, err = options.normalized()
	if err != nil {
		return nil, err
	}
	nowUnix := options.NowUnix()
	if nowUnix == 0 {
		return nil, fmt.Errorf("labfixture: server clock is invalid")
	}
	hintResolver, err := handshake.NewStaticAccessHintResolver(loaded.AccessHints)
	if err != nil {
		return nil, err
	}
	admissionVerifier, err := handshake.NewBlindRSAAdmissionVerifier(loaded.TokenKeyDER)
	if err != nil {
		return nil, err
	}
	policy, err := handshake.NewFixedProxyPolicySelector(loaded.Deployment.Suite(), registry.PolicyBalancedWeb, registry.RouteFast1, registry.ShapeNormal)
	if err != nil {
		return nil, err
	}

	cacheDir := filepath.Join(loaded.Dir, labReplayCacheDir)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("labfixture: create replay cache directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(cacheDir, 0o700); err != nil {
			return nil, fmt.Errorf("labfixture: restrict replay cache directory: %w", err)
		}
	}
	caches := make([]io.Closer, 0, 4)
	defer func() {
		if err != nil {
			for index := len(caches) - 1; index >= 0; index-- {
				_ = caches[index].Close()
			}
		}
	}()
	openCache := func(name string) (*admission.RetentionFileReplayCache, error) {
		directory, err := os.Open(cacheDir)
		if err != nil {
			return nil, fmt.Errorf("labfixture: open replay cache directory: %w", err)
		}
		cache, err := admission.NewRetentionFileReplayCacheAt(directory, name, nowUnix)
		if err != nil {
			_ = directory.Close()
			return nil, fmt.Errorf("labfixture: open replay cache %s: %w", name, err)
		}
		if !cache.Durable() {
			_ = cache.Close()
			return nil, fmt.Errorf("labfixture: replay cache %s is not durable", name)
		}
		caches = append(caches, cache)
		return cache, nil
	}
	hintSpent, err := openCache(labHintSpentCache)
	if err != nil {
		return nil, err
	}
	tokenSpent, err := openCache(labTokenSpentCache)
	if err != nil {
		return nil, err
	}
	bootstrap, err := openCache(labBootstrapCache)
	if err != nil {
		return nil, err
	}
	issuerSpent, err := openCache(labIssuerSpentCache)
	if err != nil {
		return nil, err
	}

	driver, err := handshake.NewRelayDriver(handshake.RelayDriverConfig{
		Deployment:        loaded.Deployment,
		HintResolver:      hintResolver,
		HintSpentCache:    hintSpent,
		AdmissionVerifier: admissionVerifier,
		TokenSpentCache:   tokenSpent,
		BootstrapCache:    bootstrap,
		ClassicalSigner:   loaded.ClassicalSigner(),
		PQSigner:          loaded.PQSigner(),
		PolicySelector:    policy,
		SessionLimits:     labSessionLimits(),
	})
	if err != nil {
		return nil, err
	}

	// In-process loopback cover origin, also the end-to-end egress target.
	coverListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("labfixture: listen cover origin: %w", err)
	}
	coverServer := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(writer, labCoverBody)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = coverServer.Serve(coverListener) }()
	coverTarget, err := url.Parse("http://" + coverListener.Addr().String())
	if err != nil {
		_ = coverListener.Close()
		return nil, err
	}
	coverOrigin, err := server.NewProductionReverseProxyCoverOrigin(coverTarget)
	if err != nil {
		_ = coverListener.Close()
		return nil, err
	}

	// Egress wiring. The production first hop fails closed: any dial or
	// resolution error escapes the frame handler and resets the carrier
	// stream (observed on-device as stream 1 RST_STREAM INTERNAL_ERROR). Lab
	// loopback egress therefore makes every flow succeed against in-process
	// endpoints; --dns-upstream opts into real internet egress instead.
	var udpEcho *net.UDPConn
	var dialer relay.ContextDialer
	var resolver relay.IPResolver
	var dnsResolver relay.DNSMessageResolver
	if options.DNSUpstream == "" {
		udpEcho, err = startLabUDPEcho()
		if err != nil {
			_ = coverListener.Close()
			return nil, err
		}
		dialer = labEgressDialer{tcpTarget: coverListener.Addr().String(), udpTarget: udpEcho.LocalAddr().String()}
		resolver = labEgressResolver{}
		dnsResolver = labDNSResolver{}
	} else {
		dnsResolver, err = relay.NewUDPDNSMessageResolver(options.DNSUpstream)
		if err != nil {
			_ = coverListener.Close()
			return nil, err
		}
		dialer = &net.Dialer{}
		resolver = net.DefaultResolver
	}
	defer func() {
		if err != nil && udpEcho != nil {
			_ = udpEcho.Close()
		}
	}()

	firstHop, err := server.NewProductionFirstHopServer(server.ProductionFirstHopOptions{
		Deployment:    loaded.Deployment,
		Driver:        driver,
		ListenAddress: options.PublicAddress,
		Authority:     loaded.Manifest.Relay.Authority,
		Path:          loaded.Manifest.Relay.Path,
		TLSConfig:     &tls.Config{Certificates: []tls.Certificate{loaded.Certificate}},
		CarrierStatus: http.StatusCreated,
		CarrierHeader: http.Header{"Content-Type": {"application/octet-stream"}, "X-Carrier-Mode": {"ordinary"}},
		CoverOrigin:   coverOrigin,
		ProxySession: server.FirstHopProxySessionOptions{
			// The lab relay intentionally exits to private ranges so lab
			// clients can reach loopback and LAN targets.
			ExitPolicy:    relay.ExitPolicy{AllowPrivate: true},
			RateLimit:     relay.DefaultExitRateLimit(),
			UDPConfirmTTL: 300,
			Dialer:        dialer,
			Resolver:      resolver,
			DNSResolver:   dnsResolver,
			Limits:        labEgressLimits(),
		},
		MaxConcurrentSessions: options.MaxSessions,
	})
	if err != nil {
		_ = coverListener.Close()
		return nil, err
	}

	issuerService, err := issuerd.NewProductionBlindRSAService(issuerd.ProductionBlindRSAServiceOptions{
		Metadata:           loaded.IssuerMetadata,
		AuthorityKeys:      []protocol.AuthorityKeyRecord{loaded.IssuerAuthority},
		BlindRSAKey:        loaded.BlindRSAKey,
		SpentTokenCache:    issuerSpent,
		RelayBucketID:      append([]byte(nil), loaded.IssuerMetadata.RelayBucketScopes[0].RelayBucketID...),
		OriginInfoPolicyID: loaded.IssuerMetadata.OriginInfoPolicies[0].PolicyID,
		NowUnix:            options.NowUnix,
	})
	if err != nil {
		_ = coverListener.Close()
		return nil, err
	}
	issuerHandler, err := NewIssuerCarrierHandler(issuerService, loaded.Manifest.Issuer.CarrierPath)
	if err != nil {
		_ = coverListener.Close()
		return nil, err
	}

	result := &Server{
		firstHop:    firstHop,
		issuer:      issuerService,
		issuerHTTP:  issuerHandler,
		tlsConfig:   &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{loaded.Certificate}},
		coverServer: coverServer,
		coverListen: coverListener,
		coverAddr:   coverListener.Addr().String(),
		udpEcho:     udpEcho,
		labEgress:   options.DNSUpstream == "",
		caches:      caches,
	}
	return result, nil
}

// ServeFirstHop serves the lab relay on listener until Shutdown.
func (s *Server) ServeFirstHop(listener net.Listener) error {
	if s == nil || s.firstHop == nil {
		return fmt.Errorf("labfixture: lab relay server is not initialized")
	}
	return s.firstHop.Serve(listener)
}

// IssuerHandler returns the lab issuer carrier endpoint handler.
func (s *Server) IssuerHandler() http.Handler {
	if s == nil {
		return nil
	}
	return s.issuerHTTP
}

// IssuerTLSConfig returns the TLS configuration for the lab issuer endpoint.
func (s *Server) IssuerTLSConfig() *tls.Config {
	if s == nil {
		return nil
	}
	return s.tlsConfig.Clone()
}

// CoverAddress returns the in-process loopback cover origin address, which is
// also a convenient end-to-end egress target for lab clients.
func (s *Server) CoverAddress() string {
	if s == nil {
		return ""
	}
	return s.coverAddr
}

// Shutdown stops the first-hop relay, then releases the cover origin and
// durable replay caches.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.firstHop == nil {
		return fmt.Errorf("labfixture: lab relay server is not initialized")
	}
	if ctx == nil {
		return fmt.Errorf("labfixture: shutdown context is required")
	}
	return s.firstHop.Shutdown(ctx)
}

// Close releases the cover origin and durable replay caches. Call Shutdown
// first so sessions drain before the caches close.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var errs []error
	if s.coverServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), labShutdownTimeout)
		errs = append(errs, s.coverServer.Shutdown(ctx))
		cancel()
	}
	if s.udpEcho != nil {
		errs = append(errs, s.udpEcho.Close())
	}
	for index := len(s.caches) - 1; index >= 0; index-- {
		errs = append(errs, s.caches[index].Close())
	}
	s.caches = nil
	return errors.Join(errs...)
}

// NewIssuerCarrierHandler builds the lab Blind RSA issuer carrier endpoint.
// Unlike the production mTLS gateway backend, this handler is plain TLS: it
// exists so a lab client can complete a real issuer exchange against a minted
// deployment without client certificates. LOCAL LAB TESTING ONLY.
func NewIssuerCarrierHandler(service *issuerd.Service, carrierPath string) (http.Handler, error) {
	if service == nil {
		return nil, fmt.Errorf("labfixture: issuer service is required")
	}
	if carrierPath == "" {
		return nil, fmt.Errorf("labfixture: issuer carrier path is required")
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request == nil || request.Method != http.MethodPost || request.URL == nil || request.URL.Path != carrierPath || request.Body == nil {
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		mediaType := request.Header.Get("Content-Type")
		if mediaType != "application/octet-stream" {
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, maximumLabIssuerRequestBytes+1))
		if err != nil || len(body) == 0 || len(body) > maximumLabIssuerRequestBytes {
			zeroLabBytes(body)
			writeLabIssuerFailure(writer)
			return
		}
		// The decoded carrier payload aliases body; erase it only at return.
		defer zeroLabBytes(body)
		kind, payload, err := carrier.Decode(body)
		if err != nil || kind != carrier.BlindRSAIssueRequest {
			writeLabIssuerFailure(writer)
			return
		}
		tokenNonce, redemptionContextHash, expiryUnix, err := carrier.DecodeIssueRequest(payload)
		if err != nil {
			writeLabIssuerFailure(writer)
			return
		}
		proof, err := service.IssueBlindRSA2048(issuerd.IssueBlindRSA2048Request{
			TokenNonce:            tokenNonce,
			RedemptionContextHash: redemptionContextHash,
			ExpiryUnix:            expiryUnix,
		})
		if err != nil {
			writeLabIssuerFailure(writer)
			return
		}
		encodedProof, err := protocol.Encode(proof)
		if err != nil {
			writeLabIssuerFailure(writer)
			return
		}
		response := carrier.Encode(carrier.BlindRSAIssueResponse, encodedProof)
		if len(response) == 0 || len(response) > maximumLabIssuerRequestBytes {
			zeroLabBytes(response)
			writeLabIssuerFailure(writer)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(response)
	}), nil
}

func writeLabIssuerFailure(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.WriteHeader(http.StatusBadRequest)
}

// labSessionLimits matches the production-session bounds used by the
// first-hop integration fixtures.
func labSessionLimits() session.Limits {
	return session.Limits{MaxQueuedPackets: 64, MaxQueuedBytes: 1 << 20, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 1024}
}

// labEgressLimits bounds the lab relay's socket egress. MaxFlows and
// MaxBufferedBytes match the production default scale (256 flows / 16 MiB),
// not the test-scale 16/1 MiB the fixture used: the production first hop
// fails closed, so a flow-limit rejection escapes the frame handler and
// resets the whole carrier stream (on-device: stream 1 RST_STREAM
// INTERNAL_ERROR). A real TUN client bursts past 16 concurrent flows within
// seconds of VPN startup — every DNS-driven UDP association lingers for the
// 300 s confirm TTL — which killed Pixel-class sessions even though no flow
// itself failed.
func labEgressLimits() relay.SocketEgressLimits {
	return relay.SocketEgressLimits{
		MaxFlows:            256,
		MaxBufferedBytes:    16 << 20,
		TCPReadBufferBytes:  16 << 10,
		MaxUDPDatagramBytes: 65535,
		DialTimeout:         time.Second,
		WriteTimeout:        time.Second,
		IdleTimeout:         time.Minute,
		QueueRetryInterval:  time.Millisecond,
		ResolvedTTLSeconds:  60,
	}
}

// LabEgress reports whether the server wires lab loopback egress (true) or
// real internet egress with a configured DNS upstream (false).
func (s *Server) LabEgress() bool {
	if s == nil {
		return false
	}
	return s.labEgress
}

// labEgressDialer maps every lab flow onto the in-process loopback endpoints
// so a lab flow can never fail to connect: TCP flows land on the cover origin
// and UDP flows land on the echo endpoint. LOCAL LAB TESTING ONLY.
type labEgressDialer struct {
	tcpTarget string
	udpTarget string
}

func (d labEgressDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("labfixture: lab egress dial context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		network, address = "tcp4", d.tcpTarget
	case "udp", "udp4", "udp6":
		network, address = "udp4", d.udpTarget
	default:
		return nil, fmt.Errorf("labfixture: lab egress network %q is unsupported", network)
	}
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, address)
}

// labEgressResolver answers every lab hostname lookup with loopback so
// DNS_MESSAGE flows always resolve. LOCAL LAB TESTING ONLY.
type labEgressResolver struct{}

func (labEgressResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ctx == nil {
		return nil, fmt.Errorf("labfixture: lab egress resolver context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("labfixture: lab egress lookup host is required")
	}
	switch network {
	case "ip4":
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	case "ip6":
		return []netip.Addr{netip.MustParseAddr("::1")}, nil
	case "ip":
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, nil
	default:
		return nil, fmt.Errorf("labfixture: lab egress lookup network %q is unsupported", network)
	}
}

// labDNSResolver answers non-address lab DNS messages by echoing the query
// with the response flag set, mirroring the first-hop fixture. LOCAL LAB
// TESTING ONLY.
type labDNSResolver struct{}

func (labDNSResolver) ExchangeDNS(_ context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("labfixture: lab DNS query is invalid")
	}
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	return response, nil
}

// startLabUDPEcho starts the in-process loopback UDP echo endpoint used as
// the lab egress target for UDP flows.
func startLabUDPEcho() (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("labfixture: listen UDP echo endpoint: %w", err)
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			count, address, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:count], address)
		}
	}()
	return conn, nil
}
