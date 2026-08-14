package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/trust"
	"golang.org/x/net/netutil"
)

const (
	maximumProductionFirstHopSessions    = 4096
	productionFirstHopConnectionHeadroom = 64
)

var ErrProductionFirstHopSessionLimit = errors.New("server: production first-hop session limit reached")

// ProductionFirstHopOptions contains the fixed dependencies needed by a production first-hop server.
type ProductionFirstHopOptions struct {
	Deployment            trust.VerifiedRelayDeployment
	Driver                *handshake.RelayDriver
	ListenAddress         string
	Authority             string
	Path                  string
	TLSConfig             *tls.Config
	CarrierStatus         int
	CarrierHeader         http.Header
	CoverOrigin           ProductionCoverOrigin
	ProxySession          FirstHopProxySessionOptions
	MaxConcurrentSessions int
}

// ProductionFirstHopServer owns a TLS-only, HTTP/2-only first-hop server.
type ProductionFirstHopServer struct {
	handler         *FirstHopHandler
	server          *http.Server
	connectionLimit int
}

// NewProductionFirstHopServer constructs a server from immutable, production-safe dependencies.
func NewProductionFirstHopServer(options ProductionFirstHopOptions) (*ProductionFirstHopServer, error) {
	if err := validateProductionFirstHopOptions(options); err != nil {
		return nil, err
	}
	if options.ProxySession.Limits == (relay.SocketEgressLimits{}) {
		return nil, fmt.Errorf("server: production first-hop requires explicit egress limits")
	}
	factory, err := NewFirstHopProxySessionFactory(options.ProxySession)
	if err != nil {
		return nil, err
	}
	template := options.Deployment.Template()
	requestClass := options.Deployment.RequestClass()
	limiter := newProductionFirstHopLimiter(options.MaxConcurrentSessions)
	handler, err := NewFirstHopHandler(FirstHopOptions{
		Driver:    options.Driver,
		Authority: options.Authority,
		Path:      options.Path,
		BindingMetadata: handshake.HTTP2BindingMetadata{
			NormalizedAuthorityHash: template.PublicNameHash,
			PathTemplateID:          requestClass.PathTemplateID,
			RequestClassID:          requestClass.ClassID,
			MethodFamilyID:          options.Deployment.Method(),
		},
		CoverStatus:    options.CarrierStatus,
		CoverHeader:    options.CarrierHeader,
		CoverOrigin:    options.CoverOrigin,
		SessionFactory: factory,
	})
	if err != nil {
		return nil, err
	}
	handler.sessionAdmission = limiter.acquire
	httpServer, err := NewFirstHopHTTPServer(options.ListenAddress, handler, options.TLSConfig)
	if err != nil {
		return nil, err
	}
	httpServer.ErrorLog = log.New(io.Discard, "", 0)
	return &ProductionFirstHopServer{
		handler:         handler,
		server:          httpServer,
		connectionLimit: options.MaxConcurrentSessions + productionFirstHopConnectionHeadroom,
	}, nil
}

// Serve accepts TLS connections from listener until Shutdown is called or serving fails.
func (s *ProductionFirstHopServer) Serve(listener net.Listener) error {
	if s == nil || s.server == nil || s.server.TLSConfig == nil {
		return fmt.Errorf("server: production first-hop server is not initialized")
	}
	if isNilFirstHopInterface(listener) {
		return fmt.Errorf("server: production first-hop listener is required")
	}
	if s.connectionLimit <= 0 {
		return fmt.Errorf("server: production first-hop connection limit is invalid")
	}
	limitedListener := netutil.LimitListener(listener, s.connectionLimit)
	err := s.server.Serve(tls.NewListener(limitedListener, s.server.TLSConfig))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting new connections, cancels active first-hop sessions, and closes remaining connections after its deadline.
func (s *ProductionFirstHopServer) Shutdown(ctx context.Context) error {
	if s == nil || s.handler == nil || s.server == nil {
		return fmt.Errorf("server: production first-hop server is not initialized")
	}
	if ctx == nil {
		return fmt.Errorf("server: production first-hop shutdown context is required")
	}
	s.handler.shutdown()
	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- s.server.Shutdown(ctx)
	}()
	if err := s.handler.waitForSessions(ctx); err != nil {
		closeErr := s.server.Close()
		shutdownErr := <-shutdownResult
		if closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
			return errors.Join(err, shutdownErr, closeErr)
		}
		return errors.Join(err, shutdownErr)
	}
	err := <-shutdownResult
	if err == nil {
		return nil
	}
	closeErr := s.server.Close()
	if closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
		return errors.Join(err, closeErr)
	}
	return err
}

func validateProductionFirstHopOptions(options ProductionFirstHopOptions) error {
	if !options.Deployment.Valid() {
		return fmt.Errorf("server: production first-hop verified deployment is required")
	}
	if options.Driver == nil {
		return fmt.Errorf("server: production first-hop relay driver is required")
	}
	if !sameProductionDeployment(options.Deployment, options.Driver.Deployment()) {
		return fmt.Errorf("server: production first-hop relay driver deployment mismatch")
	}
	if err := validateProductionListenAddress(options.ListenAddress); err != nil {
		return err
	}
	if strings.TrimSpace(options.Authority) == "" || strings.TrimSpace(options.Authority) != options.Authority {
		return fmt.Errorf("server: production first-hop authority is required")
	}
	if options.Path == "" {
		return fmt.Errorf("server: production first-hop path is required")
	}
	if isNilFirstHopInterface(options.CoverOrigin) {
		return fmt.Errorf("server: production first-hop cover origin is required")
	}
	if isNilFirstHopInterface(options.ProxySession.DNSResolver) {
		return fmt.Errorf("server: production first-hop DNS resolver is required")
	}
	if options.MaxConcurrentSessions <= 0 || options.MaxConcurrentSessions > maximumProductionFirstHopSessions {
		return fmt.Errorf("server: production first-hop session limit is invalid")
	}
	return nil
}

func sameProductionDeployment(left, right trust.VerifiedRelayDeployment) bool {
	return left.Valid() && right.Valid() && left.Suite() == right.Suite() && left.Method() == right.Method() &&
		bytes.Equal(left.DescriptorHash(), right.DescriptorHash()) && bytes.Equal(left.TemplateHash(), right.TemplateHash())
}

func validateProductionListenAddress(address string) error {
	if address == "" || strings.TrimSpace(address) != address {
		return fmt.Errorf("server: production first-hop listen address is required")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || portText == "" {
		return fmt.Errorf("server: production first-hop listen address is invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("server: production first-hop listen port is invalid")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("server: production first-hop loopback listen address is forbidden")
	}
	ipHost := strings.Split(host, "%")[0]
	if ip, err := netip.ParseAddr(ipHost); err == nil && ip.IsLoopback() {
		return fmt.Errorf("server: production first-hop loopback listen address is forbidden")
	}
	return nil
}

type productionFirstHopLimiter struct {
	slots chan struct{}
}

func newProductionFirstHopLimiter(limit int) *productionFirstHopLimiter {
	return &productionFirstHopLimiter{slots: make(chan struct{}, limit)}
}

func (l *productionFirstHopLimiter) acquire(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, fmt.Errorf("server: production first-hop session context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case l.slots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-l.slots })
		}, nil
	default:
		return nil, ErrProductionFirstHopSessionLimit
	}
}
