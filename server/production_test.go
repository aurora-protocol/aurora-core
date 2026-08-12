package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/trust"
)

func TestNewProductionFirstHopServerRejectsInvalidOptions(t *testing.T) {
	options := newProductionFirstHopTestOptions(t)
	otherFixture := newLiveFirstHopFixture(t, time.Now())
	otherDriver := otherFixture.newRelayDriver(t)
	tests := []struct {
		name   string
		mutate func(*ProductionFirstHopOptions)
	}{
		{name: "zero deployment", mutate: func(options *ProductionFirstHopOptions) { options.Deployment = trust.VerifiedRelayDeployment{} }},
		{name: "nil driver", mutate: func(options *ProductionFirstHopOptions) { options.Driver = nil }},
		{name: "mismatched driver deployment", mutate: func(options *ProductionFirstHopOptions) { options.Driver = otherDriver }},
		{name: "nil TLS", mutate: func(options *ProductionFirstHopOptions) { options.TLSConfig = nil }},
		{name: "dynamic TLS", mutate: func(options *ProductionFirstHopOptions) {
			options.TLSConfig = options.TLSConfig.Clone()
			options.TLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
		}},
		{name: "loopback listen address", mutate: func(options *ProductionFirstHopOptions) { options.ListenAddress = "127.0.0.1:443" }},
		{name: "IPv6 loopback listen address", mutate: func(options *ProductionFirstHopOptions) { options.ListenAddress = "[::1]:443" }},
		{name: "localhost listen address", mutate: func(options *ProductionFirstHopOptions) { options.ListenAddress = "localhost:443" }},
		{name: "zero listen port", mutate: func(options *ProductionFirstHopOptions) { options.ListenAddress = "0.0.0.0:0" }},
		{name: "missing authority", mutate: func(options *ProductionFirstHopOptions) { options.Authority = "" }},
		{name: "missing path", mutate: func(options *ProductionFirstHopOptions) { options.Path = "" }},
		{name: "nil cover origin", mutate: func(options *ProductionFirstHopOptions) { options.CoverOrigin = nil }},
		{name: "nil dialer", mutate: func(options *ProductionFirstHopOptions) { options.ProxySession.Dialer = nil }},
		{name: "nil resolver", mutate: func(options *ProductionFirstHopOptions) { options.ProxySession.Resolver = nil }},
		{name: "implicit egress limits", mutate: func(options *ProductionFirstHopOptions) { options.ProxySession.Limits = relay.SocketEgressLimits{} }},
		{name: "invalid egress limits", mutate: func(options *ProductionFirstHopOptions) { options.ProxySession.Limits.MaxFlows = -1 }},
		{name: "zero session cap", mutate: func(options *ProductionFirstHopOptions) { options.MaxConcurrentSessions = 0 }},
		{name: "oversized session cap", mutate: func(options *ProductionFirstHopOptions) {
			options.MaxConcurrentSessions = maximumProductionFirstHopSessions + 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneProductionFirstHopTestOptions(options)
			test.mutate(&candidate)
			if server, err := NewProductionFirstHopServer(candidate); err == nil || server != nil {
				t.Fatalf("NewProductionFirstHopServer accepted invalid options: server=%v err=%v", server, err)
			}
		})
	}
}

func TestNewProductionFirstHopServerBuildsBoundedOwnedServer(t *testing.T) {
	options := newProductionFirstHopTestOptions(t)
	server, err := NewProductionFirstHopServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if server.handler == nil || server.server == nil || server.server.Handler != server.handler || server.server.TLSConfig == options.TLSConfig || server.server.ErrorLog == nil {
		t.Fatalf("production first-hop ownership is incomplete: %+v", server)
	}
	if server.server.TLSConfig.MinVersion != tls.VersionTLS13 || server.server.TLSConfig.MaxVersion != tls.VersionTLS13 || len(server.server.TLSConfig.NextProtos) != 1 || server.server.TLSConfig.NextProtos[0] != "h2" {
		t.Fatalf("production TLS configuration is not fixed to TLS 1.3 HTTP/2: %+v", server.server.TLSConfig)
	}
	template := options.Deployment.Template()
	requestClass := options.Deployment.RequestClass()
	if server.handler.authority != options.Authority || server.handler.path != options.Path || !bytes.Equal(server.handler.bindingMetadata.NormalizedAuthorityHash, template.PublicNameHash) || !bytes.Equal(server.handler.bindingMetadata.PathTemplateID, requestClass.PathTemplateID) || server.handler.bindingMetadata.RequestClassID != requestClass.ClassID || server.handler.bindingMetadata.MethodFamilyID != options.Deployment.Method() {
		t.Fatalf("production first-hop binding is not derived from deployment: %+v", server.handler.bindingMetadata)
	}
	options.CarrierHeader.Set("X-Carrier-Mode", "mutated")
	if server.handler.coverHeader.Get("X-Carrier-Mode") == "mutated" {
		t.Fatal("production first-hop retained caller cover headers")
	}

	release, err := server.handler.sessionAdmission(context.Background())
	if err != nil || release == nil {
		t.Fatalf("acquire production session slot: release present=%t err=%v", release != nil, err)
	}
	if secondRelease, secondErr := server.handler.sessionAdmission(context.Background()); !errors.Is(secondErr, ErrProductionFirstHopSessionLimit) || secondRelease != nil {
		t.Fatalf("production session cap result: release present=%t err=%v", secondRelease != nil, secondErr)
	}
	release()
	if release, err := server.handler.sessionAdmission(context.Background()); err != nil || release == nil {
		t.Fatalf("released production session slot was not reusable: release present=%t err=%v", release != nil, err)
	} else {
		release()
	}
	//lint:ignore SA1012 Verify the public API rejects a nil context without dereferencing it.
	if err := server.Shutdown(nil); err == nil {
		t.Fatal("production first-hop accepted a nil shutdown context")
	}
}

func TestProductionFirstHopServerServesTLSAndShutsDown(t *testing.T) {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	options := newProductionFirstHopTestOptions(t)
	options.ListenAddress = listener.Addr().String()
	server, err := NewProductionFirstHopServer(options)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	clientTLS := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}} //nolint:gosec // Local self-signed test identity.
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{TLSClientConfig: clientTLS, Protocols: protocols, ForceAttemptHTTP2: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String() + "/ordinary")
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.NegotiatedProtocol != "h2" || response.TLS.DidResume {
		t.Fatalf("unexpected production carrier transport: proto=%s tls=%+v", response.Proto, response.TLS)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("production cover response status = %d", response.StatusCode)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	transport.CloseIdleConnections()
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	select {
	case serveErr := <-serveResult:
		if serveErr != nil {
			t.Fatalf("production Serve: %v", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("production server did not stop")
	}
}

func TestProductionFirstHopShutdownClosesLingeringHTTP2Connections(t *testing.T) {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	options := newProductionFirstHopTestOptions(t)
	options.ListenAddress = listener.Addr().String()
	server, err := NewProductionFirstHopServer(options)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	clientTLS := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}} //nolint:gosec // Local self-signed test identity.
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{TLSClientConfig: clientTLS, Protocols: protocols, ForceAttemptHTTP2: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String() + "/ordinary")
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(shutdownContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("production shutdown error = %v, want deadline exceeded", err)
	}
	select {
	case serveErr := <-serveResult:
		if serveErr != nil {
			t.Fatalf("production Serve: %v", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("production server did not force-close lingering HTTP/2 connection")
	}
}

func TestProductionFirstHopOptionsExcludeHarnessSurfaces(t *testing.T) {
	typeOf := reflect.TypeOf(ProductionFirstHopOptions{})
	for i := 0; i < typeOf.NumField(); i++ {
		name := typeOf.Field(i).Name
		if name == "Origin" || name == "FrameHandler" || name == "PacketExchanger" || name == "CoverBody" {
			t.Fatalf("production options expose harness field %s", name)
		}
	}
}

func newProductionFirstHopTestOptions(t testing.TB) ProductionFirstHopOptions {
	t.Helper()
	fixture := newLiveFirstHopFixture(t, time.Now())
	coverServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(coverServer.Close)
	target, err := url.Parse(coverServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	coverOrigin, err := NewProductionReverseProxyCoverOrigin(target)
	if err != nil {
		t.Fatal(err)
	}
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	return ProductionFirstHopOptions{
		Deployment:            fixture.deployment,
		Driver:                fixture.newRelayDriver(t),
		ListenAddress:         "0.0.0.0:8443",
		Authority:             "cover.example:443",
		Path:                  "/assets/upload/42",
		TLSConfig:             &tls.Config{Certificates: []tls.Certificate{certificate}},
		CarrierStatus:         http.StatusCreated,
		CarrierHeader:         http.Header{"Content-Type": {"application/octet-stream"}, "X-Carrier-Mode": {"ordinary"}},
		CoverOrigin:           coverOrigin,
		ProxySession:          FirstHopProxySessionOptions{ExitPolicy: relay.ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{}, Resolver: net.DefaultResolver, Limits: productionFirstHopTestEgressLimits()},
		MaxConcurrentSessions: 1,
	}
}

func productionFirstHopTestEgressLimits() relay.SocketEgressLimits {
	return relay.SocketEgressLimits{
		MaxFlows:            8,
		MaxBufferedBytes:    1 << 20,
		TCPReadBufferBytes:  1024,
		MaxUDPDatagramBytes: 512,
		DialTimeout:         time.Second,
		WriteTimeout:        time.Second,
		IdleTimeout:         time.Second,
		QueueRetryInterval:  time.Millisecond,
		ResolvedTTLSeconds:  60,
	}
}

func cloneProductionFirstHopTestOptions(options ProductionFirstHopOptions) ProductionFirstHopOptions {
	options.TLSConfig = options.TLSConfig.Clone()
	options.CarrierHeader = options.CarrierHeader.Clone()
	return options
}
