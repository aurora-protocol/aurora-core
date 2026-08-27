package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewProductionServiceValidatesBeforeLoadingDependencies(t *testing.T) {
	_, caches, err := newProductionService(productionConfig{})
	if err == nil || !strings.Contains(err.Error(), "listen address") {
		closeProductionCaches(caches)
		t.Fatalf("newProductionService error = %v, want early listen validation", err)
	}
}

func TestIssuerProductionConfigRejectsNonConcretePorts(t *testing.T) {
	base := issuerProductionConfig{
		tlsCertificatePath:       "certificate.pem",
		tlsPrivateKeyPath:        "private-key.pem",
		issuerMetadataPath:       "metadata.bin",
		metadataAuthorityKeyPath: "authority.bin",
		blindRSAKeyPath:          "blind-rsa.pem",
		spentTokenCachePath:      "spent-token.log",
		relayBucketID:            make([]byte, 16),
		originInfoPolicyID:       1,
	}
	for _, address := range []string{":9444", "0.0.0.0:0", "0.0.0.0:http", "0.0.0.0:+9444", "0.0.0.0:65536"} {
		t.Run(address, func(t *testing.T) {
			config := base
			config.listenAddress = address
			if err := config.validate(); err == nil || !strings.Contains(err.Error(), "listen") {
				t.Fatalf("validate(%q) error = %v, want invalid-listen error", address, err)
			}
		})
	}
	base.listenAddress = "127.0.0.1:9444"
	if err := base.validate(); err != nil {
		t.Fatalf("issuer loopback deployment rejected: %v", err)
	}
}

func TestServeProductionShutsDownAfterUnexpectedListenerFailure(t *testing.T) {
	service, caches, err := newProductionService(newProductionCommandFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closeProductionCaches(caches)

	serveFailure := errors.New("accept failed")
	if err := serveProduction(context.Background(), service, productionFailingListener{err: serveFailure}); !errors.Is(err, serveFailure) {
		t.Fatalf("serveProduction error = %v, want %v", err, serveFailure)
	}
	if err := service.Serve(productionFailingListener{err: errors.New("second accept")}); err != nil {
		t.Fatalf("production server accepted reuse after fatal serve failure: %v", err)
	}
}

func TestServeProductionIssuerShutsDownAfterUnexpectedListenerFailure(t *testing.T) {
	runtime, err := newProductionIssuerService(newProductionIssuerCommandFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	httpServer, err := newProductionIssuerHTTPServer(runtime)
	if err != nil {
		t.Fatal(err)
	}

	serveFailure := errors.New("accept failed")
	if err := serveProductionIssuerHTTPServer(context.Background(), httpServer, productionFailingListener{err: serveFailure}); !errors.Is(err, serveFailure) {
		t.Fatalf("serveProductionIssuerHTTPServer error = %v, want %v", err, serveFailure)
	}
	if err := httpServer.ServeTLS(productionFailingListener{err: errors.New("second accept")}, "", ""); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("issuer HTTP server reuse error = %v, want http.ErrServerClosed", err)
	}
}

func TestProductionServersDoNotAcceptAfterStartupCancellation(t *testing.T) {
	t.Run("relay", func(t *testing.T) {
		service, caches, err := newProductionService(newProductionCommandFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		defer closeProductionCaches(caches)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		listener := &productionCountingListener{err: errors.New("unexpected accept")}
		if err := serveProduction(ctx, service, listener); err != nil {
			t.Fatalf("serveProduction on canceled context: %v", err)
		}
		if got := listener.accepts.Load(); got != 0 {
			t.Fatalf("relay accepted %d times after startup cancellation", got)
		}
	})

	t.Run("issuer", func(t *testing.T) {
		runtime, err := newProductionIssuerService(newProductionIssuerCommandFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		httpServer, err := newProductionIssuerHTTPServer(runtime)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		listener := &productionCountingListener{err: errors.New("unexpected accept")}
		if err := serveProductionIssuerHTTPServer(ctx, httpServer, listener); err != nil {
			t.Fatalf("serveProductionIssuerHTTPServer on canceled context: %v", err)
		}
		if got := listener.accepts.Load(); got != 0 {
			t.Fatalf("issuer accepted %d times after startup cancellation", got)
		}
	})
}

type productionFailingListener struct {
	err error
}

func (l productionFailingListener) Accept() (net.Conn, error) { return nil, l.err }
func (productionFailingListener) Close() error                { return nil }
func (productionFailingListener) Addr() net.Addr              { return productionTestAddress("failed-listener") }

type productionTestAddress string

func (a productionTestAddress) Network() string { return "tcp" }
func (a productionTestAddress) String() string  { return string(a) }

type productionCountingListener struct {
	accepts atomic.Int32
	err     error
}

func (l *productionCountingListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	return nil, l.err
}

func (*productionCountingListener) Close() error   { return nil }
func (*productionCountingListener) Addr() net.Addr { return productionTestAddress("counting-listener") }
