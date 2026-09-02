package main

// Coverage for cmd/aurorad main.go:191 newReverseProxyCoverOrigin and the
// early branches of production.go:101 runProductionService /
// issuer_production.go:94 runProductionIssuer that are reachable without
// privileged ports or real deployments:
//
//   - newReverseProxyCoverOrigin: the url.Parse error branch, and the
//     scheme/host validation inherited from server.NewReverseProxyCoverOrigin.
//   - runProductionService / runProductionIssuer: the productionListen failure
//     branch (exit 1, "server: listen:" / "issuer: listen:") and the
//     serve-failure branch reached with a pre-canceled signal context and a
//     nil service/runtime (both serve helpers fail before touching the
//     network). The existing setProductionListenForTest and
//     setProductionSignalContextForTest seams keep this hermetic; the real
//     listeners bind an ephemeral loopback port only.
//
// Full successful serve runs are intentionally not covered here: they require
// a fully provisioned ProductionFirstHopServer / issuer runtime.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestNewReverseProxyCoverOriginValidatesTarget(t *testing.T) {
	handler, err := newReverseProxyCoverOrigin("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil {
		t.Fatal("newReverseProxyCoverOrigin returned a nil handler for a valid target")
	}
	if _, err := newReverseProxyCoverOrigin("ftp://127.0.0.1:8080"); err == nil {
		t.Fatal("newReverseProxyCoverOrigin accepted a non-http(s) target")
	}
	if _, err := newReverseProxyCoverOrigin("http://"); err == nil {
		t.Fatal("newReverseProxyCoverOrigin accepted a target without a host")
	}
	if _, err := newReverseProxyCoverOrigin("://%"); err == nil {
		t.Fatal("newReverseProxyCoverOrigin accepted an unparseable target")
	}
}

func TestRunProductionServiceReturnsListenFailure(t *testing.T) {
	restore := setProductionListenForTest(func(string) (net.Listener, error) {
		return nil, errors.New("listen boom")
	})
	defer restore()
	var stdout, stderr bytes.Buffer
	if code := runProductionService(nil, nil, "127.0.0.1:0", &stdout, &stderr); code != 1 {
		t.Fatalf("runProductionService(listen failure) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "server: listen:") {
		t.Fatalf("runProductionService(listen failure) stderr = %q", stderr.String())
	}
}

func TestRunProductionServiceReportsServeFailureAfterCancellation(t *testing.T) {
	restore := setProductionListenForTest(func(string) (net.Listener, error) {
		return net.Listen("tcp4", "127.0.0.1:0")
	})
	defer restore()
	restoreSignals := setProductionSignalContextForTest(func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	})
	defer restoreSignals()
	var stdout, stderr bytes.Buffer
	if code := runProductionService(nil, nil, "127.0.0.1:0", &stdout, &stderr); code != 1 {
		t.Fatalf("runProductionService(canceled) code = %d, want 1 (nil service cannot shut down)", code)
	}
	if !strings.Contains(stdout.String(), "aurorad production server started") {
		t.Fatalf("runProductionService(canceled) stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "production service and listener are required") {
		t.Fatalf("runProductionService(canceled) stderr = %q", stderr.String())
	}
}

func TestRunProductionIssuerReturnsListenFailure(t *testing.T) {
	restore := setProductionListenForTest(func(string) (net.Listener, error) {
		return nil, errors.New("listen boom")
	})
	defer restore()
	var stdout, stderr bytes.Buffer
	if code := runProductionIssuer(nil, "127.0.0.1:0", &stdout, &stderr); code != 1 {
		t.Fatalf("runProductionIssuer(listen failure) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "issuer: listen:") {
		t.Fatalf("runProductionIssuer(listen failure) stderr = %q", stderr.String())
	}
}

func TestRunProductionIssuerReportsServeFailureAfterCancellation(t *testing.T) {
	restore := setProductionListenForTest(func(string) (net.Listener, error) {
		return net.Listen("tcp4", "127.0.0.1:0")
	})
	defer restore()
	restoreSignals := setProductionSignalContextForTest(func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	})
	defer restoreSignals()
	var stdout, stderr bytes.Buffer
	if code := runProductionIssuer(nil, "127.0.0.1:0", &stdout, &stderr); code != 1 {
		t.Fatalf("runProductionIssuer(canceled) code = %d, want 1 (nil runtime cannot serve)", code)
	}
	if !strings.Contains(stdout.String(), "aurorad private issuer backend started") {
		t.Fatalf("runProductionIssuer(canceled) stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "issuer: production service is required") {
		t.Fatalf("runProductionIssuer(canceled) stderr = %q", stderr.String())
	}
}
