package main

// Coverage for two 0%-covered cmd/aurorac helpers:
//
//   - main.go:574 waitForCarrierRecovery: the happy path (timer fires before
//     context cancellation) and the cancellation path (context done before the
//     timer). Existing tests only reach it indirectly through
//     runWithCarrierRecovery with a nil Wait seam default; the direct timing
//     contract (nil after the delay, ctx.Err() on cancellation) was uncovered.
//     Delays are kept in the millisecond range so the test stays fast.
//   - main.go:649 defaultIssuerHTTPClient: the production issuer HTTP client
//     factory. Existing tests either swap the newIssuerHTTPClient seam or use
//     a lab-CA client, so the hardening properties of the default client
//     (TLS 1.3 floor, no proxies/keep-alives/compression, one connection per
//     host, redirects refused) were never asserted.

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestWaitForCarrierRecoveryReturnsAfterDelay(t *testing.T) {
	start := time.Now()
	if err := waitForCarrierRecovery(context.Background(), 5*time.Millisecond); err != nil {
		t.Fatalf("waitForCarrierRecovery returned %v, want nil after the delay", err)
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Fatalf("waitForCarrierRecovery returned after %v, before the 5ms delay", elapsed)
	}
}

func TestWaitForCarrierRecoveryRespectsCancellation(t *testing.T) {
	// Already-canceled context: with a one-hour timer pending, only the
	// ctx.Done branch can fire (a zero delay would race the timer).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForCarrierRecovery(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForCarrierRecovery(canceled) = %v, want context.Canceled", err)
	}

	// Cancellation mid-wait: a one-hour timer must not outlive the context.
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := waitForCarrierRecovery(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForCarrierRecovery(mid-wait cancel) = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("waitForCarrierRecovery took %v after cancellation", elapsed)
	}
}

func TestDefaultIssuerHTTPClientHardensTransport(t *testing.T) {
	httpClient := defaultIssuerHTTPClient()
	if httpClient == nil {
		t.Fatal("defaultIssuerHTTPClient returned nil")
	}
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default issuer transport = %T, want *http.Transport", httpClient.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("default issuer transport does not enforce TLS 1.3")
	}
	if transport.Proxy != nil {
		t.Fatal("default issuer transport honors ambient proxy settings")
	}
	if !transport.DisableKeepAlives || !transport.DisableCompression {
		t.Fatal("default issuer transport keeps connections alive or compresses")
	}
	if transport.MaxConnsPerHost != 1 || transport.MaxIdleConnsPerHost != 0 {
		t.Fatal("default issuer transport does not pin a single non-idle connection per host")
	}
	if err := httpClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("default issuer CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}
