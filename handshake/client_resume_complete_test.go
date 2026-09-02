package handshake

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capsuleBlockingClientOpener wraps scriptedClientOpener so the capsule write
// (the second bootstrap record) blocks until the test releases it. That pause
// is the window in which Complete is still awaiting the driver result, so
// tests can cancel the completion context or close the handshake mid-Complete.
type capsuleBlockingClientOpener struct {
	inner   *scriptedClientOpener
	entered chan struct{} // closed when the capsule write begins
	release chan struct{} // closed to let the capsule write proceed
}

func (o *capsuleBlockingClientOpener) Open(ctx context.Context, coverRandom []byte) (BootstrapCarrier, error) {
	carrier, err := o.inner.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	return &capsuleBlockingClientCarrier{
		BootstrapCarrier: carrier,
		entered:          o.entered,
		release:          o.release,
	}, nil
}

type capsuleBlockingClientCarrier struct {
	BootstrapCarrier
	entered chan struct{}
	release chan struct{}
	writes  atomic.Int32
	once    sync.Once
}

func (c *capsuleBlockingClientCarrier) WriteRecord(record []byte) error {
	if c.writes.Add(1) == 2 {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.BootstrapCarrier.WriteRecord(record)
}

func TestClientHandshakeCompleteRejectsCancelledContext(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, _, driver := newClientDriverTestSetup(t, now, fixture, nil)
	opener := &scriptedClientOpener{fixture: fixture, config: config}

	handshake, _, err := driver.Begin(context.Background(), opener)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	proof, replay := deferredClientProofs(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if established, err := handshake.Complete(ctx, proof, replay); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("cancelled completion context completed handshake")
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled completion error = %v, want context.Canceled", err)
	}
	carrier := opener.lastCarrier()
	if carrier == nil {
		t.Fatal("client opener did not retain carrier")
	}
	if carrier.closes.Load() != 1 {
		t.Fatalf("carrier closes after cancelled completion = %d, want 1", carrier.closes.Load())
	}
}

func TestClientHandshakeCompleteAfterCloseFails(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, _, driver := newClientDriverTestSetup(t, now, fixture, nil)
	opener := &scriptedClientOpener{fixture: fixture, config: config}

	handshake, _, err := driver.Begin(context.Background(), opener)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	if err := handshake.Close(); err != nil {
		t.Fatalf("close pending client handshake: %v", err)
	}
	proof, replay := deferredClientProofs(t)
	if established, err := handshake.Complete(context.Background(), proof, replay); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("closed client handshake accepted completion")
	} else if !strings.Contains(err.Error(), "client handshake is closed") {
		t.Fatalf("completion after close error = %v, want closed-handshake error", err)
	}
}

func TestClientHandshakeCompleteRejectsUncloneableProofs(t *testing.T) {
	for _, name := range []string{"admission", "replay"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			fixture := newTestVerifiedDeploymentFixture(t, now)
			config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
			opener := &scriptedClientOpener{fixture: fixture, config: config}

			handshake, request, err := driver.Begin(context.Background(), opener)
			if err != nil {
				t.Fatalf("begin client handshake: %v", err)
			}
			proof, replay, err := provider.BuildProofs(context.Background(), request)
			if err != nil {
				t.Fatalf("build client proofs: %v", err)
			}
			// WriteOpaqueFixed rejects a truncated fixed-width field, so the
			// deferred provider cannot clone the supplied proof and Complete
			// must fail before any capsule byte is written.
			if name == "admission" {
				proof.IssuerID = proof.IssuerID[:8]
			} else {
				replay.ClientReplayNonce = replay.ClientReplayNonce[:8]
			}
			established, err := handshake.Complete(context.Background(), proof, replay)
			if established != nil {
				_ = established.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "clone supplied "+name+" proof") {
				t.Fatalf("uncloneable %s proof error = %v, want clone failure", name, err)
			}
			carrier := opener.lastCarrier()
			if carrier == nil {
				t.Fatal("client opener did not retain carrier")
			}
			if len(carrier.writes) != 1 {
				t.Fatalf("bootstrap records after uncloneable %s proof = %d, want 1", name, len(carrier.writes))
			}
			if carrier.closes.Load() != 1 {
				t.Fatalf("carrier closes after uncloneable %s proof = %d, want 1", name, carrier.closes.Load())
			}
		})
	}
}

func TestClientHandshakeCompleteCancellationDuringCompletionClosesHandshake(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	blocking := &capsuleBlockingClientOpener{
		inner:   &scriptedClientOpener{fixture: fixture, config: config},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}

	handshake, request, err := driver.Begin(context.Background(), blocking)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	proof, replay, err := provider.BuildProofs(context.Background(), request)
	if err != nil {
		t.Fatalf("build client proofs: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed := make(chan error, 1)
	go func() {
		established, err := handshake.Complete(ctx, proof, replay)
		if established != nil {
			_ = established.Close()
		}
		completed <- err
	}()
	<-blocking.entered
	// Cancel while the driver is blocked mid-capsule: Complete must abandon the
	// wait and close the handshake. Releasing the capsule write afterwards lets
	// the driver goroutine finish so the internal Close can observe done.
	cancel()
	close(blocking.release)
	if err := <-completed; !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-completion cancellation error = %v, want context.Canceled", err)
	}
}

func TestClientHandshakeCompleteRacingCloseReportsClosed(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	blocking := &capsuleBlockingClientOpener{
		inner:   &scriptedClientOpener{fixture: fixture, config: config},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}

	handshake, request, err := driver.Begin(context.Background(), blocking)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	proof, replay, err := provider.BuildProofs(context.Background(), request)
	if err != nil {
		t.Fatalf("build client proofs: %v", err)
	}
	completed := make(chan error, 1)
	go func() {
		established, err := handshake.Complete(context.Background(), proof, replay)
		if established != nil {
			_ = established.Close()
		}
		completed <- err
	}()
	<-blocking.entered
	// Close while the driver is blocked mid-capsule: once Close has marked the
	// handshake closed, the driver result can no longer be transferred, so
	// Complete must report the closed handshake instead.
	closed := make(chan error, 1)
	go func() { closed <- handshake.Close() }()
	closedDeadline := time.After(5 * time.Second)
	for {
		handshake.mu.Lock()
		marked := handshake.closed
		handshake.mu.Unlock()
		if marked {
			break
		}
		select {
		case <-closedDeadline:
			t.Fatal("racing Close never marked the handshake closed")
		default:
		}
		runtime.Gosched()
	}
	close(blocking.release)
	if err := <-closed; err != nil {
		t.Fatalf("close racing completion: %v", err)
	}
	if err := <-completed; err == nil || !strings.Contains(err.Error(), "client handshake is closed") {
		t.Fatalf("completion racing close error = %v, want closed-handshake error", err)
	}
}
