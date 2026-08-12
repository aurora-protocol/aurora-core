package session

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestSystemEntropyCancellationDoesNotWaitForOperatingSystemRead(t *testing.T) {
	reader := newBlockingSystemEntropyReader()
	previous := rand.Reader
	rand.Reader = reader
	defer func() { rand.Reader = previous }()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- (systemEntropySource{}).ReadContext(ctx, make([]byte, keyUpdateNonceBytes))
	}()
	awaitSessionSignal(t, reader.started, "system entropy read")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("system entropy cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		reader.unblock()
		<-result
		t.Fatalf("system entropy cancellation waited for the operating system read")
	}
	reader.unblock()
	awaitSessionSignal(t, reader.finished, "system entropy worker completion")
}

func awaitSessionSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

type blockingSystemEntropyReader struct {
	started     chan struct{}
	release     chan struct{}
	finished    chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
	finishOnce  sync.Once
}

func newBlockingSystemEntropyReader() *blockingSystemEntropyReader {
	return &blockingSystemEntropyReader{
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
	}
}

func (r *blockingSystemEntropyReader) Read(p []byte) (int, error) {
	r.startOnce.Do(func() { close(r.started) })
	<-r.release
	for i := range p {
		p[i] = 0x71
	}
	r.finishOnce.Do(func() { close(r.finished) })
	return len(p), nil
}

func (r *blockingSystemEntropyReader) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

var _ io.Reader = (*blockingSystemEntropyReader)(nil)
