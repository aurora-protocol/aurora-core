package session

import (
	"bytes"
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

// TestSystemEntropySourceReadContextFailsClosedOnShortRead covers the
// incomplete-result guard at session/entropy.go:63-65: when the broker replies
// with fewer bytes than requested, ReadContext returns an error and never
// copies into the caller's buffer (the buffer stays zeroed). The test plays
// broker itself over an explicit requests channel, so it is deterministic.
func TestSystemEntropySourceReadContextFailsClosedOnShortRead(t *testing.T) {
	requests := make(chan systemEntropyRequest)
	source := systemEntropySource{requests: requests}
	buffer := make([]byte, keyUpdateNonceBytes)
	result := make(chan error, 1)
	go func() {
		result <- source.ReadContext(context.Background(), buffer)
	}()
	var request systemEntropyRequest
	select {
	case request = <-requests:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the entropy request")
	}
	request.response <- systemEntropyResult{value: bytes.Repeat([]byte{0x42}, len(buffer)-1)}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("short system entropy read succeeded, want an error")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the short-read result")
	}
	if !bytes.Equal(buffer, make([]byte, len(buffer))) {
		t.Fatal("short system entropy read copied into the caller's buffer")
	}
}

// TestSystemEntropySourceReadContextHonorsCancellationBeforeCopy covers the
// cancellation checks between the broker reply and the buffer copy at
// session/entropy.go:66-72: a context canceled after the request is accepted
// must fail the read with context.Canceled and leave the buffer zeroed, even
// though the broker delivered a full-length reply.
func TestSystemEntropySourceReadContextHonorsCancellationBeforeCopy(t *testing.T) {
	requests := make(chan systemEntropyRequest)
	source := systemEntropySource{requests: requests}
	ctx, cancel := context.WithCancel(context.Background())
	buffer := make([]byte, keyUpdateNonceBytes)
	result := make(chan error, 1)
	go func() {
		result <- source.ReadContext(ctx, buffer)
	}()
	var request systemEntropyRequest
	select {
	case request = <-requests:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the entropy request")
	}
	cancel()
	// After cancel, ReadContext may take either the response arm (:66) or the
	// ctx.Done arm (:71-72) of its second select; both return context.Canceled
	// without copying. Send the reply from a goroutine so a receiver that
	// already took the ctx.Done arm cannot deadlock the test.
	go func() {
		select {
		case request.response <- systemEntropyResult{value: bytes.Repeat([]byte{0x42}, len(buffer))}:
		case <-time.After(time.Second):
		}
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled system entropy read = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the canceled read result")
	}
	if !bytes.Equal(buffer, make([]byte, len(buffer))) {
		t.Fatal("canceled system entropy read copied into the caller's buffer")
	}
}
