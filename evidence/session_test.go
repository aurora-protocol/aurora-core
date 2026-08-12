package evidence

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunSessionRejectsInvalidOptions(t *testing.T) {
	valid := SessionOptions{
		Duration:     5 * time.Second,
		Messages:     200,
		PayloadBytes: 256,
		Concurrency:  4,
		QueuePackets: 16,
		QueueBytes:   128 << 10,
	}
	for name, mutate := range map[string]func(*SessionOptions){
		"zero duration":          func(options *SessionOptions) { options.Duration = 0 },
		"excessive duration":     func(options *SessionOptions) { options.Duration = time.Minute + time.Nanosecond },
		"zero messages":          func(options *SessionOptions) { options.Messages = 0 },
		"excessive messages":     func(options *SessionOptions) { options.Messages = 1_000_001 },
		"zero payload":           func(options *SessionOptions) { options.PayloadBytes = 0 },
		"excessive payload":      func(options *SessionOptions) { options.PayloadBytes = (1 << 20) + 1 },
		"zero concurrency":       func(options *SessionOptions) { options.Concurrency = 0 },
		"excessive concurrency":  func(options *SessionOptions) { options.Concurrency = 257 },
		"small packet queue":     func(options *SessionOptions) { options.QueuePackets = 2 },
		"excessive packet queue": func(options *SessionOptions) { options.QueuePackets = 4097 },
		"small byte queue":       func(options *SessionOptions) { options.QueueBytes = 8 << 10 },
		"excessive byte queue":   func(options *SessionOptions) { options.QueueBytes = (64 << 20) + 1 },
		"payload exceeds data queue": func(options *SessionOptions) {
			options.QueueBytes = 9 << 10
			options.PayloadBytes = 2 << 10
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if result, err := RunSession(context.Background(), options); err == nil || result != (SessionResult{}) {
				t.Fatalf("RunSession() = %+v, %v; want empty result and error", result, err)
			}
		})
	}
	if result, err := RunSession(nil, valid); err == nil || result != (SessionResult{}) {
		t.Fatalf("RunSession(nil) = %+v, %v; want empty result and error", result, err)
	}
}

func TestRunSessionReportsBoundedFullDuplexEvidence(t *testing.T) {
	options := SessionOptions{
		Duration:     5 * time.Second,
		Messages:     200,
		PayloadBytes: 256,
		Concurrency:  4,
		QueuePackets: 16,
		QueueBytes:   128 << 10,
	}
	result, err := RunSession(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || result.MessagesSent != options.Messages || result.MessagesReceived != options.Messages || result.Errors != 0 {
		t.Fatalf("session result counts = %+v", result)
	}
	wantBytes := uint64(options.Messages * options.PayloadBytes)
	if result.PayloadBytes != wantBytes {
		t.Fatalf("payload bytes = %d, want %d", result.PayloadBytes, wantBytes)
	}
	if result.Duration <= 0 || result.Duration > options.Duration || result.MessagesPerSecond <= 0 || result.BytesPerSecond <= 0 {
		t.Fatalf("invalid duration or throughput: %+v", result)
	}
	if result.LatencyP50 <= 0 || result.LatencyP95 < result.LatencyP50 {
		t.Fatalf("invalid latency percentiles: p50=%s p95=%s", result.LatencyP50, result.LatencyP95)
	}
	if result.PeakQueuedPackets <= 0 || result.PeakQueuedPackets > 2*options.QueuePackets || result.PeakQueuedBytes <= 0 || result.PeakQueuedBytes > 2*options.QueueBytes {
		t.Fatalf("invalid peak queue usage: packets=%d bytes=%d", result.PeakQueuedPackets, result.PeakQueuedBytes)
	}
	if result.GoroutineDelta > 2 {
		t.Fatalf("goroutine delta = %d, want <= 2", result.GoroutineDelta)
	}
}

func TestRunSessionHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := RunSession(ctx, SessionOptions{
		Duration:     5 * time.Second,
		Messages:     200,
		PayloadBytes: 256,
		Concurrency:  4,
		QueuePackets: 16,
		QueueBytes:   128 << 10,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunSession canceled error = %v, want context.Canceled", err)
	}
	if result.Passed || result.Errors == 0 {
		t.Fatalf("canceled session reported success: %+v", result)
	}
}

func TestRunSessionJoinsWorkersAfterDeadline(t *testing.T) {
	result, err := RunSession(context.Background(), SessionOptions{
		Duration:     time.Nanosecond,
		Messages:     1_000,
		PayloadBytes: 256,
		Concurrency:  8,
		QueuePackets: 16,
		QueueBytes:   128 << 10,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunSession deadline error = %v, want context.DeadlineExceeded", err)
	}
	if result.Passed || result.Errors == 0 {
		t.Fatalf("expired session reported success: %+v", result)
	}
	if result.GoroutineDelta > 2 {
		t.Fatalf("goroutine delta after deadline = %d, want <= 2", result.GoroutineDelta)
	}
}

func TestSessionLatencyPercentilesUseNearestRank(t *testing.T) {
	p50, p95 := sessionLatencyPercentiles([]time.Duration{5, 1, 4, 2, 3})
	if p50 != 3 || p95 != 5 {
		t.Fatalf("percentiles = %s/%s, want 3ns/5ns", p50, p95)
	}
}
