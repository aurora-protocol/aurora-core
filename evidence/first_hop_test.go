package evidence

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRunFirstHopReportsBoundedSuccess(t *testing.T) {
	harness := firstHopTestHarness{run: func(ctx context.Context) (FirstHopObservation, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > maxFirstHopEvidenceDuration {
			return FirstHopObservation{}, errors.New("evidence harness received invalid deadline")
		}
		return completeFirstHopObservation(), nil
	}}
	result, err := RunFirstHop(context.Background(), harness)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || !result.TLS13 || !result.HTTP2 || !result.FreshConnection || !result.PreludeAuthenticated || !result.AdmissionSpent || !result.ReplayRejected || !result.ApplicationRoundTrip || !result.KeyUpdateRoundTrip {
		t.Fatalf("incomplete first-hop success result: %+v", result)
	}
	if result.PeakQueuedPackets != 4 || result.PeakQueuedBytes != 8192 || result.HandshakeDuration != 25*time.Millisecond || len(result.Findings) != 0 {
		t.Fatalf("unexpected first-hop metrics: %+v", result)
	}
}

func TestRunFirstHopDerivesFixedFindings(t *testing.T) {
	observation := completeFirstHopObservation()
	observation.TLS13 = false
	observation.HTTP2 = false
	observation.FreshConnection = false
	observation.PreludeAuthenticated = false
	observation.AdmissionSpent = false
	observation.ReplayRejected = false
	observation.ApplicationRoundTrip = false
	observation.KeyUpdateRoundTrip = false
	result, err := RunFirstHop(context.Background(), firstHopTestHarness{run: func(context.Context) (FirstHopObservation, error) {
		return observation, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed || len(result.Findings) != 8 || len(result.Findings) > maxFirstHopEvidenceFindings {
		t.Fatalf("invalid failed first-hop result: %+v", result)
	}
	for _, finding := range result.Findings {
		if strings.ContainsAny(finding, "0123456789:=") {
			t.Fatalf("finding is not a fixed non-sensitive label: %q", finding)
		}
	}
}

func TestRunFirstHopRejectsInvalidInputsAndMetrics(t *testing.T) {
	validHarness := firstHopTestHarness{run: func(context.Context) (FirstHopObservation, error) {
		return completeFirstHopObservation(), nil
	}}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	if result, err := RunFirstHop(nil, validHarness); err == nil || !reflect.DeepEqual(result, FirstHopResult{}) {
		t.Fatalf("RunFirstHop(nil) = %+v, %v; want empty result and error", result, err)
	}
	if result, err := RunFirstHop(context.Background(), nil); err == nil || !reflect.DeepEqual(result, FirstHopResult{}) {
		t.Fatalf("RunFirstHop(nil harness) = %+v, %v; want empty result and error", result, err)
	}
	var typedNil *firstHopPointerHarness
	if result, err := RunFirstHop(context.Background(), typedNil); err == nil || !reflect.DeepEqual(result, FirstHopResult{}) {
		t.Fatalf("RunFirstHop(typed nil) = %+v, %v; want empty result and error", result, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := RunFirstHop(canceled, validHarness); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, FirstHopResult{}) {
		t.Fatalf("RunFirstHop(canceled) = %+v, %v; want context cancellation", result, err)
	}

	for name, mutate := range map[string]func(*FirstHopObservation){
		"negative packets":   func(in *FirstHopObservation) { in.PeakQueuedPackets = -1 },
		"excessive packets":  func(in *FirstHopObservation) { in.PeakQueuedPackets = maxFirstHopEvidenceQueuedPackets + 1 },
		"negative bytes":     func(in *FirstHopObservation) { in.PeakQueuedBytes = -1 },
		"excessive bytes":    func(in *FirstHopObservation) { in.PeakQueuedBytes = maxFirstHopEvidenceQueuedBytes + 1 },
		"zero duration":      func(in *FirstHopObservation) { in.HandshakeDuration = 0 },
		"excessive duration": func(in *FirstHopObservation) { in.HandshakeDuration = maxFirstHopEvidenceDuration + time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			observation := completeFirstHopObservation()
			mutate(&observation)
			result, err := RunFirstHop(context.Background(), firstHopTestHarness{run: func(context.Context) (FirstHopObservation, error) {
				return observation, nil
			}})
			if err == nil || result.Passed || len(result.Findings) != 1 || result.Findings[0] != "invalid harness metrics" {
				t.Fatalf("invalid metrics result = %+v, %v", result, err)
			}
		})
	}
}

func TestRunFirstHopDoesNotRetainHarnessErrorText(t *testing.T) {
	const secret = "private-key-deadbeef"
	result, err := RunFirstHop(context.Background(), firstHopTestHarness{run: func(context.Context) (FirstHopObservation, error) {
		return FirstHopObservation{}, errors.New(secret)
	}})
	if !errors.Is(err, ErrFirstHopHarnessFailed) || strings.Contains(err.Error(), secret) {
		t.Fatalf("harness error was not sanitized: %v", err)
	}
	if result.Passed || len(result.Findings) != 1 || result.Findings[0] != "harness failed" || strings.Contains(strings.Join(result.Findings, " "), secret) {
		t.Fatalf("harness error leaked into result: %+v", result)
	}
}

func TestRunFirstHopRejectsObservationAfterDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	result, err := RunFirstHop(ctx, firstHopTestHarness{run: func(ctx context.Context) (FirstHopObservation, error) {
		<-ctx.Done()
		return completeFirstHopObservation(), nil
	}})
	if !errors.Is(err, context.DeadlineExceeded) || result.Passed || len(result.Findings) != 1 || result.Findings[0] != "harness deadline exceeded" {
		t.Fatalf("late observation result = %+v, %v", result, err)
	}
}

func TestRunFirstHopReturnsAtDeadlineWhenHarnessIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := RunFirstHop(ctx, firstHopTestHarness{run: func(context.Context) (FirstHopObservation, error) {
		<-release
		return completeFirstHopObservation(), nil
	}})
	if !errors.Is(err, context.DeadlineExceeded) || result.Passed || len(result.Findings) != 1 || result.Findings[0] != "harness deadline exceeded" {
		t.Fatalf("non-cooperative harness result = %+v, %v", result, err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("non-cooperative harness blocked caller for %s", elapsed)
	}
}

func TestRunFirstHopContainsHarnessPanic(t *testing.T) {
	result, err := RunFirstHop(context.Background(), firstHopTestHarness{run: func(context.Context) (FirstHopObservation, error) {
		panic("private-key-deadbeef")
	}})
	if !errors.Is(err, ErrFirstHopHarnessFailed) || result.Passed || len(result.Findings) != 1 || result.Findings[0] != "harness failed" {
		t.Fatalf("panicking harness result = %+v, %v", result, err)
	}
}

func completeFirstHopObservation() FirstHopObservation {
	return FirstHopObservation{
		TLS13:                true,
		HTTP2:                true,
		FreshConnection:      true,
		PreludeAuthenticated: true,
		AdmissionSpent:       true,
		ReplayRejected:       true,
		ApplicationRoundTrip: true,
		KeyUpdateRoundTrip:   true,
		PeakQueuedPackets:    4,
		PeakQueuedBytes:      8192,
		HandshakeDuration:    25 * time.Millisecond,
	}
}

type firstHopTestHarness struct {
	run func(context.Context) (FirstHopObservation, error)
}

func (h firstHopTestHarness) RunFirstHop(ctx context.Context) (FirstHopObservation, error) {
	return h.run(ctx)
}

type firstHopPointerHarness struct{}

func (*firstHopPointerHarness) RunFirstHop(context.Context) (FirstHopObservation, error) {
	return FirstHopObservation{}, nil
}
