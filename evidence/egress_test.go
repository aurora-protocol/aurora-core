package evidence

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRunEgressReportsBoundedSuccess(t *testing.T) {
	result, err := RunEgress(context.Background(), egressTestHarness{run: func(ctx context.Context) (EgressObservation, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > maxEgressEvidenceDuration {
			return EgressObservation{}, errors.New("invalid evidence deadline")
		}
		return completeEgressObservation(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || !result.TCPRoundTrip || !result.UDPRoundTrip || !result.ClientKeyUpdate || !result.RelayKeyUpdate || !result.TargetEOF || !result.PolicyDenied || !result.ShutdownCanceled {
		t.Fatalf("incomplete egress result: %+v", result)
	}
	if result.FlowOpens != 2 || result.PeakFlows != 2 || result.TCPBytes != 4096 || result.UDPBytes != 1200 || result.PeakQueuedPackets != 4 || result.PeakQueuedBytes != 8192 || result.Duration != 25*time.Millisecond || len(result.Findings) != 0 {
		t.Fatalf("unexpected egress metrics: %+v", result)
	}
}

func TestRunEgressDerivesFixedFindings(t *testing.T) {
	observation := completeEgressObservation()
	observation.TCPRoundTrip = false
	observation.UDPRoundTrip = false
	observation.ClientKeyUpdate = false
	observation.RelayKeyUpdate = false
	observation.TargetEOF = false
	observation.PolicyDenied = false
	observation.ShutdownCanceled = false
	result, err := RunEgress(context.Background(), egressTestHarness{run: func(context.Context) (EgressObservation, error) {
		return observation, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed || len(result.Findings) != 7 || len(result.Findings) > maxEgressEvidenceFindings {
		t.Fatalf("invalid failed egress result: %+v", result)
	}
	for _, finding := range result.Findings {
		if strings.ContainsAny(finding, "0123456789:=") {
			t.Fatalf("finding is not a fixed label: %q", finding)
		}
	}
}

func TestRunEgressRejectsInvalidInputsAndMetrics(t *testing.T) {
	valid := egressTestHarness{run: func(context.Context) (EgressObservation, error) { return completeEgressObservation(), nil }}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	if result, err := RunEgress(nil, valid); err == nil || !reflect.DeepEqual(result, EgressResult{}) {
		t.Fatalf("RunEgress(nil) = %+v, %v", result, err)
	}
	if result, err := RunEgress(context.Background(), nil); err == nil || !reflect.DeepEqual(result, EgressResult{}) {
		t.Fatalf("RunEgress(nil harness) = %+v, %v", result, err)
	}
	var typedNil *egressPointerHarness
	if result, err := RunEgress(context.Background(), typedNil); err == nil || !reflect.DeepEqual(result, EgressResult{}) {
		t.Fatalf("RunEgress(typed nil) = %+v, %v", result, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := RunEgress(canceled, valid); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, EgressResult{}) {
		t.Fatalf("RunEgress(canceled) = %+v, %v", result, err)
	}

	for name, mutate := range map[string]func(*EgressObservation){
		"zero flow opens":     func(in *EgressObservation) { in.FlowOpens = 0 },
		"excess flow opens":   func(in *EgressObservation) { in.FlowOpens = maxEgressEvidenceFlows + 1 },
		"negative peak flows": func(in *EgressObservation) { in.PeakFlows = -1 },
		"peak exceeds opens":  func(in *EgressObservation) { in.PeakFlows = in.FlowOpens + 1 },
		"excess TCP bytes":    func(in *EgressObservation) { in.TCPBytes = maxEgressEvidenceBytes + 1 },
		"excess UDP bytes":    func(in *EgressObservation) { in.UDPBytes = maxEgressEvidenceBytes + 1 },
		"negative packets":    func(in *EgressObservation) { in.PeakQueuedPackets = -1 },
		"excess packets":      func(in *EgressObservation) { in.PeakQueuedPackets = maxEgressEvidenceQueuedPackets + 1 },
		"negative bytes":      func(in *EgressObservation) { in.PeakQueuedBytes = -1 },
		"excess queued bytes": func(in *EgressObservation) { in.PeakQueuedBytes = maxEgressEvidenceQueuedBytes + 1 },
		"zero duration":       func(in *EgressObservation) { in.Duration = 0 },
		"excess duration":     func(in *EgressObservation) { in.Duration = maxEgressEvidenceDuration + time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			observation := completeEgressObservation()
			mutate(&observation)
			result, err := RunEgress(context.Background(), egressTestHarness{run: func(context.Context) (EgressObservation, error) {
				return observation, nil
			}})
			if err == nil || result.Passed || len(result.Findings) != 1 || result.Findings[0] != "invalid harness metrics" {
				t.Fatalf("invalid metrics result = %+v, %v", result, err)
			}
		})
	}
}

func TestRunEgressSanitizesHarnessFailureAndPanic(t *testing.T) {
	const secret = "private-target-and-key-material"
	for name, run := range map[string]func(context.Context) (EgressObservation, error){
		"error": func(context.Context) (EgressObservation, error) { return EgressObservation{}, errors.New(secret) },
		"panic": func(context.Context) (EgressObservation, error) { panic(secret) },
	} {
		t.Run(name, func(t *testing.T) {
			result, err := RunEgress(context.Background(), egressTestHarness{run: run})
			if !errors.Is(err, ErrEgressHarnessFailed) || strings.Contains(err.Error(), secret) {
				t.Fatalf("harness failure was not sanitized: %v", err)
			}
			if result.Passed || len(result.Findings) != 1 || result.Findings[0] != "harness failed" || strings.Contains(strings.Join(result.Findings, " "), secret) {
				t.Fatalf("harness failure leaked into result: %+v", result)
			}
		})
	}
}

func TestRunEgressReturnsAtDeadlineWhenHarnessIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	result, err := RunEgress(ctx, egressTestHarness{run: func(context.Context) (EgressObservation, error) {
		<-release
		return completeEgressObservation(), nil
	}})
	if !errors.Is(err, context.DeadlineExceeded) || result.Passed || len(result.Findings) != 1 || result.Findings[0] != "harness deadline exceeded" {
		t.Fatalf("non-cooperative harness result = %+v, %v", result, err)
	}
}

func TestEgressEvidenceSchemaHasNoSensitiveValueFields(t *testing.T) {
	for _, value := range []any{EgressObservation{}, EgressResult{}} {
		typeOf := reflect.TypeOf(value)
		for i := 0; i < typeOf.NumField(); i++ {
			field := typeOf.Field(i)
			name := strings.ToLower(field.Name)
			sensitiveName := strings.Contains(name, "host") || strings.Contains(name, "address") || strings.Contains(name, "payload") || strings.Contains(name, "key") || strings.Contains(name, "nonce") || strings.Contains(name, "proof") || strings.Contains(name, "error")
			if sensitiveName && field.Type.Kind() != reflect.Bool {
				t.Fatalf("sensitive evidence field %s", field.Name)
			}
		}
	}
}

func completeEgressObservation() EgressObservation {
	return EgressObservation{
		TCPRoundTrip:      true,
		UDPRoundTrip:      true,
		ClientKeyUpdate:   true,
		RelayKeyUpdate:    true,
		TargetEOF:         true,
		PolicyDenied:      true,
		ShutdownCanceled:  true,
		FlowOpens:         2,
		PeakFlows:         2,
		TCPBytes:          4096,
		UDPBytes:          1200,
		PeakQueuedPackets: 4,
		PeakQueuedBytes:   8192,
		Duration:          25 * time.Millisecond,
	}
}

type egressTestHarness struct {
	run func(context.Context) (EgressObservation, error)
}

func (h egressTestHarness) RunEgress(ctx context.Context) (EgressObservation, error) {
	return h.run(ctx)
}

type egressPointerHarness struct{}

func (*egressPointerHarness) RunEgress(context.Context) (EgressObservation, error) {
	return EgressObservation{}, nil
}
