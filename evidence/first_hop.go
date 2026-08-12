package evidence

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

const (
	maxFirstHopEvidenceDuration      = 30 * time.Second
	maxFirstHopEvidenceFindings      = 16
	maxFirstHopEvidenceQueuedPackets = 4096
	maxFirstHopEvidenceQueuedBytes   = 64 << 20
)

// ErrFirstHopHarnessFailed replaces harness errors and panics so reports never
// retain dependency error text.
var ErrFirstHopHarnessFailed = errors.New("first-hop evidence: harness failed")

// FirstHopObservation is the bounded, non-sensitive output of one live run.
type FirstHopObservation struct {
	TLS13                bool
	HTTP2                bool
	FreshConnection      bool
	PreludeAuthenticated bool
	AdmissionSpent       bool
	ReplayRejected       bool
	ApplicationRoundTrip bool
	KeyUpdateRoundTrip   bool
	PeakQueuedPackets    int
	PeakQueuedBytes      int
	HandshakeDuration    time.Duration
}

// FirstHopHarness runs one live first-hop session and must honor cancellation.
type FirstHopHarness interface {
	RunFirstHop(context.Context) (FirstHopObservation, error)
}

// FirstHopResult reports fixed findings and bounded counters only.
type FirstHopResult struct {
	Passed               bool          `json:"passed"`
	TLS13                bool          `json:"tls_13"`
	HTTP2                bool          `json:"http_2"`
	FreshConnection      bool          `json:"fresh_connection"`
	PreludeAuthenticated bool          `json:"prelude_authenticated"`
	AdmissionSpent       bool          `json:"admission_spent"`
	ReplayRejected       bool          `json:"replay_rejected"`
	ApplicationRoundTrip bool          `json:"application_round_trip"`
	KeyUpdateRoundTrip   bool          `json:"key_update_round_trip"`
	PeakQueuedPackets    int           `json:"peak_queued_packets"`
	PeakQueuedBytes      int           `json:"peak_queued_bytes"`
	HandshakeDuration    time.Duration `json:"handshake_duration_ns"`
	Findings             []string      `json:"findings,omitempty"`
}

// RunFirstHop bounds harness runtime, validates metrics, and derives fixed
// findings without retaining raw dependency errors.
func RunFirstHop(ctx context.Context, harness FirstHopHarness) (FirstHopResult, error) {
	if ctx == nil {
		return FirstHopResult{}, fmt.Errorf("first-hop evidence: nil context")
	}
	if isNilFirstHopHarness(harness) {
		return FirstHopResult{}, fmt.Errorf("first-hop evidence: nil harness")
	}
	if err := ctx.Err(); err != nil {
		return FirstHopResult{}, err
	}

	runContext := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > maxFirstHopEvidenceDuration {
		runContext, cancel = context.WithTimeout(ctx, maxFirstHopEvidenceDuration)
	}
	defer cancel()
	type harnessResult struct {
		observation FirstHopObservation
		err         error
	}
	results := make(chan harnessResult, 1)
	go func() {
		completed := harnessResult{}
		defer func() {
			if recover() != nil {
				completed = harnessResult{err: ErrFirstHopHarnessFailed}
			}
			results <- completed
		}()
		completed.observation, completed.err = harness.RunFirstHop(runContext)
	}()
	var completed harnessResult
	select {
	case completed = <-results:
	case <-runContext.Done():
		return FirstHopResult{Findings: []string{"harness deadline exceeded"}}, runContext.Err()
	}
	observation, err := completed.observation, completed.err
	if contextErr := runContext.Err(); contextErr != nil {
		return FirstHopResult{Findings: []string{"harness deadline exceeded"}}, contextErr
	}
	if err != nil {
		result := FirstHopResult{Findings: []string{"harness failed"}}
		return result, ErrFirstHopHarnessFailed
	}

	result := FirstHopResult{
		TLS13:                observation.TLS13,
		HTTP2:                observation.HTTP2,
		FreshConnection:      observation.FreshConnection,
		PreludeAuthenticated: observation.PreludeAuthenticated,
		AdmissionSpent:       observation.AdmissionSpent,
		ReplayRejected:       observation.ReplayRejected,
		ApplicationRoundTrip: observation.ApplicationRoundTrip,
		KeyUpdateRoundTrip:   observation.KeyUpdateRoundTrip,
		PeakQueuedPackets:    observation.PeakQueuedPackets,
		PeakQueuedBytes:      observation.PeakQueuedBytes,
		HandshakeDuration:    observation.HandshakeDuration,
	}
	if !validFirstHopObservationMetrics(observation) {
		result.Findings = []string{"invalid harness metrics"}
		return result, fmt.Errorf("first-hop evidence: invalid harness metrics")
	}
	for _, check := range []struct {
		passed  bool
		finding string
	}{
		{observation.TLS13, "tls version mismatch"},
		{observation.HTTP2, "http transport mismatch"},
		{observation.FreshConnection, "connection was not fresh"},
		{observation.PreludeAuthenticated, "prelude authentication failed"},
		{observation.AdmissionSpent, "admission was not spent"},
		{observation.ReplayRejected, "replay was not rejected"},
		{observation.ApplicationRoundTrip, "application round trip failed"},
		{observation.KeyUpdateRoundTrip, "key update round trip failed"},
	} {
		if !check.passed && len(result.Findings) < maxFirstHopEvidenceFindings {
			result.Findings = append(result.Findings, check.finding)
		}
	}
	result.Passed = len(result.Findings) == 0
	return result, nil
}

func validFirstHopObservationMetrics(observation FirstHopObservation) bool {
	return observation.PeakQueuedPackets >= 0 &&
		observation.PeakQueuedPackets <= maxFirstHopEvidenceQueuedPackets &&
		observation.PeakQueuedBytes >= 0 &&
		observation.PeakQueuedBytes <= maxFirstHopEvidenceQueuedBytes &&
		observation.HandshakeDuration > 0 &&
		observation.HandshakeDuration <= maxFirstHopEvidenceDuration
}

func isNilFirstHopHarness(harness FirstHopHarness) bool {
	if harness == nil {
		return true
	}
	value := reflect.ValueOf(harness)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
