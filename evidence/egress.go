package evidence

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

const (
	maxEgressEvidenceDuration      = 30 * time.Second
	maxEgressEvidenceFindings      = 16
	maxEgressEvidenceFlows         = 4096
	maxEgressEvidenceBytes         = 1 << 40
	maxEgressEvidenceQueuedPackets = 4096
	maxEgressEvidenceQueuedBytes   = 64 << 20
)

// ErrEgressHarnessFailed replaces harness errors and panics in public evidence.
var ErrEgressHarnessFailed = errors.New("egress evidence: harness failed")

// EgressObservation is the bounded output of one encrypted destination run.
type EgressObservation struct {
	TCPRoundTrip      bool
	UDPRoundTrip      bool
	ClientKeyUpdate   bool
	RelayKeyUpdate    bool
	TargetEOF         bool
	PolicyDenied      bool
	ShutdownCanceled  bool
	FlowOpens         int
	PeakFlows         int
	TCPBytes          uint64
	UDPBytes          uint64
	PeakQueuedPackets int
	PeakQueuedBytes   int
	Duration          time.Duration
}

// EgressHarness runs one encrypted destination check and must honor cancellation.
type EgressHarness interface {
	RunEgress(context.Context) (EgressObservation, error)
}

// EgressResult reports fixed findings and bounded counters only.
type EgressResult struct {
	Passed            bool          `json:"passed"`
	TCPRoundTrip      bool          `json:"tcp_round_trip"`
	UDPRoundTrip      bool          `json:"udp_round_trip"`
	ClientKeyUpdate   bool          `json:"client_key_update"`
	RelayKeyUpdate    bool          `json:"relay_key_update"`
	TargetEOF         bool          `json:"target_eof"`
	PolicyDenied      bool          `json:"policy_denied"`
	ShutdownCanceled  bool          `json:"shutdown_canceled"`
	FlowOpens         int           `json:"flow_opens"`
	PeakFlows         int           `json:"peak_flows"`
	TCPBytes          uint64        `json:"tcp_bytes"`
	UDPBytes          uint64        `json:"udp_bytes"`
	PeakQueuedPackets int           `json:"peak_queued_packets"`
	PeakQueuedBytes   int           `json:"peak_queued_bytes"`
	Duration          time.Duration `json:"duration_ns"`
	Findings          []string      `json:"findings,omitempty"`
}

// RunEgress bounds harness runtime and removes dependency error text.
func RunEgress(ctx context.Context, harness EgressHarness) (EgressResult, error) {
	if ctx == nil {
		return EgressResult{}, fmt.Errorf("egress evidence: nil context")
	}
	if isNilEgressHarness(harness) {
		return EgressResult{}, fmt.Errorf("egress evidence: nil harness")
	}
	if err := ctx.Err(); err != nil {
		return EgressResult{}, err
	}
	runContext := ctx
	cancel := func() {}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > maxEgressEvidenceDuration {
		runContext, cancel = context.WithTimeout(ctx, maxEgressEvidenceDuration)
	}
	defer cancel()
	type harnessResult struct {
		observation EgressObservation
		err         error
	}
	results := make(chan harnessResult, 1)
	go func() {
		completed := harnessResult{}
		defer func() {
			if recover() != nil {
				completed = harnessResult{err: ErrEgressHarnessFailed}
			}
			results <- completed
		}()
		completed.observation, completed.err = harness.RunEgress(runContext)
	}()
	var completed harnessResult
	select {
	case completed = <-results:
	case <-runContext.Done():
		return EgressResult{Findings: []string{"harness deadline exceeded"}}, runContext.Err()
	}
	if contextErr := runContext.Err(); contextErr != nil {
		return EgressResult{Findings: []string{"harness deadline exceeded"}}, contextErr
	}
	if completed.err != nil {
		return EgressResult{Findings: []string{"harness failed"}}, ErrEgressHarnessFailed
	}
	observation := completed.observation
	result := EgressResult{
		TCPRoundTrip:      observation.TCPRoundTrip,
		UDPRoundTrip:      observation.UDPRoundTrip,
		ClientKeyUpdate:   observation.ClientKeyUpdate,
		RelayKeyUpdate:    observation.RelayKeyUpdate,
		TargetEOF:         observation.TargetEOF,
		PolicyDenied:      observation.PolicyDenied,
		ShutdownCanceled:  observation.ShutdownCanceled,
		FlowOpens:         observation.FlowOpens,
		PeakFlows:         observation.PeakFlows,
		TCPBytes:          observation.TCPBytes,
		UDPBytes:          observation.UDPBytes,
		PeakQueuedPackets: observation.PeakQueuedPackets,
		PeakQueuedBytes:   observation.PeakQueuedBytes,
		Duration:          observation.Duration,
	}
	if !validEgressObservationMetrics(observation) {
		result.Findings = []string{"invalid harness metrics"}
		return result, fmt.Errorf("egress evidence: invalid harness metrics")
	}
	for _, check := range []struct {
		passed  bool
		finding string
	}{
		{observation.TCPRoundTrip, "tcp round trip failed"},
		{observation.UDPRoundTrip, "udp round trip failed"},
		{observation.ClientKeyUpdate, "client key update failed"},
		{observation.RelayKeyUpdate, "relay key update failed"},
		{observation.TargetEOF, "target eof was not observed"},
		{observation.PolicyDenied, "policy denial failed"},
		{observation.ShutdownCanceled, "shutdown cancellation failed"},
	} {
		if !check.passed && len(result.Findings) < maxEgressEvidenceFindings {
			result.Findings = append(result.Findings, check.finding)
		}
	}
	result.Passed = len(result.Findings) == 0
	return result, nil
}

func validEgressObservationMetrics(observation EgressObservation) bool {
	return observation.FlowOpens > 0 &&
		observation.FlowOpens <= maxEgressEvidenceFlows &&
		observation.PeakFlows >= 0 &&
		observation.PeakFlows <= observation.FlowOpens &&
		observation.TCPBytes > 0 &&
		observation.TCPBytes <= maxEgressEvidenceBytes &&
		observation.UDPBytes > 0 &&
		observation.UDPBytes <= maxEgressEvidenceBytes &&
		observation.PeakQueuedPackets >= 0 &&
		observation.PeakQueuedPackets <= maxEgressEvidenceQueuedPackets &&
		observation.PeakQueuedBytes >= 0 &&
		observation.PeakQueuedBytes <= maxEgressEvidenceQueuedBytes &&
		observation.Duration > 0 &&
		observation.Duration <= maxEgressEvidenceDuration
}

func isNilEgressHarness(harness EgressHarness) bool {
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
