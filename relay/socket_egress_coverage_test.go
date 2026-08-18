package relay

// Adversarial coverage for relay/socket_egress.go validation paths that the
// existing socket_egress_test.go does not reach:
//   - NewSocketEgress cancelled-context branch (ctx.Err() before dependency
//     checks) — the existing nil-context test hits the earlier nil guard.
//   - normalizeSocketEgressLimits field-bound branches (TCPReadBufferBytes,
//     MaxUDPDatagramBytes, buffer-too-small-for-one-flow, DialTimeout,
//     WriteTimeout, IdleTimeout, QueueRetryInterval, ResolvedTTLSeconds). The
//     existing TestNewSocketEgressRejectsInvalidDependenciesAndLimits only
//     exercises the MaxFlows bounds and the partial-limits (zero
//     MaxBufferedBytes) path; the remaining field validators are reached via
//     ValidateSocketEgressLimits, the pure wrapper around
//     normalizeSocketEgressLimits, which also closes the
//     ValidateSocketEgressLimits success+error branches.
//
// Each perturbation starts from validSocketEgressLimits (an all-valid fixture)
// and mutates a single field so every earlier bound check passes and the
// target branch is the one that fires. Coverage is re-measured per group to
// confirm the intended branch moved (no wrong-branch bugs).

import (
	"context"
	"testing"
	"time"
)

// validSocketEgressLimitsForCoverage mirrors the existing validSocketEgressLimits
// helper (socket_egress_test.go:176) but takes no argument so it can be used as a
// perturbation base; the all-valid limits pass every normalize check.
func validSocketEgressLimitsForCoverage() SocketEgressLimits {
	return validSocketEgressLimits(64)
}

func TestNewSocketEgressRejectsAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A non-nil but already-errored context must be rejected at the ctx.Err()
	// guard (line 134-135), distinct from the nil-context guard (131-132).
	egress, err := NewSocketEgress(ctx, SocketEgressOptions{
		Sink:     &recordingFrameSink{},
		Dialer:   &recordingContextDialer{},
		Resolver: &recordingIPResolver{},
		Limits:   validSocketEgressLimitsForCoverage(),
	})
	if err == nil {
		_ = egress.Close()
		t.Fatal("NewSocketEgress accepted an already-cancelled context")
	}
}

// TestValidateSocketEgressLimitsRejectsOutOfBoundsFields drives each
// normalizeSocketEgressLimits field validator from an all-valid base by
// perturbing one field below/above its bound. Each case must error.
func TestValidateSocketEgressLimitsRejectsOutOfBoundsFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(l *SocketEgressLimits)
	}{
		{"tcp read buffer too small", func(l *SocketEgressLimits) { l.TCPReadBufferBytes = minimumSocketReadBufferBytes - 1 }},
		{"tcp read buffer too large", func(l *SocketEgressLimits) { l.TCPReadBufferBytes = maximumTCPReadBufferBytes + 1 }},
		{"udp datagram too small", func(l *SocketEgressLimits) { l.MaxUDPDatagramBytes = minimumSocketUDPDatagramBytes - 1 }},
		{"udp datagram too large", func(l *SocketEgressLimits) { l.MaxUDPDatagramBytes = maximumUDPDatagramBytes + 1 }},
		{"buffer smaller than tcp read buffer", func(l *SocketEgressLimits) {
			// MaxBufferedBytes stays in valid range but below TCPReadBufferBytes.
			l.MaxBufferedBytes = l.TCPReadBufferBytes - 1
		}},
		{"buffer smaller than one udp datagram", func(l *SocketEgressLimits) {
			l.MaxBufferedBytes = l.MaxUDPDatagramBytes
		}},
		{"dial timeout zero", func(l *SocketEgressLimits) { l.DialTimeout = 0 }},
		{"dial timeout too large", func(l *SocketEgressLimits) { l.DialTimeout = maximumSocketOperationTimeout + time.Second }},
		{"write timeout zero", func(l *SocketEgressLimits) { l.WriteTimeout = 0 }},
		{"write timeout too large", func(l *SocketEgressLimits) { l.WriteTimeout = maximumSocketOperationTimeout + time.Second }},
		{"idle timeout zero", func(l *SocketEgressLimits) { l.IdleTimeout = 0 }},
		{"idle timeout too large", func(l *SocketEgressLimits) { l.IdleTimeout = maximumSocketIdleTimeout + time.Second }},
		{"queue retry interval zero", func(l *SocketEgressLimits) { l.QueueRetryInterval = 0 }},
		{"queue retry interval too large", func(l *SocketEgressLimits) { l.QueueRetryInterval = maximumExitQueueRetryInterval + time.Second }},
		{"resolved ttl zero", func(l *SocketEgressLimits) { l.ResolvedTTLSeconds = 0 }},
		{"resolved ttl too large", func(l *SocketEgressLimits) { l.ResolvedTTLSeconds = maximumSocketResolvedTTLSeconds + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limits := validSocketEgressLimitsForCoverage()
			tc.mutate(&limits)
			if err := ValidateSocketEgressLimits(limits); err == nil {
				t.Fatalf("ValidateSocketEgressLimits accepted %s", tc.name)
			}
		})
	}
}

// TestValidateSocketEgressLimitsAcceptsValidBounds exercises the zero-value
// defaults path and the all-valid return-nil path, covering the success
// branches of both ValidateSocketEgressLimits and normalizeSocketEgressLimits.
func TestValidateSocketEgressLimitsAcceptsValidBounds(t *testing.T) {
	t.Run("zero value yields defaults", func(t *testing.T) {
		if err := ValidateSocketEgressLimits(SocketEgressLimits{}); err != nil {
			t.Fatalf("ValidateSocketEgressLimits(zero) returned err: %v", err)
		}
	})
	t.Run("all valid", func(t *testing.T) {
		if err := ValidateSocketEgressLimits(validSocketEgressLimitsForCoverage()); err != nil {
			t.Fatalf("ValidateSocketEgressLimits(valid) returned err: %v", err)
		}
	})
}
