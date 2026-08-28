package main

import (
	"context"
	"fmt"
	"testing"
)

func TestRunWithCarrierRecoveryTreatsWrappedAttemptCancellationAsCleanShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := runWithCarrierRecovery(ctx, carrierRecoveryPolicy{}, func(context.Context) (bool, error) {
		cancel()
		return false, fmt.Errorf("client: issuer request: %w", ctx.Err())
	})
	if err != nil {
		t.Fatalf("wrapped attempt cancellation error = %v, want nil", err)
	}
}
