//go:build cgo

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
)

func TestStartNativeSessionRejectsInvalidProvisioningBeforeCarrierOpen(t *testing.T) {
	_, _, err := startNativeSession(context.Background(), client.NativeProvisioning{}, time.Now())
	if err == nil {
		t.Fatal("native session accepted empty provisioning")
	}
	if !strings.Contains(err.Error(), "auroracore: native client configuration:") {
		t.Fatalf("native session did not preserve configuration failure context: %v", err)
	}
}

func TestNativePendingProofProviderFailsClosed(t *testing.T) {
	_, _, err := (nativePendingProofProvider{}).BuildProofs(
		context.Background(),
		handshake.ClientProofRequest{},
	)
	if err == nil {
		t.Fatal("native pending proof provider returned empty proofs without an error")
	}
	if !strings.Contains(err.Error(), "must be deferred") {
		t.Fatalf("native pending proof provider returned an unexpected error: %v", err)
	}
}
