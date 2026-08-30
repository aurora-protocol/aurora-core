package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
)

func TestStartProvisionedSessionRejectsInvalidProvisioningBeforeCarrierOpen(t *testing.T) {
	_, _, err := startProvisionedSession(context.Background(), NativeProvisioning{}, time.Now())
	if err == nil {
		t.Fatal("provisioned session accepted empty provisioning")
	}
	if !strings.Contains(err.Error(), "client: provisioned client configuration:") {
		t.Fatalf("provisioned session did not preserve configuration failure context: %v", err)
	}
}

func TestProvisionedPendingProofProviderFailsClosed(t *testing.T) {
	_, _, err := (provisionedPendingProofProvider{}).BuildProofs(
		context.Background(),
		handshake.ClientProofRequest{},
	)
	if err == nil {
		t.Fatal("pending proof provider returned empty proofs without an error")
	}
	if !strings.Contains(err.Error(), "must be deferred") {
		t.Fatalf("pending proof provider returned an unexpected error: %v", err)
	}
}
