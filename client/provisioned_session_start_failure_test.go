package client

// Failure-branch coverage for startProvisionedSession (provisioned_session.go:318)
// beyond the empty-provisioning rejection already in
// provisioned_session_start_test.go:
//
//   - Carrier-opener failure: the default valid provisioning bundle names the
//     relay "relay.example", and the transport layer rejects any visible
//     carrier target containing the "relay" protocol marker, so the opener
//     build fails after the client configuration succeeds.
//   - Handshake failure: with a bundle pinned to a live loopback TLS server
//     the carrier opener builds, and driver.Begin rejects the cancelled
//     context before any network I/O.
//
// The intermediate handshake.NewClientDriver error branch is NOT reachable
// from here: ClientDriverConfig already runs NewClientDriver on the identical
// config and returns an error when it rejects it, so no input can pass the
// first stage and fail the second without fault injection.

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/handshake"
)

func TestStartProvisionedSessionFailsWhenCarrierOpenerCannotBeBuilt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	provisioning := validNativeProvisioning(t, now)
	_, _, err := startProvisionedSession(context.Background(), provisioning, now)
	if err == nil {
		t.Fatal("provisioned session start with an unbuildable carrier opener succeeded")
	}
	if !strings.Contains(err.Error(), "client: provisioned carrier opener:") {
		t.Fatalf("provisioned session start error = %v, want carrier opener failure", err)
	}
}

func TestStartProvisionedSessionFailsHandshakeWhenContextCancelled(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test server did not provide a certificate")
	}
	provisioning := validNativeProvisioningWithOriginSPKI(t, now, auroracrypto.PreHash(certificate.RawSubjectPublicKeyInfo))
	configureNativeProvisioningRelay(t, &provisioning, server.URL+"/assets/upload/42", certificate.Raw)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deferred, request, err := startProvisionedSession(ctx, provisioning, now)
	if err == nil {
		t.Fatal("provisioned session start with a cancelled context succeeded")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("provisioned session start error = %v, want context canceled", err)
	}
	// Begin returns a typed nil *handshake.ClientHandshake on this path, which
	// a non-nil interface comparison would misread as a live handshake.
	if deferred != (*handshake.ClientHandshake)(nil) {
		t.Fatalf("cancelled provisioned session start returned a deferred handshake: %#v", deferred)
	}
	if len(request.AdmissionContextHash) != 0 {
		t.Fatal("cancelled provisioned session start returned a proof request")
	}
}
