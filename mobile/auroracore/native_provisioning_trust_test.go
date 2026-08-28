//go:build cgo

package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestNativeProvisioningTrustConfigureRejectsDifferentValue(t *testing.T) {
	fixtureA := newNativeSessionFixture(t, time.Now().UTC())
	defer fixtureA.Close(t)
	fixtureB := newNativeSessionFixture(t, time.Now().UTC())
	defer fixtureB.Close(t)
	encodedA, err := client.EncodeNativeProvisioningTrust(fixtureA.ProvisioningTrust(t))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encodedA)
	encodedB, err := client.EncodeNativeProvisioningTrust(fixtureB.ProvisioningTrust(t))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encodedB)

	config := nativeProvisioningTrustConfig{}
	if err := config.configure(encodedA); err != nil {
		t.Fatalf("initial configure: %v", err)
	}
	if err := config.configure(encodedA); err != nil {
		t.Fatalf("idempotent configure with identical trust: %v", err)
	}
	if err := config.configure(encodedB); err == nil {
		t.Fatal("configure with a different trust succeeded, want already-configured rejection")
	}
	loaded, err := config.load()
	if err != nil {
		t.Fatalf("load after rejected reconfiguration: %v", err)
	}
	canonical, err := client.EncodeNativeProvisioningTrust(loaded)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(canonical)
	if !bytes.Equal(canonical, encodedA) {
		t.Fatal("rejected reconfiguration replaced the configured trust")
	}
}

func TestNativeSessionDispatchRequiresConfiguredProvisioningTrust(t *testing.T) {
	fixture := newNativeSessionFixture(t, time.Now().UTC())
	defer fixture.Close(t)
	nativeProvisioningTrust.mu.Lock()
	previousEncoded := append([]byte(nil), nativeProvisioningTrust.encoded...)
	previousValue := nativeProvisioningTrust.value
	nativeProvisioningTrust.encoded = nil
	nativeProvisioningTrust.value = client.NativeProvisioningTrust{}
	nativeProvisioningTrust.mu.Unlock()
	t.Cleanup(func() {
		nativeProvisioningTrust.mu.Lock()
		nativeProvisioningTrust.encoded = previousEncoded
		nativeProvisioningTrust.value = previousValue
		nativeProvisioningTrust.mu.Unlock()
	})
	encoded, err := client.EncodeNativeProvisioning(fixture.Provisioning(t))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)
	if status, payload := dispatch(opBeginNativeSessionJSON, encoded, 0); status != statusError || len(payload) != 0 {
		t.Fatalf("native session began without configured trust: status=%d payload=%x", status, payload)
	}
}
