//go:build cgo

package main

import (
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

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
