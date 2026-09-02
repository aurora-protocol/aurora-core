package client

// Coverage for the defensive-copy contract of the two inspection accessors on
// NativeProvisioningTrust (client/native_provisioning_trust.go):
//
//   - SignedSeedTrustRoots (:191-196) returns cloneNativeProvisioningAuthorityKeys
//   - DeploymentTrusts (:200-205) returns cloneNativeProvisioningDeploymentTrusts
//
// Both promise that the returned slice is a copy; mutating it must not affect
// the stored trust state observed by subsequent calls. The existing trust
// tests exercise the accessors only for their values, never for aliasing.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestNativeProvisioningTrustAccessorsReturnDefensiveCopies(t *testing.T) {
	key := nativeProvisioningECDSAKey(t)
	deployment := NativeProvisioningDeploymentTrust{
		DescriptorHash:       nativeProvisioningBytes(0x61, 48),
		CoverTemplateHash:    nativeProvisioningBytes(0x62, 48),
		TemplateAuthorityKey: nativeProvisioningPublicRecord(t, key),
	}
	value, err := NewNativeProvisioningTrust(
		[]protocol.AuthorityKeyRecord{validNativeProvisioningRoot(t, 0x60)},
		deployment,
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("SignedSeedTrustRoots", func(t *testing.T) {
		before, err := value.SignedSeedTrustRoots()
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := value.SignedSeedTrustRoots()
		if err != nil {
			t.Fatal(err)
		}
		mutated[0].AuthorityID[0] ^= 0xff
		mutated[0].PublicKey.PublicKey[0] ^= 0xff
		after, err := value.SignedSeedTrustRoots()
		if err != nil {
			t.Fatal(err)
		}
		if !nativeProvisioningAuthorityKeysEqual(before, after) {
			t.Fatal("mutating a returned root set changed subsequent SignedSeedTrustRoots results")
		}
	})

	t.Run("DeploymentTrusts", func(t *testing.T) {
		before, err := value.DeploymentTrusts()
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := value.DeploymentTrusts()
		if err != nil {
			t.Fatal(err)
		}
		mutated[0].DescriptorHash[0] ^= 0xff
		mutated[0].TemplateAuthorityKey.PublicKey[0] ^= 0xff
		after, err := value.DeploymentTrusts()
		if err != nil {
			t.Fatal(err)
		}
		if !nativeProvisioningDeploymentTrustsEqual(before, after) {
			t.Fatal("mutating a returned deployment trust changed subsequent DeploymentTrusts results")
		}
	})
}
