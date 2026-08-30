package client_test

import (
	"errors"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestNativeProvisioningWalletEntryPointsRequireIndependentTrust(t *testing.T) {
	encoded := []byte{0x01}
	now := time.Unix(1_700_000_000, 0)

	t.Run("parse", func(t *testing.T) {
		wallet, err := client.ParseNativeProvisioningWallet(encoded, now)
		if wallet != nil {
			wallet.Zero()
			t.Fatal("ParseNativeProvisioningWallet returned a wallet without independent trust")
		}
		if !errors.Is(err, client.ErrNativeProvisioningTrustRequired) {
			t.Fatalf("ParseNativeProvisioningWallet error = %v, want %v", err, client.ErrNativeProvisioningTrustRequired)
		}
	})

	t.Run("validate", func(t *testing.T) {
		err := client.ValidateNativeProvisioningSource(encoded, now)
		if !errors.Is(err, client.ErrNativeProvisioningTrustRequired) {
			t.Fatalf("ValidateNativeProvisioningSource error = %v, want %v", err, client.ErrNativeProvisioningTrustRequired)
		}
	})

	t.Run("reserve", func(t *testing.T) {
		reservationChecked := false
		reservation, err := client.ReserveNativeProvisioning(encoded, func([]byte) bool {
			reservationChecked = true
			return false
		}, now)
		reservation.Zero()
		if !errors.Is(err, client.ErrNativeProvisioningTrustRequired) {
			t.Fatalf("ReserveNativeProvisioning error = %v, want %v", err, client.ErrNativeProvisioningTrustRequired)
		}
		if reservationChecked {
			t.Fatal("ReserveNativeProvisioning consulted reservation state before rejecting missing trust")
		}
	})
}
