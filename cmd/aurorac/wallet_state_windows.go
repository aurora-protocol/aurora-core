//go:build windows

package main

import (
	"fmt"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

type provisioningWalletStateStore struct{}

func newProvisioningWalletStateStore(string) (*provisioningWalletStateStore, error) {
	return nil, fmt.Errorf("client: persistent wallet state is unavailable on this platform")
}

func transactProvisioningWalletState(*provisioningWalletStateStore, time.Time, func(*provisioningWalletState) error) error {
	return fmt.Errorf("client: persistent wallet state is unavailable on this platform")
}

func (*provisioningWalletStateStore) Reserve(provisioningWalletSource, [provisioningWalletSourceDigestBytes]byte, time.Time) (client.NativeProvisioningReservation, error) {
	return client.NativeProvisioningReservation{}, fmt.Errorf("client: persistent wallet state is unavailable on this platform")
}
