//go:build windows

package main

import (
	"testing"
	"time"
)

func TestProvisioningWalletStateIsUnavailableOnWindows(t *testing.T) {
	store, err := newProvisioningWalletStateStore("C:\\wallet-state.bin")
	if err == nil || store != nil {
		t.Fatalf("wallet state store = %v, %v; want unavailable", store, err)
	}
	if err := transactProvisioningWalletState(nil, time.Now().UTC(), func(*provisioningWalletState) error { return nil }); err == nil {
		t.Fatal("wallet state transaction succeeded on Windows")
	}
}
