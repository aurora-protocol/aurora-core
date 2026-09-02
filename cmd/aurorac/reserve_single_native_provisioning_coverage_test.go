package main

// Coverage for cmd/aurorac main.go:814 reserveSingleNativeProvisioning, the
// one-time provisioning reservation path behind `aurorac proxy
// --provisioning`. The existing end-to-end lab test drives only the
// --provisioning-wallet path, so the single-file reservation flow (restricted
// file read, trusted parse, single-entry wallet re-encode/re-parse, durable
// state reservation) stayed at 0%.
//
// The test mints a one-entry lab deployment with internal/labfixture, loads
// the minted signed-seed trust through the production loader, and rewrites the
// minted wallet's entry as a standalone provisioning bundle via
// client.EncodeNativeProvisioning. Files written by labfixture are already
// owner-only (0600); the hand-written bundle is written 0600 to satisfy the
// restricted-file checks. The second call against the same state file proves
// the reservation is durable: the same entry cannot be reserved twice.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/internal/labfixture"
)

func TestReserveSingleNativeProvisioningReservesMintedEntryOnce(t *testing.T) {
	now := time.Now().UTC()
	material, err := labfixture.Mint(labfixture.MintOptions{
		RelayHost:  "127.0.0.1",
		RelayPort:  reserveLabFreePort(t),
		IssuerPort: reserveLabFreePort(t),
		Entries:    1,
		Now:        now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}

	trust, err := loadNativeProvisioningTrust(filepath.Join(dir, labfixture.FileNativeProvisioningTrust))
	if err != nil {
		t.Fatal(err)
	}
	walletEncoded, err := os.ReadFile(filepath.Join(dir, labfixture.FileWallet))
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := client.ReserveNativeProvisioningWithTrust(walletEncoded, trust, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := client.EncodeNativeProvisioning(reservation.Provisioning)
	reservation.Zero()
	if err != nil {
		t.Fatal(err)
	}
	provisioningPath := filepath.Join(dir, "single-provisioning.bin")
	if err := os.WriteFile(provisioningPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(dir, "wallet-state.bin")
	reserved, err := reserveSingleNativeProvisioning(provisioningPath, statePath, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Zero()
	if len(reserved.SpentHintKey) == 0 || reserved.Provisioning.RelayURL == "" {
		t.Fatalf("reservation is incomplete: spent=%x url=%q", reserved.SpentHintKey, reserved.Provisioning.RelayURL)
	}

	// The state file now records the spent hint key, so a second reservation
	// of the same bundle must fail instead of double-spending it.
	if _, err := reserveSingleNativeProvisioning(provisioningPath, statePath, trust, now); !errors.Is(err, client.ErrNoUsableNativeProvisioning) {
		t.Fatalf("second reservation err = %v, want client.ErrNoUsableNativeProvisioning", err)
	}
}
