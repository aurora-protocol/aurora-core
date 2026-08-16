package platform

// Adversarial coverage for VerifyAdapterBlueprints (blueprint.go:51), the
// only uncovered function in blueprint.go. The existing
// TestAdapterBlueprintsCoverP8Platforms happy path plus the
// local_proxy_fallback / dns_forwarder / core_boundary mutation tests already
// reach the per-blueprint report construction and three of the five
// reportFailure branches; the input-validation error returns, the
// packet_mode and no_crypto_state failure branches, and the missing-required
// kind loop stay uncovered. Each subtest below targets exactly one uncovered
// statement-group (confirmed via coverprofile hit-count 0).
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).

import (
	"strings"
	"testing"
)

func TestVerifyAdapterBlueprintsRejectsMalformedInput(t *testing.T) {
	t.Run("empty blueprint set", func(t *testing.T) {
		_, err := VerifyAdapterBlueprints(nil)
		if err == nil || !strings.Contains(err.Error(), "no adapter blueprints") {
			t.Fatalf("err = %v, want \"no adapter blueprints\"", err)
		}
	})
	t.Run("empty kind", func(t *testing.T) {
		blueprints := AdapterBlueprints()
		blueprints[0].Kind = ""
		_, err := VerifyAdapterBlueprints(blueprints)
		if err == nil || !strings.Contains(err.Error(), "adapter blueprint kind is empty") {
			t.Fatalf("err = %v, want \"adapter blueprint kind is empty\"", err)
		}
	})
	t.Run("duplicate kind", func(t *testing.T) {
		blueprints := append(AdapterBlueprints(), AdapterBlueprints()[0])
		_, err := VerifyAdapterBlueprints(blueprints)
		if err == nil || !strings.Contains(err.Error(), "duplicate adapter blueprint for linux") {
			t.Fatalf("err = %v, want \"duplicate adapter blueprint for linux\"", err)
		}
	})
}

func TestVerifyAdapterBlueprintsReportsPerBlueprintFailures(t *testing.T) {
	t.Run("packet mode mismatch", func(t *testing.T) {
		blueprints := AdapterBlueprints()
		blueprints[0].PacketMode = "wrong-mode"
		report, err := VerifyAdapterBlueprints(blueprints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.Passed {
			t.Fatal("VerifyAdapterBlueprints accepted a packet-mode mismatch")
		}
		if !hasAdapterFailure(report, KindLinux, "packet_mode") {
			t.Fatalf("failures = %v, want packet_mode for linux", report.Failures)
		}
	})
	t.Run("crypto state present", func(t *testing.T) {
		blueprints := AdapterBlueprints()
		blueprints[0].ContainsCryptoState = true
		report, err := VerifyAdapterBlueprints(blueprints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.Passed {
			t.Fatal("VerifyAdapterBlueprints accepted a crypto-state-bearing adapter")
		}
		if !hasAdapterFailure(report, KindLinux, "no_crypto_state") {
			t.Fatalf("failures = %v, want no_crypto_state for linux", report.Failures)
		}
	})
}

func TestVerifyAdapterBlueprintsReportsMissingRequiredKind(t *testing.T) {
	// Drop the OpenWrt blueprint; the remaining six are valid, so the only
	// finding is the missing-required-kind loop (line 94-97).
	all := AdapterBlueprints()
	blueprints := make([]AdapterBlueprint, 0, len(all)-1)
	for _, b := range all {
		if b.Kind == KindOpenWrt {
			continue
		}
		blueprints = append(blueprints, b)
	}
	report, err := VerifyAdapterBlueprints(blueprints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatal("VerifyAdapterBlueprints accepted a matrix missing a required kind")
	}
	if len(report.Failures) != 1 {
		t.Fatalf("failures = %d, want exactly 1 (the missing kind): %+v", len(report.Failures), report.Failures)
	}
	if !hasAdapterFailure(report, KindOpenWrt, "missing") {
		t.Fatalf("failures = %v, want missing for openwrt", report.Failures)
	}
}
