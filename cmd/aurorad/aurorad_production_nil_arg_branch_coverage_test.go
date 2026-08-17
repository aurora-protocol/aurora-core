package main

// Adversarial white-box coverage for two count-0 nil-arg guards in the
// production server setup helpers: a nil FileInfo guard in the durable replay
// cache directory validator and a nil service/listener guard in the production
// serve entry point.
//
//   - production.go:581 validateProductionCacheDirectoryInfo
//     info == nil -> return "server: durable replay cache directory is invalid"
//     (the first clause of the compound :581 guard; short-circuits before
//     !info.IsDir(), which would dereference a nil info and panic, so a nil
//     info is safe and returns at :582).
//   - production.go:707 serveProduction
//     service == nil || listener == nil -> return "server: production service
//     and listener are required" (fires after the :704 ctx==nil guard, which a
//     real context.Background skips, and before the :710 goroutine that would
//     call service.Serve(listener)).
//
// The existing cmd/aurorad tests drive validateProductionCacheDirectoryInfo
// only on a real directory's FileInfo and drive serveProduction only with a
// constructed service + listener, so :581 and :707 stayed count-0 even though
// each is plainly reachable with a nil arg.
//
// Proof technique (nil-arg clean return):
//   - :581: validateProductionCacheDirectoryInfo(nil) — info == nil short-
//     circuits the compound guard before !info.IsDir(), so :582 returns.
//   - :707: serveProduction(context.Background(), nil, nil) — a non-nil ctx
//     skips the :704 ctx==nil guard (no SA1012: a real context.Background is
//     passed, never a nil Context literal); nil service + nil listener trip
//     :707, so :708 returns before the :710 goroutine.
//
// No nil Context is passed, so there is no SA1012 surface. No network, no
// goroutine, no file IO — :581 returns before info is dereferenced; :707
// returns before service.Serve / the goroutine. In-package (package main)
// because validateProductionCacheDirectoryInfo and serveProduction are
// unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (validateProductionCacheDirectoryInfo, serveProduction)
// symbols and the standard library context / strings / testing packages, so it
// adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
)

func TestValidateProductionCacheDirectoryInfoNilInfoGuard(t *testing.T) {
	// 581: info == nil short-circuits the compound guard before !info.IsDir()
	// (which would panic on a nil info); :582 returns. The nil info is the only
	// true clause, isolating the info == nil branch.
	err := validateProductionCacheDirectoryInfo(nil)
	if err == nil {
		t.Fatal("validateProductionCacheDirectoryInfo(nil) returned nil, want non-nil (:582)")
	}
	if !strings.Contains(err.Error(), "durable replay cache directory is invalid") {
		t.Fatalf("validateProductionCacheDirectoryInfo nil-info err = %q, want \"...directory is invalid\" (:582)", err.Error())
	}
}

func TestServeProductionNilServiceAndListenerGuard(t *testing.T) {
	// 707: a non-nil context.Background skips the :704 ctx==nil guard (no SA1012);
	// nil service + nil listener trip :707; :708 returns before the :710 goroutine.
	err := serveProduction(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("serveProduction(bg, nil, nil) returned nil, want non-nil (:708)")
	}
	if !strings.Contains(err.Error(), "production service and listener are required") {
		t.Fatalf("serveProduction nil-service err = %q, want \"...service and listener are required\" (:708)", err.Error())
	}
}
