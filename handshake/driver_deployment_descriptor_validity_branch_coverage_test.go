package handshake

// Adversarial white-box branch coverage for the count-0 descriptor-outside-validity
// guard in validateDriverDeployment (handshake/driver.go:305):
//
//	func validateDriverDeployment(deployment trust.VerifiedRelayDeployment, suite uint64, now time.Time) error {
//	    if !deployment.Valid() { ... }                                 // :296 (covered)
//	    ...
//	    metadata := deployment.FirstHopMetadata(selectedSuite)
//	    if nowUnix < metadata.DescriptorValidFromUnix || nowUnix >= metadata.DescriptorValidUntilUnix { // :305 <-- COUNT 0
//	        return fmt.Errorf("handshake: relay descriptor outside validity interval")
//	    }
//	    if nowUnix < metadata.EpochValidFromUnix || nowUnix >= metadata.EpochValidUntilUnix { ... } // :308
//	    if nowUnix >= metadata.ReplayEpochValidUntilUnix { ... }      // :311 (already covered)
//	    if nowUnix < metadata.TemplateValidFromUnix || nowUnix >= metadata.TemplateValidUntilUnix { ... } // :314
//	    ...
//	}
//
// validateDriverDeployment checks the validity intervals in order: descriptor (:305),
// epoch (:308), replay (:311), template (:314), body-size (:317/:319). The
// testVerifiedDeployment fixture (driver_test.go:413) centers ALL FOUR time intervals at
// the SAME window [now-60, now+3600) (descriptor ValidFrom/Until :491-492, epoch
// ValidFrom/Until :506-507, template ValidFrom/Until :441-442, replay until = verifiedAt+1h
// via testVerifiedDeployment). Because :305 is checked FIRST and its window is identical to
// the epoch (:308) and template (:314) windows, those two are DEAD-BY-DESIGN (identical-window
// domination: any `now` outside the epoch/template window is also outside the descriptor
// window, so :305 returns first). :311 (replay) is ALREADY COVERED by
// TestNewRelayDriverRejectsDeploymentWithExpiredReplayEpoch, which uses a short
// replayValidUntil (verifiedAt+1s) so a `now` inside the descriptor/epoch/template window but
// past the replay until fires :311. :317/:319 (body-size > wire.DefaultRecordBodyBytes = 1 MiB)
// are dead-by-design for this fixture (the template's prelude/response/capsule max sizes are
// 4096/8192/8192, all far below 1 MiB) and would need a freshly-signed oversized deployment to
// reach — deliberately NOT claimed here.
//
// The existing happy-path test (TestValidateDriverDeploymentAvoidsVerifiedDeploymentCopies)
// calls validateDriverDeployment(deployment, deployment.Suite(), now) with now = verifiedAt
// (inside the window) -> returns nil. So :305's err body stays count 0: no fixture passes a
// `now` OUTSIDE the descriptor window. This file fires :305 in BOTH directions (now after
// ValidUntil and now before ValidFrom) through the real, already-signed testVerifiedDeployment
// fixture, asserting the err contains "relay descriptor outside validity interval". No new
// crypto fixture is built — only the `now` argument is varied. The per-line coverage flip
// (:305 0->1) is the rigorous proof.

import (
	"strings"
	"testing"
	"time"
)

func TestValidateDriverDeploymentRejectsDescriptorOutsideValidity(t *testing.T) {
	verifiedAt := time.Now()
	deployment := testVerifiedDeployment(t, verifiedAt)

	// :305 — now AFTER the descriptor ValidUntil (now+3600): nowUnix >= ValidUntilUnix.
	// :305 is checked before epoch/replay/template, so the descriptor-outside-validity err
	// fires (the other intervals are identical and would also be exceeded, but :305 wins).
	afterExpiry := verifiedAt.Add(2 * time.Hour)
	if err := validateDriverDeployment(deployment, deployment.Suite(), afterExpiry); err == nil {
		t.Fatal("validateDriverDeployment(afterExpiry) err = nil, want descriptor-outside-validity err (:305)")
	} else if !strings.Contains(err.Error(), "relay descriptor outside validity interval") {
		t.Fatalf("validateDriverDeployment(afterExpiry) err = %v, want substring %q (:305)", err, "relay descriptor outside validity interval")
	}

	// :305 (other direction) — now BEFORE the descriptor ValidFrom (now-60):
	// nowUnix < DescriptorValidFromUnix, so the same :305 err fires.
	beforeStart := verifiedAt.Add(-2 * time.Hour)
	if err := validateDriverDeployment(deployment, deployment.Suite(), beforeStart); err == nil {
		t.Fatal("validateDriverDeployment(beforeStart) err = nil, want descriptor-outside-validity err (:305)")
	} else if !strings.Contains(err.Error(), "relay descriptor outside validity interval") {
		t.Fatalf("validateDriverDeployment(beforeStart) err = %v, want substring %q (:305)", err, "relay descriptor outside validity interval")
	}
}
