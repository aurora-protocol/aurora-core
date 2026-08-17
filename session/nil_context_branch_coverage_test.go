package session

// Adversarial white-box coverage for the 5 count-0 first-statement guards in
// the session package: four nil-CONTEXT rejection guards on Application /
// systemEntropySource methods, and one nil-RECEIVER safety guard on
// TryNextPacket. Each guard fires at the method's very first statement, before
// any field is dereferenced (a.mu, a.queue, a.terminalError, s.requests) or any
// context method is called (ctx.Err). The existing session tests only ever drive
// a live Application/entropy source with a non-nil context, so these guards
// stayed count-0 even though each is plainly reachable.
//
// The four ctx==nil guards require passing a nil context, which staticcheck
// flags as SA1012 (nil Context). This is the established codebase convention
// (see handshake/production_dependencies_nil_context_branch_coverage_test.go and
// 10+ other usages): each nil-context call is preceded immediately by
//
//	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
//
// so staticcheck suppresses the warning for that one intentional call. Local
// staticcheck is broken (go1.26 module), so SA1012 is verified only in CI's
// production-evidence staticcheck@v0.7.0; the directive is CI-proven across the
// repo. The nil-receiver guard (:259 TryNextPacket) passes no context at all, so
// it has no SA1012 surface.
//
//   - application.go:221 Application.NextPacket(ctx)            ctx == nil -> nil, "session: nil context"
//   - application.go:350 Application.handlePacket(ctx,...)     ctx == nil -> nil, "session: nil context"
//   - application.go:470 Application.queueBlock(ctx,...)       ctx == nil -> "session: nil context"
//   - entropy.go:37     systemEntropySource.ReadContext(ctx,p) ctx == nil -> "session: nil entropy context"
//   - application.go:259 Application.TryNextPacket()            a == nil  -> nil, ErrClosed  (nil RECEIVER, no SA1012)
//
// The four ctx==nil tests use a non-nil &Application{} / systemEntropySource{}
// receiver (clearly about the context, not the receiver): the guard fires first,
// so the receiver's zero-valued fields are never read. The TryNextPacket test
// uses a nil *Application to exercise the nil-receiver half. The test is in-package
// because handlePacket, queueBlock, and systemEntropySource are unexported.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestApplicationRejectsNilContext(t *testing.T) {
	// 221/350/470: a non-nil Application rejects a nil context at the first
	// statement of NextPacket / handlePacket / queueBlock, before any field is
	// read or ctx.Err is called. A zero-valued Application is safe because the
	// guard fires first.
	a := &Application{}

	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := a.NextPacket(nil)
	if err == nil {
		t.Fatal("NextPacket(nil ctx) err = nil, want non-nil (:221 should reject)")
	}
	if !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("NextPacket(nil ctx) err = %v, want substring \"nil context\" (:221)", err)
	}

	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err = a.handlePacket(nil, time.Time{}, nil, false)
	if err == nil {
		t.Fatal("handlePacket(nil ctx) err = nil, want non-nil (:350 should reject)")
	}
	if !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("handlePacket(nil ctx) err = %v, want substring \"nil context\" (:350)", err)
	}

	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	err = a.queueBlock(nil, protocol.FrameBlock{}, false, false)
	if err == nil {
		t.Fatal("queueBlock(nil ctx) err = nil, want non-nil (:470 should reject)")
	}
	if !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("queueBlock(nil ctx) err = %v, want substring \"nil context\" (:470)", err)
	}
}

func TestSystemEntropySourceReadContextRejectsNilContext(t *testing.T) {
	// 37: ReadContext rejects a nil context at its first statement, before the
	// requests channel is touched. systemEntropySource is unexported, so this is
	// in-package; a zero-valued receiver is safe because the guard fires first.
	var s systemEntropySource
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	err := s.ReadContext(nil, nil)
	if err == nil {
		t.Fatal("ReadContext(nil ctx) err = nil, want non-nil (:37 should reject)")
	}
	if !strings.Contains(err.Error(), "nil entropy context") {
		t.Fatalf("ReadContext(nil ctx) err = %v, want substring \"nil entropy context\" (:37)", err)
	}
}

func TestApplicationTryNextPacketIsNilSafe(t *testing.T) {
	// 259: a nil *Application.TryNextPacket returns nil, ErrClosed at its first
	// statement rather than dereferencing a.mu / a.queue. This is a nil-RECEIVER
	// guard (no context is passed), so there is no SA1012 surface.
	var a *Application
	pkt, err := a.TryNextPacket()
	if pkt != nil {
		t.Fatalf("nil.TryNextPacket pkt = %v, want nil (:259 should return nil)", pkt)
	}
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("nil.TryNextPacket err = %v, want errors.Is ErrClosed (:259 should return ErrClosed)", err)
	}
}
