package session

// Adversarial white-box coverage for two count-0 pure input-validation
// guards in session/ that sit AFTER the ctx==nil check but BEFORE any
// state/crypto:
//
//   - key_update.go:44  InitiateKeyUpdate  if reason > wire.MaxVarint
//        -> "session: key update reason exceeds canonical range"
//   - application.go:359 handlePacket      if len(encoded) == 0
//        -> "session: empty packet"
//
// Both guards are the NON-ctx input-validation siblings of the (already
// EXHAUSTED) ctx==nil vein. They are reached with a zero-value Application
// and a non-nil context.Background() (no SA1012 surface — no nil Context
// literal is passed). Each guard fires BEFORE any *Application field is
// dereferenced or any crypto/state is touched, so the tests are pure: no
// goroutine, no network, no cgo, no crypto, no build tag, no t.Skip.
//
// Baseline (clean tree, session_base.out): the :44 condition is evaluated
// 39x and the :359 condition 60x, but both bodies are COUNT 0 (no existing
// test drives an out-of-range reason or an empty encoded packet). The
// per-line coverage flip (0 -> 1+ per guard) is the rigorous proof.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/wire"
)

func TestInitiateKeyUpdateAndHandlePacketRejectInvalidInput(t *testing.T) {
	// A zero-value Application is safe for both guards:
	//   - InitiateKeyUpdate:44 fires before any a.* access (first deref is
	//     a.writeUpdateMu.Lock() at :50, after :44 returns).
	//   - handlePacket:353 calls a.terminalError() which does a.mu.Lock()
	//     (zero-value sync.Mutex is usable) and returns a.terminal (nil on a
	//     zero-value Application), so :353 passes and :359 fires.
	app := &Application{}

	cases := []struct {
		name    string
		call    func() error
		wantSub string
	}{
		{
			// key_update.go:44 — wire.MaxVarint is uint64(1<<62 - 1), so
			// MaxVarint+1 is a valid uint64 that exceeds it (no overflow).
			// :41 (ctx==nil) passes (context.Background() is non-nil); :44
			// fires before :47 (ctx.Err()) and before any a.* deref.
			name:    "key update reason exceeds canonical range",
			call:    func() error { return app.InitiateKeyUpdate(context.Background(), wire.MaxVarint+1) },
			wantSub: "session: key update reason exceeds canonical range",
		},
		{
			// application.go:359 — HandlePacket (exported wrapper at :338)
			// delegates to handlePacket(ctx, now, encoded, false). :350
			// (ctx==nil) passes; :353 terminalError() returns nil (zero-value
			// Application); :356 ctx.Err() returns nil; :359 fires on the
			// empty encoded slice before `now` is used.
			name:    "handle packet empty encoded",
			call:    func() error { _, err := app.HandlePacket(context.Background(), time.Now(), nil); return err },
			wantSub: "session: empty packet",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.call()
			if err == nil || !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("%s: err = %v, want non-nil containing %q", c.name, err, c.wantSub)
			}
		})
	}
}
