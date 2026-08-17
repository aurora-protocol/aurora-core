package handshake

// Adversarial white-box coverage for the count-0 nil-receiver first-statement
// safety guards across the handshake package. Each guard exists so a caller that
// holds a nil driver/session/selector/signer pointer does not panic: the method
// returns a zero value or a sentinel error at its very first statement, before any
// field is dereferenced. The existing handshake tests only ever drive non-nil
// drivers built via NewClientDriver/NewRelayDriver (which never return nil) and
// non-nil sessions, so these nil-receiver guards stayed count-0 even though each is
// plainly reachable: call the method on a nil *T.
//
// These are the nil-RECEIVER analogues of the nil-context guards covered separately
// (task #126 covered ctx == nil; these cover d/s/r == nil) and do not overlap them:
// Connect/Begin check the nil receiver BEFORE the nil-context check, so a nil
// receiver fires its own guard regardless of ctx.
//
// All guards are safe to call on a nil pointer:
//   - client.go:22          Connect            d==nil        -> "nil client driver" (before :25 ctx check)
//   - client.go:404          reserveAccessHintUse  d==nil||d.hintUse==nil -> "client access hint use state is missing"
//     (the || short-circuits, so d.hintUse is never read when d==nil)
//   - client.go:417          releaseAccessHintUse  d==nil||d.hintUse==nil -> no-op return (same short-circuit)
//   - driver.go:269          EstablishedSession.Close  s==nil -> nil
//   - client_resume.go:48    ClientDriver.Begin   d==nil        -> "nil client driver" (before ctx check)
//   - relay.go:36            RelayDriver.Begin    d==nil        -> "nil relay driver" (before ctx check)
//   - production_dependencies.go:148 FixedProxyPolicySelector.accept s==nil -> zero PolicyAccept
//   - production_dependencies.go:210 ecdsaP256TranscriptSigner.PublicKey   s==nil -> zero PublicKeyRecord
//
// The test is in-package because several of these are unexported (accept,
// ecdsaP256TranscriptSigner, reserve/releaseAccessHintUse). No network, no crypto,
// no goroutine — each call returns at the first statement. context.Background() is
// passed (never a nil context literal, so no SA1012 surface) and is never reached:
// the nil-receiver guard fires first on every Connect/Begin call.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestClientDriverMethodsAreNilSafe(t *testing.T) {
	// :22 Connect, :48 Begin, :404 reserveAccessHintUse, :417 releaseAccessHintUse —
	// all on a nil *ClientDriver. Connect and Begin check d==nil before the ctx
	// check, so a non-nil context is fine and no nil-context literal is needed.
	var d *ClientDriver

	if _, err := d.Connect(context.Background(), nil); err == nil {
		t.Fatal("nil.Connect err = nil, want non-nil (:22 should return \"nil client driver\")")
	} else if !strings.Contains(err.Error(), "nil client driver") {
		t.Fatalf("nil.Connect err = %q, want it to contain \"nil client driver\" (:22)", err.Error())
	}

	if _, _, err := d.Begin(context.Background(), nil); err == nil {
		t.Fatal("nil.Begin err = nil, want non-nil (:48 should return \"nil client driver\")")
	} else if !strings.Contains(err.Error(), "nil client driver") {
		t.Fatalf("nil.Begin err = %q, want it to contain \"nil client driver\" (:48)", err.Error())
	}

	// :404 — the nil-receiver half of `d == nil || d.hintUse == nil`. The ||
	// short-circuits on d==nil, so d.hintUse is never dereferenced and the call
	// cannot panic; it returns the "missing" sentinel.
	if err := d.reserveAccessHintUse(); err == nil {
		t.Fatal("nil.reserveAccessHintUse err = nil, want non-nil (:404 should return the missing sentinel)")
	} else if !strings.Contains(err.Error(), "access hint use state is missing") {
		t.Fatalf("nil.reserveAccessHintUse err = %q, want it to contain \"access hint use state is missing\" (:404)", err.Error())
	}

	// :417 — the void analogue. Calling it on a nil receiver must be a no-op that
	// does not panic (the || short-circuits), proving the nil-safety contract for
	// the release path.
	d.releaseAccessHintUse()
}

func TestRelayDriverBeginIsNilSafe(t *testing.T) {
	// :36 — RelayDriver.Begin checks d==nil before the ctx check and returns
	// "nil relay driver" for a nil *RelayDriver. A non-nil context is passed and is
	// never reached.
	var d *RelayDriver
	if _, _, err := d.Begin(context.Background(), FirstHopBinding{}, protocol.CoverPrelude0{}, 0); err == nil {
		t.Fatal("nil.Begin err = nil, want non-nil (:36 should return \"nil relay driver\")")
	} else if !strings.Contains(err.Error(), "nil relay driver") {
		t.Fatalf("nil.Begin err = %q, want it to contain \"nil relay driver\" (:36)", err.Error())
	}
}

func TestEstablishedSessionCloseIsNilSafe(t *testing.T) {
	// :269 — EstablishedSession.Close returns nil for a nil *EstablishedSession
	// rather than dereferencing s.closeOnce/s.Application.
	var s *EstablishedSession
	if err := s.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:269 should return nil)", err)
	}
}

func TestProductionDependencyNilReceivers(t *testing.T) {
	// :148 FixedProxyPolicySelector.accept and :210 ecdsaP256TranscriptSigner.PublicKey
	// both return a zero value for a nil receiver instead of dereferencing s.public.
	// PolicyAccept contains a []uint64, so it cannot be compared with ==;
	// assert the zero value by checking the representative scalar field and the
	// slice length, which is enough to prove accept() returned the zero value
	// rather than the populated non-nil path.
	var selector *FixedProxyPolicySelector
	accept := selector.accept()
	if accept.SelectedVersion != 0 || len(accept.FallbackMethods) != 0 {
		t.Fatalf("nil.accept = %+v, want zero protocol.PolicyAccept (:148 should return the zero value)", accept)
	}

	// PublicKeyRecord contains a []byte, so it cannot be compared with ==;
	// assert the zero value by checking the scalar fields and the byte length.
	var signer *ecdsaP256TranscriptSigner
	pk := signer.PublicKey()
	if pk.SignatureScheme != 0 || pk.KeyEncoding != 0 || len(pk.PublicKey) != 0 {
		t.Fatalf("nil.PublicKey = %+v, want zero protocol.PublicKeyRecord (:210 should return the zero value)", pk)
	}
}
