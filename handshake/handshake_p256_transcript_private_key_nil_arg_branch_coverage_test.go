package handshake

// Adversarial white-box coverage for the count-0 nil-arg nil-safety guard in
// rawECDSAP256TranscriptPrivateKey.
//
//   - production_dependencies.go:193 rawECDSAP256TranscriptPrivateKey
//     private == nil || private.PublicKey.Curve != elliptic.P256()
//     -> "handshake: P-256 transcript private key is invalid" (the first clause
//     short-circuits before private.PublicKey.Curve, which would dereference a
//     nil *ecdsa.PrivateKey and panic; :194 returns before the :196 defer/recover).
//
// The existing handshake tests drive rawECDSAP256TranscriptPrivateKey only with a
// real P-256 private key (the success path) and with a wrong-curve key (the
// second clause), so the nil-arg clause stayed count-0 even though it is plainly
// reachable with a nil key.
//
// Proof: rawECDSAP256TranscriptPrivateKey(nil) — private == nil short-circuits
// :193 before private.PublicKey.Curve; :194 returns the unique error. The
// message is unique to :194.
//
// No context is involved, so there is no SA1012 surface. No network, no
// goroutine, no crypto operation — the guard returns before the :196
// defer/recover and before any curve arithmetic. In-package (package handshake)
// because rawECDSAP256TranscriptPrivateKey is unexported.
//
// This test file adds only a TestXxx entry point and references existing
// in-package (rawECDSAP256TranscriptPrivateKey) symbols and the standard library
// strings / testing packages, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestRawECDSAP256TranscriptPrivateKeyNilArgGuard(t *testing.T) {
	// 193: private == nil short-circuits the compound guard before
	// private.PublicKey.Curve (nil deref panic); :194 returns "P-256 transcript
	// private key is invalid". The message is unique to :194.
	_, err := rawECDSAP256TranscriptPrivateKey(nil)
	if err == nil {
		t.Fatal("rawECDSAP256TranscriptPrivateKey(nil) err = nil, want non-nil (:194)")
	}
	if !strings.Contains(err.Error(), "P-256 transcript private key is invalid") {
		t.Fatalf("nil-arg err = %q, want \"...P-256 transcript private key is invalid\" (:194)", err.Error())
	}
}
