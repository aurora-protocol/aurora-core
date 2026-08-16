package trust

// Adversarial white-box coverage for the four reachable count-0 error branches in
// trust/deployment.go's clone helpers and request-class resolver: the Encode
// failure of cloneRelayDescriptor (363) and cloneCoverTemplate (379), and the two
// rejection branches of deploymentRequestClass (352/355). This file also corrects a
// misclassification in deployment_coverage_test.go, which had recorded 363/379 as
// dead-by-design on the reasoning that "Encode only fails on a varint-length
// overflow (a slice with > 2^62 elements, impossible for a real struct)". That
// analysis is incomplete: RelayDescriptor.EncodeTo and CoverTemplate.EncodeTo both
// write fixed-width fields via WriteOpaqueFixed / WritePreHash
// (WriteOpaqueFixed(b, 48)), which fail with "wire: fixed opaque length N, want M"
// whenever the field's length does not match the fixed width — and a zero-valued
// struct has nil/empty fixed fields, so Encode of protocol.RelayDescriptor{} fails
// at the very first WriteOpaqueFixed(RelayID, 32) and Encode of
// protocol.CoverTemplate{} fails at WritePreHash(OriginSPKIHash, 48). Those
// branches are therefore reachable and are covered here. (The same class of
// fixed-width length-mismatch error was the root cause of the
// clientTransportHintsHashForPolicy / Padding misclassification corrected in a
// prior pass: an Encode that looks scalar-bounded can still fail on an
// uncapped-or-zeroed fixed-width field.)
//
// The decode-side error branches that remain count-0 are dead-by-design and stay
// documented in deployment_coverage_test.go (they are NOT claimed here): 368/371
// of cloneRelayDescriptor and 384/387 of cloneCoverTemplate. Each clone is a
// faithful Encode -> NewReader -> Decode round-trip of the same wire format, so
// for any struct whose Encode succeeds, the Decode consumes exactly the encoded
// bytes (no decode error, and EOF is reached with no trailing bytes) — the decode
// and trailing-bytes branches guard against an Encode/Decode wire-format mismatch
// that no constructible struct can produce.
//
// deploymentRequestClass(t, classID, method) collects the request classes whose
// ClassID matches, requires exactly one match (already covered via the duplicate
// and not-found cases), then checks the matched class is a gateway-owned bootstrap
// slot (ClassType == RequestGatewayOwnedSlot, MayCarryPrelude, MayCarryCapsule at
// line 352) and that its AllowedMethodFamily matches the requested method and the
// method is HTTP/2 stream (line 355). The existing suite reaches
// deploymentRequestClass only with a fully-valid gateway class, so 352 and 355 are
// unreached.
//
// Targets covered (previously count-0):
//
//   - cloneRelayDescriptor:363-365 — a zero-valued RelayDescriptor fails
//     protocol.Encode at WriteOpaqueFixed(RelayID, 32) with "wire: fixed opaque
//     length 0, want 32"; cloneRelayDescriptor surfaces it.
//   - cloneCoverTemplate:379-381 — a zero-valued CoverTemplate fails protocol.Encode
//     at WritePreHash(OriginSPKIHash, 48) with "wire: fixed opaque length 0, want
//     48"; cloneCoverTemplate surfaces it.
//   - deploymentRequestClass:352-354 — a matching class whose ClassType is not
//     RequestGatewayOwnedSlot (or which drops a prelude/capsule flag) reports
//     "trust: request class is not a gateway-owned bootstrap slot".
//   - deploymentRequestClass:355-357 — a matching gateway class whose
//     AllowedMethodFamily differs from the requested method, OR whose method is
//     not MethodWebH2Stream, reports "trust: request class does not match HTTP/2
//     method".
//
// Happy-path locks (so each rejection is a meaningful contrast): a valid
// RelayDescriptor round-trips through cloneRelayDescriptor and re-encodes to the
// same bytes (byte-identity lock); a valid CoverTemplate round-trips through
// cloneCoverTemplate and re-encodes to the same bytes; a matching gateway class
// resolves successfully. The byte-identity lock (protocol.Encode(clone) ==
// protocol.Encode(original)) is preferred over reflect.DeepEqual because the
// encoder normalizes nil-vs-empty slices, so it locks the wire-level fidelity
// that actually matters without a fragile structural equality assertion.
//
// This file adds no new helpers: the clone happy paths reuse the existing
// validDeploymentDescriptor / validDeploymentTemplate fixtures (each already
// referenced by multiple tests), and the deploymentRequestClass cases build
// minimal inline CoverTemplates. So there is no staticcheck U1000 surface. No
// context.Context (no SA1012 surface), no goroutines, no cryptography, no
// network, no filesystem: cloneRelayDescriptor/cloneCoverTemplate are pure
// wire encode/decode and deploymentRequestClass is pure logic.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestCloneRelayDescriptorRejectsZeroStruct(t *testing.T) {
	// 363-365: a zero-valued RelayDescriptor fails protocol.Encode at the first
	// fixed-width write — WriteOpaqueFixed(RelayID, 32) sees a nil RelayID and
	// records "wire: fixed opaque length 0, want 32" — so cloneRelayDescriptor
	// surfaces the Encode error rather than decoding. (The decode-side 368/371
	// branches stay dead-by-design: the round-trip is faithful for any struct
	// whose Encode succeeds.)
	_, err := cloneRelayDescriptor(protocol.RelayDescriptor{})
	if err == nil {
		t.Fatal("cloneRelayDescriptor(zero) err = nil, want non-nil (Encode fixed-width failure)")
	}
	if !strings.Contains(err.Error(), "wire: fixed opaque length 0, want 32") {
		t.Fatalf("cloneRelayDescriptor(zero) err = %v, want substring \"wire: fixed opaque length 0, want 32\"", err)
	}
}

func TestCloneRelayDescriptorRoundTripsValidDescriptor(t *testing.T) {
	// Happy-path lock so the :363 rejection is a meaningful contrast: a valid
	// RelayDescriptor clones cleanly, and the clone re-encodes to the same bytes
	// as the original (byte-identity lock on the wire round-trip).
	original := validDeploymentDescriptor()
	clone, err := cloneRelayDescriptor(original)
	if err != nil {
		t.Fatalf("cloneRelayDescriptor(valid) err = %v, want nil", err)
	}
	origEnc, err := protocol.Encode(original)
	if err != nil {
		t.Fatalf("Encode(original): %v", err)
	}
	cloneEnc, err := protocol.Encode(clone)
	if err != nil {
		t.Fatalf("Encode(clone): %v", err)
	}
	if !bytes.Equal(origEnc, cloneEnc) {
		t.Fatalf("clone round-trip is not byte-identical: original and clone re-encode to different bytes")
	}
}

func TestCloneCoverTemplateRejectsZeroStruct(t *testing.T) {
	// 379-381: a zero-valued CoverTemplate fails protocol.Encode at
	// WritePreHash(OriginSPKIHash, 48) (a fixed 48-byte write) with "wire: fixed
	// opaque length 0, want 48", so cloneCoverTemplate surfaces the Encode error.
	// (The decode-side 384/387 branches stay dead-by-design.)
	_, err := cloneCoverTemplate(protocol.CoverTemplate{})
	if err == nil {
		t.Fatal("cloneCoverTemplate(zero) err = nil, want non-nil (Encode fixed-width failure)")
	}
	if !strings.Contains(err.Error(), "wire: fixed opaque length 0, want 48") {
		t.Fatalf("cloneCoverTemplate(zero) err = %v, want substring \"wire: fixed opaque length 0, want 48\"", err)
	}
}

func TestCloneCoverTemplateRoundTripsValidTemplate(t *testing.T) {
	// Happy-path lock so the :379 rejection is a meaningful contrast: a valid
	// CoverTemplate clones cleanly and re-encodes to the same bytes as the
	// original (byte-identity lock on the wire round-trip).
	original := validDeploymentTemplate(t)
	clone, err := cloneCoverTemplate(original)
	if err != nil {
		t.Fatalf("cloneCoverTemplate(valid) err = %v, want nil", err)
	}
	origEnc, err := protocol.Encode(original)
	if err != nil {
		t.Fatalf("Encode(original): %v", err)
	}
	cloneEnc, err := protocol.Encode(clone)
	if err != nil {
		t.Fatalf("Encode(clone): %v", err)
	}
	if !bytes.Equal(origEnc, cloneEnc) {
		t.Fatalf("clone round-trip is not byte-identical: original and clone re-encode to different bytes")
	}
}

func TestDeploymentRequestClassRejectsNonGatewaySlot(t *testing.T) {
	// 352-354: a class that matches ClassID but is not a gateway-owned bootstrap
	// slot (wrong ClassType) reports "not a gateway-owned bootstrap slot" before
	// the method check runs. (The MayCarryPrelude/MayCarryCapsule disjuncts are
	// covered by the same line; the ClassType case is the cleanest trigger.)
	tmpl := protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{{
		ClassID:             5,
		ClassType:           0xDEAD, // not RequestGatewayOwnedSlot
		AllowedMethodFamily: registry.MethodWebH2Stream,
		MayCarryPrelude:     true,
		MayCarryCapsule:     true,
	}}}
	_, err := deploymentRequestClass(tmpl, 5, registry.MethodWebH2Stream)
	if err == nil {
		t.Fatal("deploymentRequestClass(wrong ClassType) err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "trust: request class is not a gateway-owned bootstrap slot") {
		t.Fatalf("deploymentRequestClass(wrong ClassType) err = %v, want substring \"trust: request class is not a gateway-owned bootstrap slot\"", err)
	}
}

func TestDeploymentRequestClassRejectsMethodMismatch(t *testing.T) {
	// 355-357: a gateway-owned class whose AllowedMethodFamily differs from the
	// requested method fails the `class.AllowedMethodFamily != method` disjunct.
	t.Run("familyDoesNotMatchMethod", func(t *testing.T) {
		tmpl := protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{{
			ClassID:             5,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: 0xDEAD, // != method
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}}}
		_, err := deploymentRequestClass(tmpl, 5, registry.MethodWebH2Stream)
		if err == nil {
			t.Fatal("deploymentRequestClass(family mismatch) err = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), "trust: request class does not match HTTP/2 method") {
			t.Fatalf("deploymentRequestClass(family mismatch) err = %v, want substring \"trust: request class does not match HTTP/2 method\"", err)
		}
	})

	// 355-357: the `method != registry.MethodWebH2Stream` disjunct — the family
	// matches the (non-HTTP/2) method, but the method itself is not HTTP/2 stream,
	// so the class is rejected even though family == method.
	t.Run("methodIsNotHTTP2Stream", func(t *testing.T) {
		const nonH2 uint64 = 0x7777
		tmpl := protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{{
			ClassID:             5,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: nonH2, // == method, but neither is HTTP/2
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}}}
		_, err := deploymentRequestClass(tmpl, 5, nonH2)
		if err == nil {
			t.Fatal("deploymentRequestClass(non-HTTP/2 method) err = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), "trust: request class does not match HTTP/2 method") {
			t.Fatalf("deploymentRequestClass(non-HTTP/2 method) err = %v, want substring \"trust: request class does not match HTTP/2 method\"", err)
		}
	})
}

func TestDeploymentRequestClassAcceptsMatchingGatewaySlot(t *testing.T) {
	// Happy-path lock so the :352/:355 rejections are meaningful contrasts: a
	// single class that is a gateway-owned bootstrap slot carrying HTTP/2 stream
	// resolves with no error and returns that class.
	const classID uint64 = 5
	class := protocol.RequestClass{
		ClassID:             classID,
		ClassType:           registry.RequestGatewayOwnedSlot,
		AllowedMethodFamily: registry.MethodWebH2Stream,
		MayCarryPrelude:     true,
		MayCarryCapsule:     true,
	}
	tmpl := protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{class}}
	got, err := deploymentRequestClass(tmpl, classID, registry.MethodWebH2Stream)
	if err != nil {
		t.Fatalf("deploymentRequestClass(valid gateway) err = %v, want nil", err)
	}
	if got.ClassID != classID || got.ClassType != registry.RequestGatewayOwnedSlot ||
		got.AllowedMethodFamily != registry.MethodWebH2Stream {
		t.Fatalf("deploymentRequestClass(valid gateway) = %+v, want the matching gateway class", got)
	}
}
