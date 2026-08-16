package protocol

// Adversarial coverage for the three Unsigned() accessors in
// protocol/directory.go.
//
// Unsigned() returns a copy of the record with its signature fields nilled,
// so a signer can encode-and-sign the unsigned body without mutating the
// signed instance. All three are live production code — called by
// trust/hashes.go, trust/issuer.go, trust/signed_seed.go, route/route.go,
// and handshake/keys.go to compute the bytes that get signed — but they sit
// at 0% in the protocol package because those calls happen in OTHER
// packages, and Go credits cross-package coverage to the caller, not to
// protocol. A white-box test here adds the protocol-package coverage.
//
// This file covers the residual count-0 blocks, one per accessor, each
// reached by a single call on a fixture whose signature fields are non-nil:
//
//   - DirectoryConsensus.Unsigned (86): nils AuthoritySignatures.
//   - RelayDescriptor.Unsigned (224): nils SignatureByLongtermClassical and
//     SignatureByLongtermPQ.
//   - CoverTemplate.Unsigned (609): nils TemplateFamilySignature and
//     TemplateInstanceSignature.
//
// No dead-by-design: every accessor is reachable and live. Each case asserts
// three things — the signature fields are nil in the returned copy, a
// non-signature field is preserved (proving the copy carries data, not just
// the zero value), and the original receiver is unmutated (the value-receiver
// semantic that lets a caller keep the signed instance alongside the unsigned
// body).
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). No new package-level helpers are introduced: the test
// reuses the in-package fuzzSampleDirectoryConsensus / sampleRelayDescriptor /
// sampleCoverTemplate fixtures, so there is nothing for staticcheck U1000 to
// flag. No context.Context, no goroutines, no crypto, no deprecated APIs.

import (
	"bytes"
	"testing"
)

func TestDirectoryConsensusUnsigned(t *testing.T) {
	c := fuzzSampleDirectoryConsensus()
	if len(c.AuthoritySignatures) == 0 {
		t.Fatal("fixture must carry authority signatures to prove Unsigned strips them")
	}
	epoch := c.Epoch
	sigs := c.AuthoritySignatures

	u := c.Unsigned()
	if u.AuthoritySignatures != nil {
		t.Fatalf("Unsigned AuthoritySignatures = %v, want nil", u.AuthoritySignatures)
	}
	if u.Epoch != epoch {
		t.Fatalf("Unsigned Epoch = %d, want %d (non-signature field must be preserved)", u.Epoch, epoch)
	}
	// Value receiver: the original must be untouched.
	if len(c.AuthoritySignatures) != len(sigs) {
		t.Fatalf("original AuthoritySignatures changed: len %d, want %d (Unsigned must not mutate the receiver)", len(c.AuthoritySignatures), len(sigs))
	}
}

func TestRelayDescriptorUnsigned(t *testing.T) {
	r := sampleRelayDescriptor()
	classical, pq := r.SignatureByLongtermClassical, r.SignatureByLongtermPQ
	role := r.RoleFlags
	if classical == nil || pq == nil {
		t.Fatal("fixture must carry both longterm signatures to prove Unsigned strips them")
	}

	u := r.Unsigned()
	if u.SignatureByLongtermClassical != nil || u.SignatureByLongtermPQ != nil {
		t.Fatalf("Unsigned classical=%x pq=%x, want both nil", u.SignatureByLongtermClassical, u.SignatureByLongtermPQ)
	}
	if u.RoleFlags != role {
		t.Fatalf("Unsigned RoleFlags = %d, want %d (non-signature field must be preserved)", u.RoleFlags, role)
	}
	if !bytes.Equal(r.SignatureByLongtermClassical, classical) || !bytes.Equal(r.SignatureByLongtermPQ, pq) {
		t.Fatal("original signatures changed: Unsigned must not mutate the receiver")
	}
}

func TestCoverTemplateUnsigned(t *testing.T) {
	tpl := sampleCoverTemplate()
	family, instance := tpl.TemplateFamilySignature, tpl.TemplateInstanceSignature
	version := tpl.TemplateVersion
	if family == nil || instance == nil {
		t.Fatal("fixture must carry both template signatures to prove Unsigned strips them")
	}

	u := tpl.Unsigned()
	if u.TemplateFamilySignature != nil || u.TemplateInstanceSignature != nil {
		t.Fatalf("Unsigned family=%x instance=%x, want both nil", u.TemplateFamilySignature, u.TemplateInstanceSignature)
	}
	if u.TemplateVersion != version {
		t.Fatalf("Unsigned TemplateVersion = %d, want %d (non-signature field must be preserved)", u.TemplateVersion, version)
	}
	if !bytes.Equal(tpl.TemplateFamilySignature, family) || !bytes.Equal(tpl.TemplateInstanceSignature, instance) {
		t.Fatal("original signatures changed: Unsigned must not mutate the receiver")
	}
}
