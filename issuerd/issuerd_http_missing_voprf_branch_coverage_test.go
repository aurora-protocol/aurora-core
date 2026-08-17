package issuerd

// Adversarial white-box coverage for the count-0 "missing VOPRF token key"
// guard of harnessIssuerVerifierRequest (issuerd/http.go:401). The function
// loops service.PublishIssuerMetadata().TokenKeyMappings for an entry whose
// ProofType == registry.ProofVOPRFP384SHA384 and returns "missing VOPRF token
// key" if none is present, BEFORE reading the verifier service record or
// computing the metadata hash.
//
// Coverage target (baseline measured on main; body COUNT 0 while the :401
// condition was already evaluated — the harness service always carries a VOPRF
// mapping, so tokenKeyID is set and the :401 body is never taken):
//   - http.go:401.23,403.3 0  — the missing-VOPRF-token-key error return
//
// Reuses the existing NewHarnessService(200) harness (service.go:84) and mutates
// the in-package service.metadata.TokenKeyMappings to drop the VOPRF entry,
// leaving only BlindRSA — modelling a service configured without VOPRF.
// PublishIssuerMetadata (service.go) clones s.metadata, so the mutation is
// reflected. harnessIssuerVerifierRequest is unexported, so this is an in-package
// test calling it directly. The verifierService argument is a zero-value record:
// :401 returns before it is read (:410).
//
// The :405 IssuerMetadataHash-err guard stays count-0 (deferred, like the
// makeTCPPacket/NewFlowCloseFrame-err guards in client #343/#344/#345 — only
// fires if IssuerMetadataHash itself errors, which valid metadata never does).
//
// No context.Context, no goroutines, no network. This file adds one TestXxx
// entry point and references existing in-package helpers + stdlib strings/
// testing + protocol/registry -> no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestHarnessIssuerVerifierRequestRejectsMissingVOPRFTokenKey(t *testing.T) {
	// :401 — drop the VOPRF token-key mapping from the harness service's
	// in-package metadata so the TokenKeyMappings loop yields no tokenKeyID.
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatalf("NewHarnessService: %v", err)
	}
	mappings := make([]protocol.IssuerTokenKeyRecord, 0, len(service.metadata.TokenKeyMappings))
	for _, mapping := range service.metadata.TokenKeyMappings {
		if mapping.ProofType != registry.ProofVOPRFP384SHA384 {
			mappings = append(mappings, mapping)
		}
	}
	service.metadata.TokenKeyMappings = mappings

	// verifierService is a zero-value record: :401 returns before it is read.
	_, err = harnessIssuerVerifierRequest(service, protocol.IssuerVerifierServiceRecord{}, 200)
	if err == nil || !strings.Contains(err.Error(), "missing VOPRF token key") {
		t.Fatalf("harnessIssuerVerifierRequest err = %v, want non-nil containing \"missing VOPRF token key\" (:401)", err)
	}
}
