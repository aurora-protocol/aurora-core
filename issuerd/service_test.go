package issuerd

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestServiceReadinessHarnessCoversIssuerDuties(t *testing.T) {
	report, err := RunServiceReadinessHarness(200)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("issuer service readiness failed: %+v", report)
	}
	for name, passed := range map[string]bool{
		"metadata_published":        report.MetadataPublished,
		"blind_rsa_issue_verify":    report.BlindRSAIssuedAndVerified,
		"voprf_verifier":            report.VOPRFVerifierService,
		"voprf_fail_closed":         report.VOPRFVerifierFailClosed,
		"atomic_spent_store":        report.AtomicSpentTokenStore,
		"sensitive_logs_redacted":   report.SensitiveLogsRedacted,
		"metadata_hash_bound_token": report.MetadataHashBoundToken,
	} {
		if !passed {
			t.Fatalf("%s control was not covered: %+v", name, report)
		}
	}
	if len(report.Findings) != 0 {
		t.Fatalf("issuer service readiness reported findings: %+v", report.Findings)
	}
}

func TestServicePublishesIssuesVerifiesSpendsAndRedacts(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	metadata := service.PublishIssuerMetadata()
	if err := auroratrust.VerifyIssuerMetadataSignature(metadata, service.AuthorityKeys(), 200); err != nil {
		t.Fatalf("published metadata signature did not verify: %v", err)
	}

	proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x44, 32),
		RedemptionContextHash: fill(0x45, 48),
		ExpiryUnix:            300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, 200); err != nil {
		t.Fatalf("issued Blind RSA proof did not verify against metadata: %v", err)
	}

	spentKey, err := service.SpendToken(proof)
	if err != nil {
		t.Fatalf("first token spend failed: %v", err)
	}
	if len(spentKey) != 48 {
		t.Fatalf("spent key length = %d, want 48", len(spentKey))
	}
	if _, err := service.SpendToken(proof); err == nil {
		t.Fatalf("second token spend was accepted")
	}

	request := VOPRFVerifierRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       fill(0x81, 16),
		RequestAuthPolicyID: 9,
	}
	if err := service.VerifyVOPRFRequest(request); err != nil {
		t.Fatalf("available VOPRF verifier rejected request: %v", err)
	}
	service.SetVOPRFVerifierAvailable(false)
	if err := service.VerifyVOPRFRequest(request); err == nil {
		t.Fatalf("VOPRF verifier outage did not fail closed")
	}

	logLine := service.RedactedOperationalLog(LogInput{
		AdmissionProof:   proof,
		HintSecret:       []byte("hint-secret-material-that-must-not-log"),
		CapsulePlaintext: []byte("capsule-plaintext-that-must-not-log"),
	})
	for _, forbidden := range []string{
		hex.EncodeToString(proof.TokenPublicMetadata),
		hex.EncodeToString(proof.TokenAuthenticator),
		"hint-secret-material-that-must-not-log",
		"capsule-plaintext-that-must-not-log",
	} {
		if strings.Contains(logLine, forbidden) {
			t.Fatalf("operational log leaked sensitive material %q: %s", forbidden, logLine)
		}
	}
	for _, want := range []string{
		"[redacted:admission-proof:",
		"[redacted:token-authenticator:",
		"[redacted:hint-secret:",
		"[redacted:capsule-plaintext:",
	} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("operational log missing redaction marker %q: %s", want, logLine)
		}
	}
}

func TestIssueBlindRSA2048RejectsIncompleteServiceWithoutPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("IssueBlindRSA2048 panicked for incomplete service: %v", recovered)
		}
	}()
	var service Service
	if _, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x44, 32),
		RedemptionContextHash: fill(0x45, 48),
		ExpiryUnix:            300,
	}); err == nil {
		t.Fatalf("incomplete service issued a token")
	}
}

func fill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
