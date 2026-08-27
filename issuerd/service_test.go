package issuerd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestSignBlindRSAAuthenticatorScrubsInputAfterSigning(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte{0x41}, 128)
	digest := sha512.Sum384(input)
	signature, err := signBlindRSAAuthenticator(key, input)
	if err != nil {
		t.Fatalf("signBlindRSAAuthenticator failed: %v", err)
	}
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA384, digest[:], signature, &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}); err != nil {
		t.Fatalf("Blind RSA signature did not verify: %v", err)
	}
	assertIssuerdBytesZeroed(t, input)
}

func TestSignIssuerVerifierResponseScrubsInputAfterSigning(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte{0x42}, 48)
	expected := append([]byte(nil), input...)
	signature, err := signIssuerVerifierResponse(key, input)
	if err != nil {
		t.Fatalf("signIssuerVerifierResponse failed: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, expected, signature) {
		t.Fatal("verifier response signature did not verify")
	}
	assertIssuerdBytesZeroed(t, input)
}

func assertIssuerdBytesZeroed(t *testing.T, input []byte) {
	t.Helper()
	for index, value := range input {
		if value != 0 {
			t.Fatalf("issuer signing input byte %d = %x after signing, want zero", index, value)
		}
	}
}

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
	if _, err := service.SpendToken(proof); !errors.Is(err, ErrTokenAlreadySpent) {
		t.Fatalf("second token spend error = %v, want ErrTokenAlreadySpent", err)
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

func TestHarnessServiceAuthorityKeyIDIsCanonical(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	keys := service.AuthorityKeys()
	if len(keys) != 1 {
		t.Fatalf("authority key count = %d, want 1", len(keys))
	}
	encoded, err := protocol.Encode(keys[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys[0].AuthorityKeyID, auroratrust.AuthorityKeyID(encoded)) {
		t.Fatal("harness authority key id is not canonical")
	}
}

func TestServiceRetainsSpentTokenThroughTokenExpiry(t *testing.T) {
	cache := &recordingIssuerRetentionCache{}
	service, err := NewHarnessServiceWithOptions(200, ServiceOptions{SpentTokenCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x46, 32),
		RedemptionContextHash: fill(0x47, 48),
		ExpiryUnix:            300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SpendToken(proof); err != nil {
		t.Fatal(err)
	}
	wantDeadline, err := admission.RetentionDeadline(proof.ExpiryUnix)
	if err != nil {
		t.Fatal(err)
	}
	cache.requireSingleRetention(t, wantDeadline, 200)
}

func TestVerifierServiceRetainsSpentTokenThroughReplayEpoch(t *testing.T) {
	cache := &recordingIssuerRetentionCache{}
	service, err := NewHarnessServiceWithOptions(200, ServiceOptions{SpentTokenCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	req := verifierHTTPTestRequest(t, service, verifierService)
	response, err := service.VerifyIssuerVerifierRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Decision != registry.VerifierDecisionAccept {
		t.Fatalf("verifier decision = 0x%x, want accept", response.Decision)
	}
	wantDeadline, err := admission.RetentionDeadline(req.ReplayEpochValidUntilUnix)
	if err != nil {
		t.Fatal(err)
	}
	cache.requireSingleRetention(t, wantDeadline, 200)
}

func TestHarnessServiceRejectsReplayCacheWithoutRetention(t *testing.T) {
	service, err := NewHarnessServiceWithOptions(200, ServiceOptions{SpentTokenCache: legacyIssuerReplayCache{}})
	if err == nil {
		t.Fatal("NewHarnessServiceWithOptions accepted legacy replay cache")
	}
	if service != nil {
		t.Fatal("NewHarnessServiceWithOptions returned a service with a legacy replay cache")
	}
	if !strings.Contains(err.Error(), "retention") {
		t.Fatalf("legacy replay-cache error = %v", err)
	}
}

func TestHarnessServiceValidityFollowsWallClockNow(t *testing.T) {
	nowUnix := uint64(1_800_000_000)
	service, err := NewHarnessService(nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	metadata := service.PublishIssuerMetadata()
	if metadata.ValidFromUnix > nowUnix || metadata.ValidUntilUnix <= nowUnix+300 {
		t.Fatalf("metadata validity [%d,%d) does not cover wall-clock issue window at %d", metadata.ValidFromUnix, metadata.ValidUntilUnix, nowUnix)
	}
	if err := auroratrust.VerifyIssuerMetadataSignature(metadata, service.AuthorityKeys(), nowUnix); err != nil {
		t.Fatalf("wall-clock metadata signature did not verify: %v", err)
	}

	proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x44, 32),
		RedemptionContextHash: fill(0x45, 48),
		ExpiryUnix:            nowUnix + 300,
	})
	if err != nil {
		t.Fatalf("wall-clock issue request failed: %v", err)
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, nowUnix); err != nil {
		t.Fatalf("wall-clock proof did not verify against metadata: %v", err)
	}
}

func TestHarnessServiceValiditySupportsLongRunningPrototypeServer(t *testing.T) {
	nowUnix := uint64(1_800_000_000)
	service, err := NewHarnessService(nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	metadata := service.PublishIssuerMetadata()
	if metadata.ValidUntilUnix < nowUnix+86_400 {
		t.Fatalf("metadata validity ends at %d, want at least %d for day-long prototype server runs", metadata.ValidUntilUnix, nowUnix+86_400)
	}

	proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x46, 32),
		RedemptionContextHash: fill(0x47, 48),
		ExpiryUnix:            nowUnix + 3_600,
	})
	if err != nil {
		t.Fatalf("long-running server issue window failed: %v", err)
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, nowUnix); err != nil {
		t.Fatalf("long-running proof did not verify against metadata: %v", err)
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

type issuerRetentionCall struct {
	deadline uint64
	now      uint64
}

type recordingIssuerRetentionCache struct {
	legacyCalls    int
	retentionCalls []issuerRetentionCall
	seen           map[string]uint64
}

func (c *recordingIssuerRetentionCache) InsertIfAbsent([]byte) (bool, error) {
	c.legacyCalls++
	return true, nil
}

func (c *recordingIssuerRetentionCache) InsertIfAbsentUntil(key []byte, deadline, now uint64) (bool, error) {
	c.retentionCalls = append(c.retentionCalls, issuerRetentionCall{deadline: deadline, now: now})
	if c.seen == nil {
		c.seen = make(map[string]uint64)
	}
	if previous, ok := c.seen[string(key)]; ok && previous > now {
		return false, nil
	}
	c.seen[string(key)] = deadline
	return true, nil
}

func (c *recordingIssuerRetentionCache) Has(key []byte) bool {
	_, ok := c.seen[string(key)]
	return ok
}

func (c *recordingIssuerRetentionCache) requireSingleRetention(t *testing.T, wantDeadline, wantNow uint64) {
	t.Helper()
	if c.legacyCalls != 0 {
		t.Fatalf("used %d legacy replay-cache inserts", c.legacyCalls)
	}
	if len(c.retentionCalls) != 1 {
		t.Fatalf("retention calls = %d, want 1", len(c.retentionCalls))
	}
	if got := c.retentionCalls[0]; got.deadline != wantDeadline || got.now != wantNow {
		t.Fatalf("retention call = %+v, want deadline=%d now=%d", got, wantDeadline, wantNow)
	}
}

type legacyIssuerReplayCache struct{}

func (legacyIssuerReplayCache) InsertIfAbsent([]byte) (bool, error) { return true, nil }

func (legacyIssuerReplayCache) Has([]byte) bool { return false }
