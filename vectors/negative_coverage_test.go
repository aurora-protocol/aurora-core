package vectors

// Adversarial coverage for FormatNegativeVectorReport (negative.go:219), the
// pure strings.Builder formatter. In production it is called only from
// cmd/auroractl's check command (main.go:432/441), never from a vectors-package
// test, so the package's own coverage never reaches it (0.0%). This test drives
// it directly with a crafted report that populates both the Cases loop and the
// Findings loop — the existing TestGenerateNegativeVectorReportCoversP2RequiredFailures
// produces a passing report with empty Findings, so the findings loop body
// stays uncovered.
//
// Deferred (need fault-injectable crypto/issuerd, out of scope for this
// pure-formatter pillar):
//   - GenerateNegativeVectorReport:32/35/38/41/44/47 (the six
//     `return NegativeVectorReport{}, err` propagation bodies): each fires only
//     when an add*Case helper returns a non-nil error, which requires a real
//     signature/issue/AEAD/replay failure. The happy path (every case rejects
//     and every helper returns nil) is covered by
//     TestGenerateNegativeVectorReportCoversP2RequiredFailures.

import (
	"strings"
	"testing"
)

func TestFormatNegativeVectorReportEmitsSummaryCasesAndFindings(t *testing.T) {
	report := NegativeVectorReport{
		Passed: false,
		Cases: []NegativeVectorCase{
			{Name: "rejected_case", Rejected: true, Error: "verify failed", Evidence: "scheme=ecdsa_p256_sha384_der"},
			{Name: "accepted_case", Rejected: false, Error: "", Evidence: "scheme=aes_256_gcm"},
		},
		Findings: []string{"accepted_case negative vector was accepted"},
	}
	out := FormatNegativeVectorReport(report)
	for _, want := range []string{
		"negative_vectors_check passed=false cases=2 failures=1",
		`negative_vector rejected_case rejected=true error="verify failed" evidence=scheme=ecdsa_p256_sha384_der`,
		`negative_vector accepted_case rejected=false error="" evidence=scheme=aes_256_gcm`,
		"negative_vector_finding accepted_case negative vector was accepted",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatNegativeVectorReport missing %q:\n%s", want, out)
		}
	}
}

func TestFormatNegativeVectorReportEmptyReport(t *testing.T) {
	// A zero-value report has Passed=false and nil Cases/Findings, so only the
	// summary line is emitted (neither loop body executes).
	out := FormatNegativeVectorReport(NegativeVectorReport{})
	const want = "negative_vectors_check passed=false cases=0 failures=0\n"
	if out != want {
		t.Fatalf("FormatNegativeVectorReport(empty) = %q, want %q", out, want)
	}
}