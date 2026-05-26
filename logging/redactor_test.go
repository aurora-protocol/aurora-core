package logging

import (
	"fmt"
	"strings"
	"testing"
)

func TestSecretStringRedactsData(t *testing.T) {
	secret := Secret{Kind: HintSecret, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	got := fmt.Sprintf("%s", secret)
	if strings.Contains(got, "deadbeef") || !strings.Contains(got, "[redacted:hint-secret:4-bytes]") {
		t.Fatalf("unexpected redaction string: %s", got)
	}
}

func TestSanitizeMessageRemovesSensitiveFieldNames(t *testing.T) {
	got := SanitizeMessage("AdmissionProof failed with token_authenticator")
	if strings.Contains(got, "AdmissionProof") || strings.Contains(got, "token_authenticator") {
		t.Fatalf("message was not sanitized: %s", got)
	}
}
