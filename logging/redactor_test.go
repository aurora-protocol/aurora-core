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

func TestSanitizeMessageRemovesRawCapsulePlaintext(t *testing.T) {
	got := SanitizeMessage("decoder rejected raw capsule plaintext before route-wrap plaintext")
	for _, token := range []string{"raw capsule plaintext", "route-wrap plaintext"} {
		if strings.Contains(got, token) {
			t.Fatalf("message still contained %q after sanitization: %s", token, got)
		}
	}
}

func TestSanitizeMessageRemovesOperationalSensitiveFieldNames(t *testing.T) {
	got := SanitizeMessage("bridge_locator private_relay_ip cover_origin admission_key bucket_user_mapping")
	for _, token := range []string{
		"bridge_locator",
		"private_relay_ip",
		"cover_origin",
		"admission_key",
		"bucket_user_mapping",
	} {
		if strings.Contains(got, token) {
			t.Fatalf("message still contained %q after sanitization: %s", token, got)
		}
	}
}

func TestLabStringRequiresExplicitLabMode(t *testing.T) {
	secret := Secret{Kind: TokenAuthenticator, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	if got := LabString(secret, false); strings.Contains(got, "deadbeef") || !strings.Contains(got, "[redacted:token-authenticator:4-bytes]") {
		t.Fatalf("secret leaked without lab mode: %s", got)
	}
	if got := LabString(secret, true); !strings.Contains(got, "deadbeef") {
		t.Fatalf("lab mode did not expose fixture secret: %s", got)
	}
}

func TestSafeFieldRedactsSensitiveRawValues(t *testing.T) {
	field := SafeField("token_authenticator", []byte{0xde, 0xad, 0xbe, 0xef}, false)
	if field.Key != "token_authenticator" || strings.Contains(field.Value, "deadbeef") || field.Value != "[redacted-field]" {
		t.Fatalf("sensitive raw field was not redacted: %+v", field)
	}
	secret := SafeField("hint_secret", Secret{Kind: HintSecret, Data: []byte{0xca, 0xfe}}, true)
	if !strings.Contains(secret.Value, "cafe") {
		t.Fatalf("lab-enabled secret field did not expose fixture bytes: %+v", secret)
	}
	ordinary := SafeField("route_instance_id", "r1", false)
	if ordinary.Value != "r1" {
		t.Fatalf("ordinary field was unexpectedly changed: %+v", ordinary)
	}
}

func TestSafeFieldRedactsPublicLogSensitiveOperationalFields(t *testing.T) {
	for _, key := range []string{
		"bridge_locator",
		"private_relay_ip",
		"cover_origin",
		"admission_key",
		"bucket_user_mapping",
	} {
		t.Run(key, func(t *testing.T) {
			field := SafeField(key, "sensitive-value", false)
			if field.Value != "[redacted-field]" {
				t.Fatalf("public-log-sensitive field was not redacted: %+v", field)
			}
		})
	}
}

func TestSafeFieldRedactsRawCapsulePlaintextAliases(t *testing.T) {
	for _, key := range []string{
		"raw_capsule_plaintext",
		"raw-capsule-plaintext",
	} {
		t.Run(key, func(t *testing.T) {
			field := SafeField(key, "capsule-body", false)
			if field.Value != "[redacted-field]" {
				t.Fatalf("raw capsule plaintext field was not redacted: %+v", field)
			}
		})
	}
}
