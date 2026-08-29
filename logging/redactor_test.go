package logging

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestSecretStringRedactsData(t *testing.T) {
	secret := Secret{Kind: HintSecret, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	got := secret.String()
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

func TestSanitizeMessageRemovesSensitiveFieldAliasesCaseInsensitively(t *testing.T) {
	got := SanitizeMessage("admission_proof Replay Proof TOKEN AUTHENTICATOR hint-secret")
	for _, token := range []string{
		"admission_proof",
		"Replay Proof",
		"TOKEN AUTHENTICATOR",
		"hint-secret",
	} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(token)) {
			t.Fatalf("message still contained %q after sanitization: %s", token, got)
		}
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
	got := LabString(secret, true)
	if LabBuildEnabled() {
		if !strings.Contains(got, "deadbeef") {
			t.Fatalf("lab build did not expose fixture secret with runtime lab flag: %s", got)
		}
		return
	}
	if strings.Contains(got, "deadbeef") || !strings.Contains(got, "[redacted:token-authenticator:4-bytes]") {
		t.Fatalf("runtime lab flag exposed fixture secret without lab build: %s", got)
	}
}

func TestSafeFieldRedactsSensitiveRawValues(t *testing.T) {
	field := SafeField("token_authenticator", []byte{0xde, 0xad, 0xbe, 0xef}, false)
	if field.Key != "token_authenticator" || strings.Contains(field.Value, "deadbeef") || field.Value != "[redacted-field]" {
		t.Fatalf("sensitive raw field was not redacted: %+v", field)
	}
	secret := SafeField("hint_secret", Secret{Kind: HintSecret, Data: []byte{0xca, 0xfe}}, true)
	if LabBuildEnabled() {
		if !strings.Contains(secret.Value, "cafe") {
			t.Fatalf("lab build did not expose secret field with runtime lab flag: %+v", secret)
		}
	} else if strings.Contains(secret.Value, "cafe") || !strings.Contains(secret.Value, "[redacted:hint-secret:2-bytes]") {
		t.Fatalf("runtime lab flag exposed secret field without lab build: %+v", secret)
	}
	ordinary := SafeField("route_instance_id", "r1", false)
	if ordinary.Value != "r1" {
		t.Fatalf("ordinary field was unexpectedly changed: %+v", ordinary)
	}
}

func TestSafeFieldRedactsTypedProofValuesUnderOrdinaryKeys(t *testing.T) {
	for name, value := range map[string]any{
		"admission": protocol.AdmissionProof{
			TokenAuthenticator: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		"admission pointer": &protocol.AdmissionProof{
			TokenAuthenticator: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		"replay": protocol.ReplayProof{
			ClientReplayNonce: []byte{0xca, 0xfe},
		},
	} {
		t.Run(name, func(t *testing.T) {
			field := SafeField("context", value, false)
			if field.Value != "[redacted-field]" {
				t.Fatalf("typed proof value was not fully redacted: %+v", field)
			}
		})
	}
}

func TestSafeFieldRedactsStructsWithSensitiveCamelCaseFields(t *testing.T) {
	value := struct {
		TokenAuthenticator []byte
	}{
		TokenAuthenticator: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	field := SafeField("context", value, false)
	if field.Value != "[redacted-field]" {
		t.Fatalf("struct with sensitive field was not fully redacted: %+v", field)
	}
}

func TestSafeFieldRedactsSensitiveValuesInsideContainers(t *testing.T) {
	for name, value := range map[string]any{
		"slice": []protocol.AdmissionProof{{
			TokenAuthenticator: []byte{0xde, 0xad, 0xbe, 0xef},
		}},
		"map": map[string]protocol.ReplayProof{
			"proof": {ClientReplayNonce: []byte{0xca, 0xfe}},
		},
		"struct slice field": struct {
			Items []protocol.AdmissionProof
		}{
			Items: []protocol.AdmissionProof{{TokenAuthenticator: []byte{0xde, 0xad}}},
		},
		"struct pointer field": struct {
			Item *protocol.ReplayProof
		}{
			Item: &protocol.ReplayProof{ClientReplayNonce: []byte{0xca, 0xfe}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			field := SafeField("context", value, false)
			if field.Value != "[redacted-field]" {
				t.Fatalf("container with sensitive value was not fully redacted: %+v", field)
			}
		})
	}
}

func TestSafeFieldRedactsAllCapsulePlaintextTypes(t *testing.T) {
	for name, value := range map[string]any{
		"cover capsule 1": protocol.CoverCapsule1Plain{},
		"cover capsule 2": protocol.CoverCapsule2Plain{},
		"route capsule 1": protocol.RouteCapsule1Plain{},
		"route capsule 2": protocol.RouteCapsule2Plain{},
	} {
		t.Run(name, func(t *testing.T) {
			field := SafeField("context", value, false)
			if field.Value != "[redacted-field]" {
				t.Fatalf("capsule plaintext type was not fully redacted: %+v", field)
			}
		})
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

// TestSanitizeMessageHandlesFoldLengthShiftingRunes proves sanitization is
// robust against runes whose case-folded form has a different UTF-8 byte
// length. Lowercasing a copy of the message and indexing the original with the
// copy's offsets misaligns as soon as such a rune appears before a sensitive
// token: Ⱥ (U+023A) folds to ⱥ (U+2C65), one byte longer, which used to slice
// out of bounds and panic; K (U+212A) folds to k, two bytes shorter, which
// used to re-emit the tail of the token (or the whole token, given enough
// shifting runes) after the replacement.
func TestSanitizeMessageHandlesFoldLengthShiftingRunes(t *testing.T) {
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SanitizeMessage panicked on fold-lengthening rune: %v", r)
			}
		}()
		if got := SanitizeMessage("Ⱥ admission_proof"); strings.Contains(got, "admission_proof") {
			t.Fatalf("sensitive token survived sanitization: %q", got)
		}
	}()
	got := SanitizeMessage(strings.Repeat("K", 8) + " admission_proof")
	if strings.Contains(got, "admission_proof") {
		t.Fatalf("sensitive token survived sanitization: %q", got)
	}
}

// TestSafeFieldRedactsSensitiveValuesBeyondDepthGuard proves the value-driven
// sensitivity scan fails closed: a sensitive value nested inside enough
// interface containers to exceed the recursion depth guard must still be
// redacted, not formatted raw (which leaks the proof bytes as a decimal byte
// list via %v).
func TestSafeFieldRedactsSensitiveValuesBeyondDepthGuard(t *testing.T) {
	var value any = protocol.AdmissionProof{TokenAuthenticator: []byte{0xde, 0xad, 0xbe, 0xef}}
	for i := 0; i < 5; i++ {
		value = []any{value}
	}
	field := SafeField("context", value, false)
	if field.Value != "[redacted-field]" {
		t.Fatalf("deeply nested sensitive value was not redacted: %+v", field)
	}
}

// TestSafeFieldRedactsSecretsNestedInUnexportedFields proves a Secret cannot
// escape through a wrapper the fmt package prints without calling String():
// fmt only invokes Stringer on values it can Interface(), so a Secret (or a
// *Secret) held in an unexported struct field is printed as raw bytes unless
// the redactor's value scan recognizes the Secret type itself.
func TestSafeFieldRedactsSecretsNestedInUnexportedFields(t *testing.T) {
	secret := Secret{Kind: HintSecret, Data: []byte{0x61, 0x62, 0x63}}
	type byValue struct{ inner Secret }
	type byPointer struct{ inner *Secret }
	for name, value := range map[string]any{
		"unexported value":   byValue{inner: secret},
		"unexported pointer": byPointer{inner: &secret},
		"pointer to wrapper": &byValue{inner: secret},
		"slice of wrappers":  []byValue{{inner: secret}},
	} {
		field := SafeField("detail", value, false)
		if field.Value != "[redacted-field]" {
			t.Fatalf("%s: nested Secret escaped redaction: %+v", name, field)
		}
	}
}
