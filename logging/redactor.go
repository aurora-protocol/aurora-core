package logging

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type SensitiveKind string

const (
	AdmissionProofPlaintext SensitiveKind = "admission-proof"
	ReplayProofPlaintext    SensitiveKind = "replay-proof"
	TokenAuthenticator      SensitiveKind = "token-authenticator"
	HintSecret              SensitiveKind = "hint-secret"
	CapsulePlaintext        SensitiveKind = "capsule-plaintext"
	RouteWrapPlaintext      SensitiveKind = "route-wrap-plaintext"
)

type Secret struct {
	Kind SensitiveKind
	Data []byte
}

type Field struct {
	Key   string
	Value string
}

func (s Secret) String() string {
	return fmt.Sprintf("[redacted:%s:%d-bytes]", s.Kind, len(s.Data))
}

func (s Secret) GoString() string {
	return s.String()
}

func LabString(s Secret, labEnabled bool) string {
	if !labEnabled || !LabBuildEnabled() {
		return s.String()
	}
	return fmt.Sprintf("[lab:%s:%s]", s.Kind, hex.EncodeToString(s.Data))
}

func SafeField(key string, value any, labEnabled bool) Field {
	if secret, ok := value.(Secret); ok {
		return Field{Key: key, Value: LabString(secret, labEnabled)}
	}
	if isSensitiveFieldKey(key) {
		return Field{Key: key, Value: "[redacted-field]"}
	}
	return Field{Key: key, Value: SanitizeMessage(fmt.Sprintf("%v", value))}
}

func SanitizeMessage(msg string) string {
	for _, token := range []string{
		"AdmissionProof",
		"admission_proof",
		"admission-proof",
		"admission proof",
		"ReplayProof",
		"replay_proof",
		"replay-proof",
		"replay proof",
		"token_authenticator",
		"token-authenticator",
		"token authenticator",
		"hint_secret",
		"hint-secret",
		"hint secret",
		"bridge_locator",
		"bridge-locator",
		"bridge locator",
		"private_relay_ip",
		"private-relay-ip",
		"private relay ip",
		"cover_origin",
		"cover-origin",
		"cover origin",
		"admission_key",
		"admission-key",
		"admission key",
		"bucket_user_mapping",
		"bucket-user-mapping",
		"bucket user mapping",
		"CoverCapsule plaintext",
		"cover-capsule plaintext",
		"cover_capsule_plaintext",
		"cover-capsule-plaintext",
		"raw capsule plaintext",
		"raw_capsule_plaintext",
		"raw-capsule-plaintext",
		"route-wrap plaintext",
		"route_wrap_plaintext",
		"route wrap plaintext",
		"route_prelude_plaintext",
		"route-prelude-plaintext",
		"route prelude plaintext",
	} {
		msg = replaceCaseInsensitive(msg, token, "[redacted-field]")
	}
	return msg
}

func replaceCaseInsensitive(msg, token, replacement string) string {
	if token == "" || msg == "" {
		return msg
	}
	lowerMsg := strings.ToLower(msg)
	lowerToken := strings.ToLower(token)
	start := 0
	var out strings.Builder
	for {
		idx := strings.Index(lowerMsg[start:], lowerToken)
		if idx < 0 {
			break
		}
		idx += start
		out.WriteString(msg[start:idx])
		out.WriteString(replacement)
		start = idx + len(token)
	}
	if start == 0 {
		return msg
	}
	out.WriteString(msg[start:])
	return out.String()
}

func isSensitiveFieldKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(key))
	switch normalized {
	case "admission_proof",
		"replay_proof",
		"token_authenticator",
		"hint_secret",
		"bridge_locator",
		"private_relay_ip",
		"cover_origin",
		"admission_key",
		"bucket_user_mapping",
		"raw_capsule_plaintext",
		"cover_capsule_plaintext",
		"capsule_plaintext",
		"route_wrap_plaintext",
		"route_prelude_plaintext":
		return true
	default:
		return false
	}
}
