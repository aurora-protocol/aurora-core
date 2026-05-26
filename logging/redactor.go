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
	if !labEnabled {
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
		"ReplayProof",
		"token_authenticator",
		"hint_secret",
		"CoverCapsule plaintext",
		"route-wrap plaintext",
	} {
		msg = strings.ReplaceAll(msg, token, "[redacted-field]")
	}
	return msg
}

func isSensitiveFieldKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
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
		"cover_capsule_plaintext",
		"capsule_plaintext",
		"route_wrap_plaintext",
		"route_prelude_plaintext":
		return true
	default:
		return false
	}
}
