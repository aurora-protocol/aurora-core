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

func (s Secret) String() string {
	return fmt.Sprintf("[redacted:%s:%d-bytes]", s.Kind, len(s.Data))
}

func (s Secret) GoString() string {
	return s.String()
}

func LabString(s Secret) string {
	return fmt.Sprintf("[lab:%s:%s]", s.Kind, hex.EncodeToString(s.Data))
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
