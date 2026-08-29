package logging

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"
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
	if secret, ok := value.(*Secret); ok && secret != nil {
		return Field{Key: key, Value: LabString(*secret, labEnabled)}
	}
	if isSensitiveFieldKey(key) || isSensitiveValue(value) {
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
	var out strings.Builder
	start := 0
	i := 0
	for i < len(msg) {
		if n := foldMatchLen(msg[i:], token); n > 0 {
			out.WriteString(msg[start:i])
			out.WriteString(replacement)
			i += n
			start = i
			continue
		}
		i++
	}
	if start == 0 {
		return msg
	}
	out.WriteString(msg[start:])
	return out.String()
}

// foldMatchLen returns the length in bytes of the prefix of s that matches
// token under Unicode simple case folding, or 0 if there is no match. Matching
// against s directly — rather than indexing s with offsets from a lowercased
// copy — keeps byte offsets aligned even for runes whose folded form has a
// different UTF-8 length (e.g. Ⱥ folds to the longer ⱥ, K folds to k).
func foldMatchLen(s, token string) int {
	n := 0
	for _, tr := range token {
		if n >= len(s) {
			return 0
		}
		sr, size := utf8.DecodeRuneInString(s[n:])
		if !strings.EqualFold(string(sr), string(tr)) {
			return 0
		}
		n += size
	}
	return n
}

func isSensitiveFieldKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(key))
	switch normalized {
	case "admission_proof",
		"admissionproof",
		"replay_proof",
		"replayproof",
		"token_authenticator",
		"tokenauthenticator",
		"hint_secret",
		"hintsecret",
		"bridge_locator",
		"bridgelocator",
		"private_relay_ip",
		"privaterelayip",
		"cover_origin",
		"coverorigin",
		"admission_key",
		"admissionkey",
		"bucket_user_mapping",
		"bucketusermapping",
		"raw_capsule_plaintext",
		"rawcapsuleplaintext",
		"cover_capsule_plaintext",
		"covercapsuleplaintext",
		"capsule_plaintext",
		"capsuleplaintext",
		"route_wrap_plaintext",
		"routewrapplaintext",
		"route_prelude_plaintext",
		"routepreludeplaintext":
		return true
	default:
		return false
	}
}

func isSensitiveValue(value any) bool {
	if value == nil {
		return false
	}
	return containsSensitiveValue(reflect.ValueOf(value), 0)
}

// secretType is matched by identity so a Secret reached through a container
// or an unexported field is redacted wholesale. fmt only calls String() on
// values it can Interface(), so relying on the Stringer alone would print the
// raw bytes of a Secret held in an unexported field.
var secretType = reflect.TypeOf(Secret{})

func containsSensitiveValue(v reflect.Value, depth int) bool {
	if !v.IsValid() {
		return false
	}
	if depth > 8 {
		// Fail closed: a value nested too deeply to scan within the
		// recursion bound is treated as sensitive rather than passed
		// through to the log unredacted.
		return true
	}
	t := v.Type()
	if t == secretType || isSensitiveType(t, depth) {
		return true
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return false
		}
		return containsSensitiveValue(v.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if isSensitiveFieldKey(field.Name) || isSensitiveType(field.Type, depth+1) {
				return true
			}
			if containsSensitiveValue(v.Field(i), depth+1) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if containsSensitiveValue(v.Index(i), depth+1) {
				return true
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if containsSensitiveValue(iter.Key(), depth+1) || containsSensitiveValue(iter.Value(), depth+1) {
				return true
			}
		}
	}
	return false
}

func isSensitiveType(t reflect.Type, depth int) bool {
	if t == nil || depth > 8 {
		return false
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
		if t == nil {
			return false
		}
	}
	if isSensitiveTypeName(t.Name()) {
		return true
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return isSensitiveType(t.Elem(), depth+1)
	case reflect.Map:
		return isSensitiveType(t.Key(), depth+1) || isSensitiveType(t.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if isSensitiveFieldKey(field.Name) || isSensitiveType(field.Type, depth+1) {
				return true
			}
		}
	}
	return false
}

func isSensitiveTypeName(name string) bool {
	switch name {
	case "AdmissionProof",
		"ReplayProof",
		"CoverCapsule1Plain",
		"CoverCapsule2Plain",
		"RouteCapsule1Plain",
		"RouteCapsule2Plain",
		"IssuerVerifierRequest":
		return true
	default:
		return false
	}
}
