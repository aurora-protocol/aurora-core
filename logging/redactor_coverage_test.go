package logging

// redactor_coverage_test.go lifts the redactor's value-driven sensitivity scan
// to near-full coverage. Three statements remain uncovered and are intentionally
// NOT contrived here:
//
//   - redactor.go:43 (LabString lab-formatting return): only reachable when the
//     lab build tag is set; redactor_lab_test.go exercises it conditionally.
//   - redactor.go:196-198 (containsSensitiveValue struct-field early return):
//     dead-by-design. The isSensitiveType(t) call at line 183 already scans every
//     struct field with the identical predicate
//     (isSensitiveFieldKey(field.Name) || isSensitiveType(field.Type, depth+1)),
//     so any struct with a sensitive field name/type returns true at 183 and
//     never enters the switch; a struct that does enter the switch has no such
//     field, so line 196 re-evaluates the same (now-false) predicate. It cannot
//     fire.
//   - redactor.go:226-228 (isSensitiveType pointer-elem nil guard): dead-by-
//     design. reflect.Type.Elem() on a Pointer kind never returns nil for a real
//     type, so the guard is purely defensive.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// TestSecretGoString covers the GoString formatter (previously 0%), which %#+v
// formatters invoke. It must redact identically to String.
func TestSecretGoString(t *testing.T) {
	secret := Secret{Kind: HintSecret, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	got := secret.GoString()
	if got != secret.String() || strings.Contains(got, "deadbeef") {
		t.Fatalf("GoString leaked secret data or diverged from String: %s", got)
	}
}

// TestSafeFieldRedactsSecretPointer covers the *Secret branch of SafeField
// (previously uncovered): a non-nil *Secret is routed through LabString, while
// a nil *Secret must NOT take that branch (the `&& secret != nil` guard) and
// instead falls through to the ordinary-value path.
func TestSafeFieldRedactsSecretPointer(t *testing.T) {
	secret := Secret{Kind: TokenAuthenticator, Data: []byte{0xca, 0xfe}}
	nonNil := SafeField("detail", &secret, false)
	if !strings.Contains(nonNil.Value, "[redacted:token-authenticator") || strings.Contains(nonNil.Value, "cafe") {
		t.Fatalf("non-nil *Secret not redacted via LabString: %+v", nonNil)
	}
	// nil *Secret: the `&& secret != nil` guard is false, so SafeField must not
	// treat it as a secret pointer; it falls through to the value path.
	var nilSecret *Secret
	fellThrough := SafeField("detail", nilSecret, false)
	if fellThrough.Value == "[redacted-field]" {
		t.Fatalf("nil *Secret incorrectly redacted as a sensitive field: %+v", fellThrough)
	}
}

// TestSanitizeMessageEmpty covers the empty-message guard of
// replaceCaseInsensitive (previously uncovered): an empty message short-circuits
// to the empty string without scanning.
func TestSanitizeMessageEmpty(t *testing.T) {
	if got := SanitizeMessage(""); got != "" {
		t.Fatalf("empty message was not passed through unchanged: %q", got)
	}
}

// TestIsSensitiveValueNil covers the nil guard of isSensitiveValue (previously
// uncovered): a nil interface value is never sensitive.
func TestIsSensitiveValueNil(t *testing.T) {
	if isSensitiveValue(nil) {
		t.Fatal("nil value reported as sensitive")
	}
	// Behaviourally, SafeField with a nil value must also avoid redaction.
	if f := SafeField("note", nil, false); f.Value == "[redacted-field]" {
		t.Fatalf("nil value redacted as a sensitive field: %+v", f)
	}
}

// TestContainsSensitiveValueGuards covers the !IsValid / depth>8 guard of
// containsSensitiveValue (previously uncovered): a zero reflect.Value and a
// too-deep recursion both short-circuit to "not sensitive".
func TestContainsSensitiveValueGuards(t *testing.T) {
	if containsSensitiveValue(reflect.Value{}, 0) {
		t.Fatal("invalid reflect.Value reported as sensitive")
	}
	if containsSensitiveValue(reflect.ValueOf("plain"), 9) {
		t.Fatal("value beyond the depth guard reported as sensitive")
	}
}

// TestIsSensitiveTypeGuards covers the nil-type / depth>8 guard of
// isSensitiveType (previously uncovered).
//
// The pointer-unwrapping loop's `if t == nil { return false }` (redactor.go
// line 226-228) is dead-by-design: reflect.Type.Elem() on a Pointer kind never
// returns nil for a real type, so the guard can never fire. It is defensive and
// not contrived here.
func TestIsSensitiveTypeGuards(t *testing.T) {
	if isSensitiveType(nil, 0) {
		t.Fatal("nil reflect.Type reported as sensitive")
	}
	if isSensitiveType(reflect.TypeOf(0), 9) {
		t.Fatal("type beyond the depth guard reported as sensitive")
	}
}

// TestSafeFieldRedactsViaEmptyInterfaceContainers covers the dynamic
// recursion branches of containsSensitiveValue (Pointer/Interface/Struct/
// Slice/Map) that the type-based isSensitiveType check cannot reach: when a
// container is typed with empty interfaces (`any`), the static type scan sees
// no sensitive element type and returns false, so the value-driven switch must
// walk the concrete values to find the nested sensitive payload.
func TestSafeFieldRedactsViaEmptyInterfaceContainers(t *testing.T) {
	// Non-nil interface holding a sensitive concrete value: slice case +
	// interface-elem recursion.
	sliceWithSensitive := []any{protocol.AdmissionProof{TokenAuthenticator: []byte{0xde, 0xad}}}
	if f := SafeField("context", sliceWithSensitive, false); f.Value != "[redacted-field]" {
		t.Fatalf("slice of any holding sensitive not redacted: %+v", f)
	}
	// Struct with an `any` field holding a sensitive value: struct-field
	// recursion + interface-elem recursion.
	structWithSensitive := struct {
		Detail any
	}{Detail: protocol.ReplayProof{ClientReplayNonce: []byte{0xca, 0xfe}}}
	if f := SafeField("context", structWithSensitive, false); f.Value != "[redacted-field]" {
		t.Fatalf("struct with any-field holding sensitive not redacted: %+v", f)
	}
	// Map with `any` values holding a sensitive value: map case (both key and
	// value recursion) + interface-elem recursion.
	mapWithSensitive := map[string]any{"entry": protocol.CoverCapsule1Plain{}}
	if f := SafeField("context", mapWithSensitive, false); f.Value != "[redacted-field]" {
		t.Fatalf("map with any-value holding sensitive not redacted: %+v", f)
	}
	// Nil interface element: the Pointer/Interface nil branch must report not
	// sensitive (no redaction).
	sliceWithNil := []any{(*string)(nil), nil}
	if f := SafeField("context", sliceWithNil, false); f.Value == "[redacted-field]" {
		t.Fatalf("nil interface/pointer elements incorrectly redacted: %+v", f)
	}
	// Non-nil pointer to a non-sensitive struct reachable only through the
	// pointer-elem recursion (its static pointer type is not sensitive).
	ptrStruct := &struct {
		Note string
	}{Note: "ok"}
	if f := SafeField("context", ptrStruct, false); f.Value == "[redacted-field]" {
		t.Fatalf("non-sensitive pointer struct incorrectly redacted: %+v", f)
	}
}