package failure

import (
	"errors"
	"fmt"
	"testing"
)

var errSentinel = errors.New("sentinel")

// TestNewErrorFormatsMessageAndPreservesKind covers NewError's formatted
// message construction and Kind/Err assignment.
func TestNewErrorFormatsMessageAndPreservesKind(t *testing.T) {
	e := NewError(BadAEADTag, "aead tag mismatch for suite %d", 5)
	if e.Kind != BadAEADTag {
		t.Fatalf("Kind = %v, want BadAEADTag", e.Kind)
	}
	if e.Err == nil {
		t.Fatal("Err is nil")
	}
	if got, want := e.Error(), "aead tag mismatch for suite 5"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

// TestErrorNilSafe covers both nil-safety branches of (*Error).Error: a nil
// receiver and a non-nil receiver with a nil inner error both report the
// generic "failure" string without panicking.
func TestErrorNilSafe(t *testing.T) {
	var nilReceiver *Error
	if got := nilReceiver.Error(); got != "failure" {
		t.Fatalf("nil receiver Error() = %q, want %q", got, "failure")
	}
	empty := &Error{Kind: WrongSuite}
	if got := empty.Error(); got != "failure" {
		t.Fatalf("nil-Err Error() = %q, want %q", got, "failure")
	}
}

// TestUnwrapReturnsInnerErrorAndSupportsErrorsIs covers (*Error).Unwrap's
// nil-safety and the errors.Is traversal through the wrapped chain.
func TestUnwrapReturnsInnerErrorAndSupportsErrorsIs(t *testing.T) {
	inner := fmt.Errorf("inner: %w", errSentinel)
	e := NewError(WrongToken, "outer: %w", inner)
	if !errors.Is(e, errSentinel) {
		t.Fatalf("errors.Is(e, sentinel) = false, want true (Unwrap chain)")
	}
	if got := e.Unwrap(); got == nil {
		t.Fatal("Unwrap() = nil, want the inner error")
	}

	var nilReceiver *Error
	if got := nilReceiver.Unwrap(); got != nil {
		t.Fatalf("nil receiver Unwrap() = %v, want nil", got)
	}
}
