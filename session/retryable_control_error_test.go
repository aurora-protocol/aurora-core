package session

import (
	"errors"
	"testing"
)

func TestRetryableControlErrorPreservesCauseAndClassification(t *testing.T) {
	cause := errors.New("transient key-control failure")
	err := retryableControlError{err: cause}

	if err.Error() != cause.Error() {
		t.Fatalf("retryable error message = %q, want %q", err.Error(), cause.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("retryable error did not unwrap to its cause")
	}
	if !isRetryableControlError(err) {
		t.Fatal("retryable control error was not classified as retryable")
	}
	if isRetryableControlError(cause) {
		t.Fatal("ordinary control error was classified as retryable")
	}
}
