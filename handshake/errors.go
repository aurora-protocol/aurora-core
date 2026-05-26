package handshake

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/failure"
)

type FailureError struct {
	Kind failure.Kind
	Err  error
}

func (e *FailureError) Error() string {
	if e == nil || e.Err == nil {
		return "handshake: failure"
	}
	return e.Err.Error()
}

func (e *FailureError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func failureError(kind failure.Kind, format string, args ...any) error {
	return &FailureError{Kind: kind, Err: fmt.Errorf(format, args...)}
}
