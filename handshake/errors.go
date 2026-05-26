package handshake

import "github.com/aurora-protocol/aurora-core/failure"

type FailureError = failure.Error

func failureError(kind failure.Kind, format string, args ...any) error {
	return failure.NewError(kind, format, args...)
}
