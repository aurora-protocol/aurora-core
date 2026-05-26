package failure

import "fmt"

type Error struct {
	Kind Kind
	Err  error
}

func NewError(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Err: fmt.Errorf(format, args...)}
}

func (e *Error) Error() string {
	if e == nil || e.Err == nil {
		return "failure"
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
