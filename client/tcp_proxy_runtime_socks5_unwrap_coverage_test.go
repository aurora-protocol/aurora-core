package client

// Coverage for socks5RequestError.Unwrap (tcp_proxy_runtime.go:129). The
// SOCKS5 handshake tests assert on Error() and the reply code but never unwrap,
// so the error-chain contract (Unwrap returns the wrapped failure, errors.Is
// reaches it) stayed uncovered.

import (
	"errors"
	"fmt"
	"testing"
)

func TestSocks5RequestErrorUnwrapReturnsWrappedError(t *testing.T) {
	sentinel := errors.New("upstream dial refused")
	err := &socks5RequestError{err: sentinel, reply: 0x05}
	if unwrapped := err.Unwrap(); !errors.Is(unwrapped, sentinel) {
		t.Fatalf("socks5RequestError.Unwrap() = %v, want %v", unwrapped, sentinel)
	}
	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is does not reach the wrapped error through Unwrap")
	}
	if err.Error() != sentinel.Error() {
		t.Fatalf("socks5RequestError.Error() = %q, want %q", err.Error(), sentinel.Error())
	}

	wrapped := fmt.Errorf("socks5 connect: %w", err)
	if !errors.Is(wrapped, sentinel) {
		t.Fatal("errors.Is does not reach the sentinel through a doubly wrapped error")
	}
}
