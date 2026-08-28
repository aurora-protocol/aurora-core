//go:build cgo

// Hostile-input contract coverage for the full dispatch table (auroracore.go).
// FuzzNativeDispatchCodecOperations pins the status/payload contract for the
// stateless codec ops (1-7); this table test extends the same assertions to
// every operation code, including the session ops (8-18) and provisioning ops
// (19-22), whose reject paths must fail closed without a panic: a panic in
// dispatch crashes the host app, and a non-OK status carrying a payload would
// hand the adapter bytes it is not prepared to own.
//
// The garbage inputs can never succeed for the stateful ops, so the package
// globals (nativeSessions, nativeProvisioningTrust) are never mutated here:
// begin/reserve fail parsing, configure rejects non-canonical trust, and the
// handle-carrying ops miss the empty in-process registry.

package main

import (
	"bytes"
	"testing"
)

func TestDispatchHostileInputsPreserveStatusContract(t *testing.T) {
	inputs := []struct {
		name string
		in   []byte
	}{
		{name: "nil", in: nil},
		{name: "empty", in: []byte{}},
		{name: "single zero", in: []byte{0x00}},
		{name: "79 x ff", in: bytes.Repeat([]byte{0xff}, issueRequestInputLen-1)},
		{name: "80 x ff", in: bytes.Repeat([]byte{0xff}, issueRequestInputLen)},
		{name: "4k zeros", in: bytes.Repeat([]byte{0x00}, 4096)},
	}
	args := []uint64{0, 1, 1 << 63, ^uint64(0)}
	for op := 0; op <= opReserveNativeProvisioningJSON+1; op++ {
		for _, input := range inputs {
			for _, arg := range args {
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							t.Fatalf("dispatch(op=%d, %s, arg=%d) panicked: %v", op, input.name, arg, recovered)
						}
					}()
					status, payload := dispatch(op, input.in, arg)
					switch status {
					case statusOK:
						// OK may carry a nil payload for stateful ops
						// (complete/close/validate/configure, empty next packet).
					case statusConflict, statusError:
						if payload != nil {
							t.Fatalf("dispatch(op=%d, %s, arg=%d) status %d carried a %d-byte payload", op, input.name, arg, status, len(payload))
						}
					default:
						t.Fatalf("dispatch(op=%d, %s, arg=%d) returned undefined status %d", op, input.name, arg, status)
					}
				}()
			}
		}
	}
}
