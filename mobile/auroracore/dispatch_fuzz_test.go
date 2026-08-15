//go:build cgo

package main

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/server"
)

// codecDispatchOperations are the stateless byte-level operations of the native
// ABI. They are the operations a native adapter reaches with attacker-influenced
// bytes -- issuer responses arrive over the cover carrier -- and they hold no
// session state, so they can be driven directly.
var codecDispatchOperations = []int{
	opEncodeMetadataRequest,
	opEncodeIssueRequest,
	opEncodeSpendRequest,
	opDecodeMetadataResponse,
	opDecodeIssueResponse,
	opDecodeSpendResponse,
	opParseAdmissionProof,
}

// FuzzNativeDispatchCodecOperations drives the single ABI entry point that every
// native adapter call passes through. A panic here crashes the host app rather
// than failing a call, and a status that carries an unexpected payload would
// hand the adapter bytes it is not prepared to own, so both are asserted.
func FuzzNativeDispatchCodecOperations(f *testing.F) {
	f.Add(0, []byte(nil), uint64(0))
	f.Add(1, []byte{}, uint64(0))
	f.Add(2, bytes.Repeat([]byte{0x00}, issueRequestInputLen), uint64(1))
	f.Add(3, []byte{0x01, 0x02, 0x03}, uint64(0))
	f.Add(4, server.EncodeCarrier(server.CarrierIssuerMetadataResp, []byte{0x00}), uint64(0))
	f.Add(5, server.EncodeCarrier(server.CarrierBlindRSAIssueResp, []byte{0x01}), uint64(0))
	f.Add(6, server.EncodeCarrier(server.CarrierTokenSpendConflict, nil), uint64(0))
	f.Add(6, server.EncodeCarrier(server.CarrierTokenSpendResp, []byte{0x02}), uint64(0))

	f.Fuzz(func(t *testing.T, operationIndex int, in []byte, arg uint64) {
		if len(in) > maximumNativeCallInputBytes {
			in = in[:maximumNativeCallInputBytes]
		}
		if operationIndex < 0 {
			operationIndex = ^operationIndex
		}
		op := codecDispatchOperations[operationIndex%len(codecDispatchOperations)]

		status, payload := dispatch(op, in, arg)
		switch status {
		case statusOK:
		case statusConflict, statusError:
			// A non-OK result must not hand the adapter a buffer to own.
			if payload != nil {
				t.Fatalf("op %d status %d returned a %d byte payload", op, status, len(payload))
			}
		default:
			t.Fatalf("op %d returned undefined status %d", op, status)
		}
	})
}

// FuzzNativeDispatchUnknownOperations checks that operation codes outside the
// table fail closed rather than falling through to another operation.
func FuzzNativeDispatchUnknownOperations(f *testing.F) {
	f.Add(0, []byte(nil))
	f.Add(23, []byte{0x00})
	f.Add(-1, []byte{0x01, 0x02})

	known := make(map[int]struct{}, len(codecDispatchOperations))
	for op := opEncodeMetadataRequest; op <= opReserveNativeProvisioningJSON; op++ {
		known[op] = struct{}{}
	}

	f.Fuzz(func(t *testing.T, op int, in []byte) {
		if _, ok := known[op]; ok {
			return
		}
		if len(in) > maximumNativeCallInputBytes {
			in = in[:maximumNativeCallInputBytes]
		}
		status, payload := dispatch(op, in, 0)
		if status != statusError {
			t.Fatalf("unknown operation %d returned status %d", op, status)
		}
		if payload != nil {
			t.Fatalf("unknown operation %d returned a %d byte payload", op, len(payload))
		}
	})
}
