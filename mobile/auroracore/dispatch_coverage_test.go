//go:build cgo

package main

// Adversarial coverage for the stateless carrier-codec dispatch operations
// (ops 1-7, auroracore.go:214-271). The existing fuzz seeds
// (dispatch_fuzz_test.go) reach only a handful of these branches, and the
// integration tests drive the session/provisioning ops (8-22) rather than the
// pure codec ops. This test drives each codec op through dispatch with crafted
// inputs so every reachable branch in the op1-op7 cases executes.
//
// The dispatch non-OK invariant (mirrors FuzzNativeDispatchCodecOperations):
// every statusError/statusConflict return carries a nil payload, and every
// statusOK return carries a non-nil payload. assertDispatchResult enforces it.
//
// Deferred (need a nativeProvisioningTrust/session fixture, out of scope for
// this pure-codec pillar):
//   - ops 8-18 (native session lifecycle): require a configured
//     nativeProvisioningTrust and a live first-hop fixture; covered by
//     native_session_integration_test.go.
//   - ops 19-22 (provisioning reserve/validate/configure/JSON): touch the
//     global nativeProvisioningTrust state; covered by
//     provisioning_reservation_test.go / native_provisioning_trust_test.go.
//
// Dead-by-design (documented, not tested):
//   - opEncodeIssueRequest encode-err branch (auroracore.go:221): the
//     len(in)==issueRequestInputLen guard at line 217 guarantees the nonce
//     (in[:32]) and redemption-context (in[32:80]) slices are exactly 32 and 48
//     bytes, so server.EncodeCarrierIssueRequest cannot return an error.
//   - opDecodeMetadataResponse json.Marshal-err branch (auroracore.go:243):
//     parsedMetadata holds two hex strings derived from already-decoded bytes;
//     json.Marshal of two strings cannot fail.

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/server"
)

func TestDispatchCodecOperations(t *testing.T) {
	t.Run("opEncodeMetadataRequest happy", func(t *testing.T) {
		assertDispatchResult(t, opEncodeMetadataRequest, nil, 0, statusOK)
	})

	t.Run("opEncodeIssueRequest wrong length", func(t *testing.T) {
		// 79 bytes != issueRequestInputLen(80) -> line 217-218.
		assertDispatchResult(t, opEncodeIssueRequest, bytes.Repeat([]byte{0x00}, issueRequestInputLen-1), 1, statusError)
	})
	t.Run("opEncodeIssueRequest happy", func(t *testing.T) {
		// Exactly 80 bytes -> EncodeCarrierIssueRequest succeeds -> line 224.
		assertDispatchResult(t, opEncodeIssueRequest, bytes.Repeat([]byte{0x00}, issueRequestInputLen), 1, statusOK)
	})

	t.Run("opEncodeSpendRequest empty", func(t *testing.T) {
		assertDispatchResult(t, opEncodeSpendRequest, nil, 0, statusError) // line 226-227
	})
	t.Run("opEncodeSpendRequest happy", func(t *testing.T) {
		assertDispatchResult(t, opEncodeSpendRequest, []byte{0x01, 0x02, 0x03}, 0, statusOK) // line 229
	})

	t.Run("opDecodeMetadataResponse empty body", func(t *testing.T) {
		// carrier.Decode errors on len < 1 -> line 232 err disjunct.
		assertDispatchResult(t, opDecodeMetadataResponse, nil, 0, statusError)
	})
	t.Run("opDecodeMetadataResponse wrong carrier type", func(t *testing.T) {
		in := server.EncodeCarrier(server.CarrierBlindRSAIssueResp, []byte{0x01})
		assertDispatchResult(t, opDecodeMetadataResponse, in, 0, statusError) // line 232 type disjunct
	})
	t.Run("opDecodeMetadataResponse malformed payload", func(t *testing.T) {
		// Correct carrier type but the inner metadata frame is too short for
		// DecodeCarrierMetadataResponse -> line 236-237.
		in := server.EncodeCarrier(server.CarrierIssuerMetadataResp, []byte{0x00})
		assertDispatchResult(t, opDecodeMetadataResponse, in, 0, statusError)
	})
	t.Run("opDecodeMetadataResponse happy", func(t *testing.T) {
		metaPayload, err := server.EncodeCarrierMetadataResponse([]byte("issuer-metadata"), bytes.Repeat([]byte{0xaa}, 48))
		if err != nil {
			t.Fatalf("EncodeCarrierMetadataResponse: %v", err)
		}
		in := server.EncodeCarrier(server.CarrierIssuerMetadataResp, metaPayload)
		assertDispatchResult(t, opDecodeMetadataResponse, in, 0, statusOK) // line 246
	})

	t.Run("opDecodeIssueResponse empty body", func(t *testing.T) {
		assertDispatchResult(t, opDecodeIssueResponse, nil, 0, statusError) // line 249 err disjunct
	})
	t.Run("opDecodeIssueResponse wrong carrier type", func(t *testing.T) {
		in := server.EncodeCarrier(server.CarrierIssuerMetadataResp, []byte{0x00})
		assertDispatchResult(t, opDecodeIssueResponse, in, 0, statusError) // line 249 type disjunct
	})
	t.Run("opDecodeIssueResponse empty payload", func(t *testing.T) {
		// Correct type, but the carrier body carries no payload -> line 249
		// len(payload)==0 disjunct.
		in := server.EncodeCarrier(server.CarrierBlindRSAIssueResp, nil)
		assertDispatchResult(t, opDecodeIssueResponse, in, 0, statusError)
	})
	t.Run("opDecodeIssueResponse happy", func(t *testing.T) {
		in := server.EncodeCarrier(server.CarrierBlindRSAIssueResp, []byte{0x01})
		assertDispatchResult(t, opDecodeIssueResponse, in, 0, statusOK) // line 252
	})

	t.Run("opDecodeSpendResponse empty body", func(t *testing.T) {
		assertDispatchResult(t, opDecodeSpendResponse, nil, 0, statusError) // line 255-256
	})
	t.Run("opDecodeSpendResponse spend resp", func(t *testing.T) {
		in := server.EncodeCarrier(server.CarrierTokenSpendResp, []byte{0x02})
		assertDispatchResult(t, opDecodeSpendResponse, in, 0, statusOK) // line 259-260
	})
	t.Run("opDecodeSpendResponse conflict", func(t *testing.T) {
		in := server.EncodeCarrier(server.CarrierTokenSpendConflict, nil)
		status, payload := dispatch(opDecodeSpendResponse, in, 0)
		if status != statusConflict {
			t.Fatalf("status=%d, want statusConflict=%d", status, statusConflict)
		}
		if payload != nil {
			t.Fatalf("conflict returned %d-byte payload, want nil", len(payload)) // line 261-262
		}
	})
	t.Run("opDecodeSpendResponse unknown type", func(t *testing.T) {
		in := server.EncodeCarrier(server.CarrierIssuerMetadataResp, []byte{0x00})
		assertDispatchResult(t, opDecodeSpendResponse, in, 0, statusError) // line 263-264 default
	})

	t.Run("opParseAdmissionProof malformed", func(t *testing.T) {
		assertDispatchResult(t, opParseAdmissionProof, []byte{0xff, 0xff, 0xff}, 0, statusError) // line 268-269
	})
	t.Run("opParseAdmissionProof happy", func(t *testing.T) {
		// validProofWire (admission_proof_test.go) is a self-contained fixture
		// that parseAdmissionProof + encodeParsedAdmissionProof accept, so the
		// dispatch wrapper returns statusOK -> line 271.
		assertDispatchResult(t, opParseAdmissionProof, validProofWire(t), 0, statusOK)
	})
}

// assertDispatchResult drives dispatch(op, in, arg) and asserts both the
// returned status and the dispatch payload invariant: a statusOK return
// carries a non-nil payload and a statusError return carries a nil payload.
// statusConflict (which also carries a nil payload) is asserted inline by its
// caller since it is neither statusOK nor statusError.
func assertDispatchResult(t *testing.T, op int, in []byte, arg uint64, wantStatus byte) {
	t.Helper()
	status, payload := dispatch(op, in, arg)
	if status != wantStatus {
		t.Fatalf("dispatch(%d, len=%d, arg=%d) status=%d, want %d", op, len(in), arg, status, wantStatus)
	}
	switch wantStatus {
	case statusOK:
		if payload == nil {
			t.Fatalf("dispatch(%d) OK returned nil payload", op)
		}
	case statusError:
		if payload != nil {
			t.Fatalf("dispatch(%d) error returned %d-byte payload, want nil", op, len(payload))
		}
	}
}
