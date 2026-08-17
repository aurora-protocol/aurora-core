package client

// Adversarial white-box coverage for the four count-0 input-validation /
// parse-error guards of provisionedProofsForIssuerResponse
// (client/provisioned_session.go:378/:386/:389/:393). This is the companion to
// #362 (buildProvisionedIssuerWork) in the same file: both are pure-ish
// functions on the provisioned-issuer-response path whose count-0 guards sit
// BEFORE the crypto verify (admission.VerifyBlindRSA2048WithIssuerMetadata at
// :397, already covered by #331's happy-path test). #363 covers the four error
// guards that the valid-signed-proof happy path (#331) never trips.
//
// provisionedProofsForIssuerResponse(request, issuerResponse, issuerMetadata,
// nowUnix, random) validates in order:
//   - :378  nowUnix == 0
//        -> "client: provisioned issuer response requires a valid time"
//   - :381/:382  carrier.Decode(issuerResponse) err ||
//        carrierType != carrier.BlindRSAIssueResponse || len(payload) == 0
//        -> "client: invalid provisioned issuer response"   (ALREADY COVERED,
//           count=1 — left untouched)
//   - :385/:386  issuerd.DecodeAdmissionProofBytes(payload) err
//        -> "client: decode provisioned admission proof: <err>"
//   - :389  proof.ExpiryUnix <= nowUnix
//        -> "client: provisioned admission proof is expired"
//   - :393  !bytes.Equal(proof.RedemptionContextHash, request.AdmissionContextHash)
//        -> "client: provisioned admission proof context mismatch"
//   - :397  admission.VerifyBlindRSA2048WithIssuerMetadata(...) err  (crypto,
//           ALREADY COVERED count=1 by #331 — left untouched)
//
// The happy path (#331) passes a valid SIGNED Blind RSA proof (nowUnix!=0,
// valid carrier envelope, decodable proof, ExpiryUnix>nowUnix,
// RedemptionContextHash==AdmissionContextHash, crypto verifies) -> returns
// err==nil, so :378/:386/:389/:393 stayed COUNT 0 (confirmed: each block
// count=0 on a clean tree).
//
// Coverage targets (baseline measured on a clean tree; bodies COUNT 0):
//   - provisioned_session.go:378.18,380.3 0 — nowUnix == 0
//   - provisioned_session.go:386.16,388.3  0 — decode admission proof err
//   - provisioned_session.go:389.33,392.3  0 — proof expired
//   - provisioned_session.go:393.77,396.3  0 — redemption context mismatch
//
// Reachability (one subtest per guard, each crafted to trip exactly one guard
// and pass all earlier ones; all return BEFORE :397 so no crypto/signing is
// needed — issuerMetadata is zero-value and random is nil, never used):
//   - nowUnix zero: nowUnix=0 trips :378 before anything is decoded.
//   - malformed proof: issuerResponse = carrier.Encode(BlindRSAIssueResponse,
//     []byte{0xFF}) -> carrier.Decode succeeds (right type, payload len 1 >
//     0, passes :382) but DecodeAdmissionProofBytes([0xFF]) underflows on the
//     first ReadVarint (0xFF continuation bit set, no more bytes) -> reader.Err
//     -> :386.
//   - expired proof: a STRUCTURALLY-VALID AdmissionProof (exact fixed-opaque
//     lengths so wire.Encode + DecodeAdmissionProof round-trip cleanly,
//     reader.Err==nil) with ExpiryUnix=0 <= nowUnix=100, wrapped in
//     carrier.Encode(BlindRSAIssueResponse, encoded). DecodeAdmissionProofBytes
//     succeeds (:386 passes), then :389 ExpiryUnix(0) <= nowUnix(100) trips.
//     RedemptionContextHash == request.AdmissionContextHash (both zero-filled)
//     so :393 does not interfere.
//   - context mismatch: structurally-valid AdmissionProof with ExpiryUnix=200
//     > nowUnix=100 (passes :389) but RedemptionContextHash differs from
//     request.AdmissionContextHash (set byte 0 to 0xFF while the request hash
//     stays zero-filled) -> :393 trips.
//
// DecodeAdmissionProofBytes (issuerd/http.go:431) only DECODES
// (protocol.DecodeAdmissionProof + reader.Err/EOF); ValidateStructural is
// separate, so a structurally-valid-but-semantically-invalid proof decodes
// cleanly and the semantic checks at :389/:393 catch the field violations.
// Error substring is asserted per subtest (self-validating); the per-line
// coverage flip (0->1 per guard) is the rigorous proof. In-package
// (package client) matches the existing provisioned_session test family and
// the #362 companion. Distinct filename + test name, a local validProof helper
// (no collision with existing client tests), no shared helpers. One TestXxx
// with four t.Run subtests; imports strings/testing/carrier/handshake/protocol/
// wire (all used) -> no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

// validAdmissionProofBytes returns the wire encoding of a STRUCTURALLY-VALID
// AdmissionProof (every fixed-opaque field at the exact length EncodeTo/
// DecodeAdmissionProof expect, Opaque16/Extensions nil) with the given
// ExpiryUnix and RedemptionContextHash. It decodes cleanly via
// DecodeAdmissionProof (reader.Err==nil, reader.EOF==true) so the semantic
// guards :389/:393 are reached.
func validAdmissionProofBytes(t *testing.T, expiry uint64, redemptionContextHash []byte) []byte {
	t.Helper()
	enc, err := wire.Encode(protocol.AdmissionProof{
		IssuerID:              make([]byte, 16),
		TokenKeyID:            make([]byte, 32),
		RelayBucketID:         make([]byte, 16),
		TokenScopeID:          make([]byte, 16),
		ExpiryUnix:            expiry,
		TokenNonce:            make([]byte, 32),
		RedemptionContextHash: redemptionContextHash,
		// TokenPublicMetadata / TokenAuthenticator / BindingProof: nil
		//   -> WriteOpaque16 length 0 (decode cleanly).
		// Extensions: nil -> EncodeExtensions count 0 (decode cleanly).
	})
	if err != nil {
		t.Fatalf("wire.Encode(AdmissionProof) err = %v, want nil (structurally-valid fields)", err)
	}
	return enc
}

func TestProvisionedProofsForIssuerResponseRejectsInvalidInputs(t *testing.T) {
	// request.AdmissionContextHash is zero-filled; the :393 mismatch subtest
	// perturbs the proof's RedemptionContextHash away from this.
	request := handshake.ClientProofRequest{AdmissionContextHash: make([]byte, 48)}
	zeroHash := make([]byte, 48)

	cases := []struct {
		name           string
		issuerResponse []byte
		nowUnix        uint64
		wantSub        string
	}{
		{
			// :378 — nowUnix == 0 trips before any decode.
			name:           "nowUnix zero",
			issuerResponse: carrier.Encode(carrier.BlindRSAIssueResponse, validAdmissionProofBytes(t, 200, zeroHash)),
			nowUnix:        0,
			wantSub:        "provisioned issuer response requires a valid time",
		},
		{
			// :386 — valid carrier envelope but malformed proof payload:
			// 0xFF varint-continuation underflows on the first ReadVarint.
			name:           "malformed proof payload",
			issuerResponse: carrier.Encode(carrier.BlindRSAIssueResponse, []byte{0xFF}),
			nowUnix:        100,
			wantSub:        "decode provisioned admission proof",
		},
		{
			// :389 — structurally-valid proof with ExpiryUnix(0) <= nowUnix(100).
			// RedemptionContextHash == request.AdmissionContextHash (both zero)
			// so :393 does not fire first.
			name:           "expired proof",
			issuerResponse: carrier.Encode(carrier.BlindRSAIssueResponse, validAdmissionProofBytes(t, 0, zeroHash)),
			nowUnix:        100,
			wantSub:        "provisioned admission proof is expired",
		},
		{
			// :393 — structurally-valid proof, ExpiryUnix(200) > nowUnix(100)
			// (passes :389), but RedemptionContextHash != request hash.
			name: "redemption context mismatch",
			issuerResponse: func() []byte {
				mismatchHash := make([]byte, 48)
				mismatchHash[0] = 0xFF
				return carrier.Encode(carrier.BlindRSAIssueResponse, validAdmissionProofBytes(t, 200, mismatchHash))
			}(),
			nowUnix: 100,
			wantSub: "provisioned admission proof context mismatch",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := provisionedProofsForIssuerResponse(request, c.issuerResponse, protocol.IssuerMetadata{}, c.nowUnix, nil)
			if err == nil || !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("provisionedProofsForIssuerResponse(%s) err = %v, want non-nil containing %q", c.name, err, c.wantSub)
			}
		})
	}
}
