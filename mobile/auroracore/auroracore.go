// Package main builds the Aurora portable-core C archive consumed by the Apple
// (and other native) thin adapters via an AuroraCore.xcframework.
//
// Per Aurora spec Section 35.10, wire encoding, AdmissionProof handling,
// ReplayProof, and the issuance/cover-carrier codec are portable-core
// responsibilities that MUST live outside the platform adapter. Native adapters
// own only network and packet I/O; they call into this archive for every
// byte-level protocol operation instead of reimplementing it.
//
// The ABI is a single dispatch entry point plus a free function so the Swift
// bridging surface stays tiny. All buffers are length-delimited; results are
// prefixed with a one-byte status (OK / CONFLICT / ERROR).
package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/server"
)

// Operation codes for AuroraCoreCall. Kept stable as part of the ABI contract.
const (
	opEncodeMetadataRequest  = 1
	opEncodeIssueRequest     = 2
	opEncodeSpendRequest     = 3
	opDecodeMetadataResponse = 4
	opDecodeIssueResponse    = 5
	opDecodeSpendResponse    = 6
	opParseAdmissionProof    = 7
)

// Result status bytes.
const (
	statusOK       byte = 0x00
	statusConflict byte = 0x01
	statusError    byte = 0x02
)

const issueRequestInputLen = 32 + 48 // token_nonce || redemption_context_hash

type parsedAdmissionProof struct {
	RelayBucketIDHex      string `json:"relay_bucket_id"`
	TokenAuthenticatorHex string `json:"token_authenticator"`
	IssuerMetadataHashHex string `json:"issuer_metadata_hash"`
	ExpiryUnix            uint64 `json:"expiry_unix"`
}

type parsedMetadata struct {
	IssuerMetadataHex     string `json:"issuer_metadata"`
	IssuerMetadataHashHex string `json:"issuer_metadata_hash"`
}

// AuroraCoreCall dispatches a single portable-core operation. in/inLen is the
// input buffer; arg carries a scalar argument (e.g. token expiry). The returned
// buffer is malloc'd and owned by the caller, who MUST release it with
// AuroraCoreFree. Its first byte is a status; the remaining bytes are the
// payload.
//
//export AuroraCoreCall
func AuroraCoreCall(op C.int, in *C.uint8_t, inLen C.int, arg C.uint64_t, outLen *C.int) *C.uint8_t {
	var input []byte
	if in != nil && inLen > 0 {
		input = C.GoBytes(unsafe.Pointer(in), inLen)
	}
	status, payload := dispatch(int(op), input, uint64(arg))
	result := make([]byte, 1+len(payload))
	result[0] = status
	copy(result[1:], payload)
	return cBytes(result, outLen)
}

//export AuroraCoreFree
func AuroraCoreFree(p *C.uint8_t) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

func cBytes(b []byte, outLen *C.int) *C.uint8_t {
	*outLen = C.int(len(b))
	p := C.malloc(C.size_t(len(b)))
	if p == nil {
		*outLen = 0
		return nil
	}
	if len(b) > 0 {
		C.memmove(p, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	}
	return (*C.uint8_t)(p)
}

func dispatch(op int, in []byte, arg uint64) (byte, []byte) {
	switch op {
	case opEncodeMetadataRequest:
		return statusOK, server.EncodeCarrier(server.CarrierIssuerMetadataReq, nil)
	case opEncodeIssueRequest:
		if len(in) != issueRequestInputLen {
			return statusError, nil
		}
		body, err := server.EncodeCarrierIssueRequest(in[:32], in[32:issueRequestInputLen], arg)
		if err != nil {
			return statusError, nil
		}
		return statusOK, server.EncodeCarrier(server.CarrierBlindRSAIssueReq, body)
	case opEncodeSpendRequest:
		if len(in) == 0 {
			return statusError, nil
		}
		return statusOK, server.EncodeCarrier(server.CarrierTokenSpendReq, in)
	case opDecodeMetadataResponse:
		carrierType, payload, err := server.DecodeCarrier(in)
		if err != nil || carrierType != server.CarrierIssuerMetadataResp {
			return statusError, nil
		}
		encoded, hash, err := server.DecodeCarrierMetadataResponse(payload)
		if err != nil {
			return statusError, nil
		}
		out, err := json.Marshal(parsedMetadata{
			IssuerMetadataHex:     hex.EncodeToString(encoded),
			IssuerMetadataHashHex: hex.EncodeToString(hash),
		})
		if err != nil {
			return statusError, nil
		}
		return statusOK, out
	case opDecodeIssueResponse:
		carrierType, payload, err := server.DecodeCarrier(in)
		if err != nil || carrierType != server.CarrierBlindRSAIssueResp || len(payload) == 0 {
			return statusError, nil
		}
		return statusOK, payload
	case opDecodeSpendResponse:
		carrierType, payload, err := server.DecodeCarrier(in)
		if err != nil {
			return statusError, nil
		}
		switch carrierType {
		case server.CarrierTokenSpendResp:
			return statusOK, payload
		case server.CarrierTokenSpendConflict:
			return statusConflict, nil
		default:
			return statusError, nil
		}
	case opParseAdmissionProof:
		encoded, err := parseAdmissionProof(in)
		if err != nil {
			return statusError, nil
		}
		return statusOK, encoded
	default:
		return statusError, nil
	}
}

// parseAdmissionProof decodes and binding-validates an AdmissionProof using the
// portable core, returning the wallet-relevant fields as JSON. This is the
// logic the spec forbids the platform adapter from reimplementing.
func parseAdmissionProof(in []byte) ([]byte, error) {
	proof, err := issuerd.DecodeAdmissionProofBytes(in)
	if err != nil {
		return nil, err
	}
	meta, err := protocol.DecodeAuroraTokenMetadataBytes(proof.TokenPublicMetadata)
	if err != nil {
		return nil, err
	}
	if err := meta.ValidateForProof(proof, meta.IssuerMetadataHash); err != nil {
		return nil, err
	}
	if len(proof.TokenAuthenticator) == 0 {
		return nil, fmt.Errorf("auroracore: empty token authenticator")
	}
	return json.Marshal(parsedAdmissionProof{
		RelayBucketIDHex:      hex.EncodeToString(proof.RelayBucketID),
		TokenAuthenticatorHex: hex.EncodeToString(proof.TokenAuthenticator),
		IssuerMetadataHashHex: hex.EncodeToString(meta.IssuerMetadataHash),
		ExpiryUnix:            proof.ExpiryUnix,
	})
}

func main() {}
