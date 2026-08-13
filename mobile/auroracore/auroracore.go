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

void aurora_core_secure_zero(void *p, size_t length);
*/
import "C"

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
)

// Operation codes for AuroraCoreCall. Kept stable as part of the ABI contract.
const (
	opEncodeMetadataRequest            = 1
	opEncodeIssueRequest               = 2
	opEncodeSpendRequest               = 3
	opDecodeMetadataResponse           = 4
	opDecodeIssueResponse              = 5
	opDecodeSpendResponse              = 6
	opParseAdmissionProof              = 7
	opBeginNativeSession               = 8
	opCompleteNativeSession            = 9
	opCloseNativeSession               = 10
	opQueueFrameBlock                  = 11
	opNextPacket                       = 12
	opHandlePacket                     = 13
	opIngressLocalPacket               = 14
	opNextLocalPacket                  = 15
	opBeginNativeSessionJSON           = 16
	opCompleteNativeSessionRaw         = 17
	opIngressLocalPacketJSON           = 18
	opReserveNativeProvisioning        = 19
	opValidateNativeProvisioningSource = 20
)

// Result status bytes.
const (
	statusOK       byte = 0x00
	statusConflict byte = 0x01
	statusError    byte = 0x02
)

const issueRequestInputLen = 32 + 48 // token_nonce || redemption_context_hash

const (
	nativeProvisioningReservationSourceLengthBytes = 4
	nativeProvisioningReservationCountBytes        = 1
	nativeProvisioningReservationSpentHintKeyBytes = 48
	nativeProvisioningReservationRelayBucketBytes  = 16
	maximumNativeProvisioningReservationKeys       = 64
	maximumNativeProvisioningReservationInput      = client.MaximumNativeProvisioningWalletBytes + nativeProvisioningReservationSourceLengthBytes + nativeProvisioningReservationCountBytes + maximumNativeProvisioningReservationKeys*nativeProvisioningReservationSpentHintKeyBytes
	maximumNativeCallInputBytes                    = maximumNativeProvisioningReservationInput
)

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

type nativeIssuerWorkJSON struct {
	Handle            uint64 `json:"handle"`
	IssuerURL         string `json:"issuer_url"`
	IssuerCarrierPath string `json:"issuer_carrier_path"`
	RequestBodyBase64 string `json:"request_body_base64"`
}

type nativeLocalPacketsJSON struct {
	PacketsBase64 []string `json:"packets_base64"`
}

// AuroraCoreCall dispatches a single portable-core operation. in/inLen is the
// input buffer; arg carries a scalar argument (e.g. token expiry). The returned
// buffer is malloc'd and owned by the caller, who MUST release it with
// AuroraCoreZeroFree. Its first byte is a status; the remaining bytes are the
// payload.
//
//export AuroraCoreCall
func AuroraCoreCall(op C.int, in *C.uint8_t, inLen C.int, arg C.uint64_t, outLen *C.int) *C.uint8_t {
	if outLen == nil {
		return nil
	}
	var input []byte
	if !nativeCallInputLengthValid(int(inLen)) || (inLen > 0 && in == nil) {
		return cBytes([]byte{statusError}, outLen)
	}
	if inLen > 0 {
		input = C.GoBytes(unsafe.Pointer(in), inLen)
	}
	defer zeroNativeBytes(input)
	status, payload := dispatch(int(op), input, uint64(arg))
	result := make([]byte, 1+len(payload))
	result[0] = status
	copy(result[1:], payload)
	output := cBytes(result, outLen)
	zeroNativeBytes(payload)
	zeroNativeBytes(result)
	return output
}

// nativeCallInputLengthValid bounds the caller-controlled copy before C.GoBytes.
func nativeCallInputLengthValid(length int) bool {
	return length >= 0 && length <= maximumNativeCallInputBytes
}

// AuroraCoreFree releases an output buffer from AuroraCoreCall.
//
// Deprecated: use AuroraCoreZeroFree to scrub the buffer before release.
//
//export AuroraCoreFree
func AuroraCoreFree(p *C.uint8_t) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

// AuroraCoreZeroFree scrubs and releases an output buffer from AuroraCoreCall.
//
//export AuroraCoreZeroFree
func AuroraCoreZeroFree(p *C.uint8_t, length C.int) {
	if p == nil {
		return
	}
	if length > 0 {
		C.aurora_core_secure_zero(unsafe.Pointer(p), C.size_t(length))
	}
	C.free(unsafe.Pointer(p))
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
	case opBeginNativeSession:
		if arg != 0 {
			return statusError, nil
		}
		provisioning, err := client.ParseNativeProvisioning(in, time.Now())
		if err != nil {
			return statusError, nil
		}
		work, err := nativeSessions.begin(provisioning)
		if err != nil {
			return statusError, nil
		}
		encoded, err := work.encode()
		handle := work.Handle
		zeroNativeIssuerWork(&work)
		if err != nil {
			_ = nativeSessions.close(handle)
			return statusError, nil
		}
		return statusOK, encoded
	case opCompleteNativeSession:
		if arg != 0 {
			return statusError, nil
		}
		handle, issuerResponse, err := decodeNativeHandlePayload(in, maximumNativeIssuerResponse)
		if err != nil || nativeSessions.complete(handle, issuerResponse) != nil {
			return statusError, nil
		}
		return statusOK, nil
	case opCloseNativeSession:
		if len(in) != 0 || arg == 0 || nativeSessions.close(arg) != nil {
			return statusError, nil
		}
		return statusOK, nil
	case opQueueFrameBlock:
		if arg != 0 {
			return statusError, nil
		}
		handle, block, err := decodeNativeHandlePayload(in, maximumNativeSessionPacket)
		if err != nil {
			return statusError, nil
		}
		if err := nativeSessions.queueFrameBlock(handle, block); err != nil {
			if errors.Is(err, session.ErrBackpressure) {
				return statusConflict, nil
			}
			return statusError, nil
		}
		return statusOK, nil
	case opNextPacket:
		if len(in) != 0 || arg == 0 {
			return statusError, nil
		}
		packet, err := nativeSessions.nextPacket(arg)
		if errors.Is(err, session.ErrNoPacket) {
			return statusOK, nil
		}
		if err != nil {
			return statusError, nil
		}
		return statusOK, packet
	case opHandlePacket:
		if arg != 0 {
			return statusError, nil
		}
		handle, packet, err := decodeNativeHandlePayload(in, maximumNativeSessionPacket)
		if err != nil {
			return statusError, nil
		}
		blocks, err := nativeSessions.handlePacket(handle, packet)
		if err != nil {
			return statusError, nil
		}
		return statusOK, blocks
	case opIngressLocalPacket:
		if arg == 0 {
			return statusError, nil
		}
		packets, err := nativeSessions.ingressLocalPacket(arg, in)
		if err != nil {
			if errors.Is(err, session.ErrBackpressure) {
				return statusConflict, nil
			}
			return statusError, nil
		}
		defer zeroNativeLocalPackets(packets)
		encoded, err := encodeNativeLocalPackets(packets)
		if err != nil {
			return statusError, nil
		}
		return statusOK, encoded
	case opNextLocalPacket:
		if arg == 0 || len(in) != 0 {
			return statusError, nil
		}
		packet, err := nativeSessions.nextLocalPacket(context.Background(), arg)
		if err != nil {
			return statusError, nil
		}
		return statusOK, packet
	case opBeginNativeSessionJSON:
		if arg != 0 {
			return statusError, nil
		}
		provisioning, err := client.ParseNativeProvisioning(in, time.Now())
		if err != nil {
			return statusError, nil
		}
		work, err := nativeSessions.begin(provisioning)
		if err != nil {
			return statusError, nil
		}
		encoded, err := encodeNativeIssuerWorkJSON(work)
		handle := work.Handle
		zeroNativeIssuerWork(&work)
		if err != nil {
			_ = nativeSessions.close(handle)
			return statusError, nil
		}
		return statusOK, encoded
	case opCompleteNativeSessionRaw:
		if arg == 0 || len(in) == 0 || nativeSessions.complete(arg, in) != nil {
			return statusError, nil
		}
		return statusOK, nil
	case opIngressLocalPacketJSON:
		if arg == 0 {
			return statusError, nil
		}
		packets, err := nativeSessions.ingressLocalPacket(arg, in)
		if err != nil {
			if errors.Is(err, session.ErrBackpressure) {
				return statusConflict, nil
			}
			return statusError, nil
		}
		defer zeroNativeLocalPackets(packets)
		encoded, err := encodeNativeLocalPacketsJSON(packets)
		if err != nil {
			return statusError, nil
		}
		return statusOK, encoded
	case opReserveNativeProvisioning:
		if arg == 0 || arg > uint64(^uint64(0)>>1) {
			return statusError, nil
		}
		reservation, err := reserveNativeProvisioning(in, time.Unix(int64(arg), 0).UTC())
		if err != nil {
			return statusError, nil
		}
		defer reservation.Zero()
		encoded, err := encodeNativeProvisioningReservation(reservation)
		if err != nil {
			return statusError, nil
		}
		return statusOK, encoded
	case opValidateNativeProvisioningSource:
		if arg == 0 || arg > uint64(^uint64(0)>>1) {
			return statusError, nil
		}
		if err := client.ValidateNativeProvisioningSource(in, time.Unix(int64(arg), 0).UTC()); err != nil {
			return statusError, nil
		}
		return statusOK, nil
	default:
		return statusError, nil
	}
}

type nativeProvisioningReservation struct {
	Provisioning         []byte
	SpentHintKey         []byte
	RelayBucketID        []byte
	AccessHintExpiryUnix uint64
}

func reserveNativeProvisioning(encoded []byte, now time.Time) (client.NativeProvisioningReservation, error) {
	source, spentHintKeys, err := decodeNativeProvisioningReservationRequest(encoded)
	if err != nil {
		return client.NativeProvisioningReservation{}, err
	}
	return client.ReserveNativeProvisioning(source, func(candidate []byte) bool {
		for _, spentHintKey := range spentHintKeys {
			if subtle.ConstantTimeCompare(candidate, spentHintKey) == 1 {
				return true
			}
		}
		return false
	}, now)
}

func encodeNativeProvisioningReservationRequest(source []byte, spentHintKeys [][]byte) ([]byte, error) {
	if len(source) == 0 || len(source) > client.MaximumNativeProvisioningWalletBytes || len(spentHintKeys) > maximumNativeProvisioningReservationKeys {
		return nil, fmt.Errorf("auroracore: native provisioning reservation request is invalid")
	}
	encoded := make([]byte, nativeProvisioningReservationSourceLengthBytes+len(source)+nativeProvisioningReservationCountBytes+len(spentHintKeys)*nativeProvisioningReservationSpentHintKeyBytes)
	binary.BigEndian.PutUint32(encoded[:nativeProvisioningReservationSourceLengthBytes], uint32(len(source)))
	copy(encoded[nativeProvisioningReservationSourceLengthBytes:], source)
	offset := nativeProvisioningReservationSourceLengthBytes + len(source)
	encoded[offset] = byte(len(spentHintKeys))
	offset += nativeProvisioningReservationCountBytes
	for _, spentHintKey := range spentHintKeys {
		if len(spentHintKey) != nativeProvisioningReservationSpentHintKeyBytes {
			zeroNativeBytes(encoded)
			return nil, fmt.Errorf("auroracore: native provisioning reservation spent hint key is invalid")
		}
		copy(encoded[offset:], spentHintKey)
		offset += nativeProvisioningReservationSpentHintKeyBytes
	}
	return encoded, nil
}

func decodeNativeProvisioningReservationRequest(encoded []byte) ([]byte, [][]byte, error) {
	if len(encoded) < nativeProvisioningReservationSourceLengthBytes+nativeProvisioningReservationCountBytes || len(encoded) > maximumNativeProvisioningReservationInput {
		return nil, nil, fmt.Errorf("auroracore: native provisioning reservation request size is invalid")
	}
	sourceLength := int(binary.BigEndian.Uint32(encoded[:nativeProvisioningReservationSourceLengthBytes]))
	if sourceLength == 0 || sourceLength > client.MaximumNativeProvisioningWalletBytes {
		return nil, nil, fmt.Errorf("auroracore: native provisioning reservation source is invalid")
	}
	offset := nativeProvisioningReservationSourceLengthBytes
	if sourceLength > len(encoded)-offset-nativeProvisioningReservationCountBytes {
		return nil, nil, fmt.Errorf("auroracore: native provisioning reservation source is truncated")
	}
	source := encoded[offset : offset+sourceLength]
	offset += sourceLength
	count := int(encoded[offset])
	offset += nativeProvisioningReservationCountBytes
	if count > maximumNativeProvisioningReservationKeys || len(encoded)-offset != count*nativeProvisioningReservationSpentHintKeyBytes {
		return nil, nil, fmt.Errorf("auroracore: native provisioning reservation spent hint keys are invalid")
	}
	spentHintKeys := make([][]byte, count)
	for index := range count {
		spentHintKeys[index] = encoded[offset : offset+nativeProvisioningReservationSpentHintKeyBytes]
		offset += nativeProvisioningReservationSpentHintKeyBytes
	}
	return source, spentHintKeys, nil
}

func encodeNativeProvisioningReservation(reservation client.NativeProvisioningReservation) ([]byte, error) {
	if len(reservation.SpentHintKey) != nativeProvisioningReservationSpentHintKeyBytes || len(reservation.RelayBucketID) != nativeProvisioningReservationRelayBucketBytes || reservation.AccessHintExpiryUnix == 0 {
		return nil, fmt.Errorf("auroracore: native provisioning reservation is invalid")
	}
	provisioning, err := client.EncodeNativeProvisioning(reservation.Provisioning)
	if err != nil {
		return nil, err
	}
	defer zeroNativeBytes(provisioning)
	encoded := make([]byte, 3+len(provisioning)+nativeProvisioningReservationSpentHintKeyBytes+nativeProvisioningReservationRelayBucketBytes+8)
	encoded[0] = byte(len(provisioning) >> 16)
	encoded[1] = byte(len(provisioning) >> 8)
	encoded[2] = byte(len(provisioning))
	offset := 3
	copy(encoded[offset:], provisioning)
	offset += len(provisioning)
	copy(encoded[offset:], reservation.SpentHintKey)
	offset += nativeProvisioningReservationSpentHintKeyBytes
	copy(encoded[offset:], reservation.RelayBucketID)
	offset += nativeProvisioningReservationRelayBucketBytes
	binary.BigEndian.PutUint64(encoded[offset:], reservation.AccessHintExpiryUnix)
	return encoded, nil
}

func decodeNativeProvisioningReservation(encoded []byte) (nativeProvisioningReservation, error) {
	if len(encoded) < 3+nativeProvisioningReservationSpentHintKeyBytes+nativeProvisioningReservationRelayBucketBytes+8 {
		return nativeProvisioningReservation{}, fmt.Errorf("auroracore: native provisioning reservation result is invalid")
	}
	provisioningLength := int(encoded[0])<<16 | int(encoded[1])<<8 | int(encoded[2])
	offset := 3
	if provisioningLength == 0 || provisioningLength > client.MaximumNativeProvisioningWalletBytes || provisioningLength != len(encoded)-offset-nativeProvisioningReservationSpentHintKeyBytes-nativeProvisioningReservationRelayBucketBytes-8 {
		return nativeProvisioningReservation{}, fmt.Errorf("auroracore: native provisioning reservation result is malformed")
	}
	reservation := nativeProvisioningReservation{
		Provisioning: append([]byte(nil), encoded[offset:offset+provisioningLength]...),
	}
	offset += provisioningLength
	reservation.SpentHintKey = append([]byte(nil), encoded[offset:offset+nativeProvisioningReservationSpentHintKeyBytes]...)
	offset += nativeProvisioningReservationSpentHintKeyBytes
	reservation.RelayBucketID = append([]byte(nil), encoded[offset:offset+nativeProvisioningReservationRelayBucketBytes]...)
	offset += nativeProvisioningReservationRelayBucketBytes
	reservation.AccessHintExpiryUnix = binary.BigEndian.Uint64(encoded[offset:])
	if reservation.AccessHintExpiryUnix == 0 {
		zeroNativeBytes(reservation.Provisioning)
		zeroNativeBytes(reservation.SpentHintKey)
		zeroNativeBytes(reservation.RelayBucketID)
		return nativeProvisioningReservation{}, fmt.Errorf("auroracore: native provisioning reservation expiry is invalid")
	}
	return reservation, nil
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

func encodeNativeIssuerWorkJSON(work nativeIssuerWork) ([]byte, error) {
	if work.Handle == 0 || len(work.IssuerURL) == 0 || len(work.IssuerCarrierPath) == 0 || len(work.RequestBody) == 0 || len(work.RequestBody) > maximumNativeIssuerWorkBytes {
		return nil, fmt.Errorf("auroracore: native issuer work is invalid")
	}
	return json.Marshal(nativeIssuerWorkJSON{
		Handle:            work.Handle,
		IssuerURL:         work.IssuerURL,
		IssuerCarrierPath: work.IssuerCarrierPath,
		RequestBodyBase64: base64.StdEncoding.EncodeToString(work.RequestBody),
	})
}

func encodeNativeLocalPacketsJSON(packets [][]byte) ([]byte, error) {
	if len(packets) > maximumNativeLocalPacketQueue {
		return nil, fmt.Errorf("auroracore: native local packet result count exceeds limit")
	}
	encodedPackets := make([]string, len(packets))
	for index, packet := range packets {
		if len(packet) == 0 || len(packet) > maximumNativeLocalPacketBytes {
			return nil, fmt.Errorf("auroracore: native local packet is invalid")
		}
		encodedPackets[index] = base64.StdEncoding.EncodeToString(packet)
	}
	encoded, err := json.Marshal(nativeLocalPacketsJSON{PacketsBase64: encodedPackets})
	if err != nil {
		return nil, err
	}
	if len(encoded) > maximumNativeLocalPacketResult*2 {
		zeroNativeBytes(encoded)
		return nil, fmt.Errorf("auroracore: native local packet JSON exceeds size limit")
	}
	return encoded, nil
}

func main() {}
