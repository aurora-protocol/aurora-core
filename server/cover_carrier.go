package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/relay"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

// CarrierType identifies the cover-carrier message kind multiplexed over the
// single application/octet-stream cover surface (DefaultPacketExchangePath).
//
// This fixed type-byte carrier is the lab/readiness native-adapter surface. It
// is not, by itself, a production cover-issuance admission mechanism: an
// internet-facing deployment must place it behind a verified cover-slot gate.
// Malformed messages always fall through to byte-identical cover behaviour.
type CarrierType = carrier.Type

const (
	// CarrierPacketBatch carries an encoded PacketBatch (the P6/P8 packet slot).
	CarrierPacketBatch = carrier.PacketBatch
	// CarrierIssuerMetadataReq requests published IssuerMetadata. Empty payload.
	CarrierIssuerMetadataReq = carrier.IssuerMetadataRequest
	// CarrierIssuerMetadataResp carries encoded IssuerMetadata plus its hash.
	CarrierIssuerMetadataResp = carrier.IssuerMetadataResponse
	// CarrierBlindRSAIssueReq requests a Blind RSA admission token.
	CarrierBlindRSAIssueReq = carrier.BlindRSAIssueRequest
	// CarrierBlindRSAIssueResp carries the encoded AdmissionProof.
	CarrierBlindRSAIssueResp = carrier.BlindRSAIssueResponse
	// CarrierTokenSpendReq spends a previously issued AdmissionProof.
	CarrierTokenSpendReq = carrier.TokenSpendRequest
	// CarrierTokenSpendResp carries the resulting token_spent_key.
	CarrierTokenSpendResp = carrier.TokenSpendResponse
	// CarrierTokenSpendConflict reports a replayed (already-spent) token. It is
	// only reachable by a holder of a valid AdmissionProof, so it is not an
	// adversary-observable distinguisher.
	CarrierTokenSpendConflict = carrier.TokenSpendConflict
)

const (
	carrierTokenNonceLen          = carrier.TokenNonceLength
	carrierRedemptionContextLen   = carrier.RedemptionContextLength
	carrierIssueRequestLen        = carrierTokenNonceLen + carrierRedemptionContextLen + 8
	carrierSpentKeyLen            = 48
	carrierMetadataHashLen        = 48
	maxCarrierControlPayloadBytes = (1 << 20) - 1
	maxCarrierBodyBytes           = 1 + maxPacketBatchBytes
)

// IssuerCarrier is the minimal issuer capability the cover carrier forwards to.
// The relay carries issuance over its cover surface and delegates the actual
// admission logic to the issuer trust domain; it never reimplements it. Request
// slices are borrowed only for the duration of each method call. SpendToken
// implementations must return an error matching issuerd.ErrTokenAlreadySpent
// only after fully authenticating a proof and atomically finding its spent key;
// every other failure remains cover-neutral.
type IssuerCarrier interface {
	IssuerMetadata() (encoded []byte, hash []byte, err error)
	IssueBlindRSA(tokenNonce, redemptionContextHash []byte, expiryUnix uint64) (admissionProof []byte, err error)
	SpendToken(admissionProof []byte) (spentKey []byte, err error)
}

type serviceIssuerCarrier struct {
	service *issuerd.Service
}

func (c serviceIssuerCarrier) IssuerMetadata() ([]byte, []byte, error) {
	if c.service == nil {
		return nil, nil, fmt.Errorf("server: issuer unavailable")
	}
	metadata := c.service.PublishIssuerMetadata()
	encoded, err := protocol.Encode(metadata)
	if err != nil {
		return nil, nil, err
	}
	hash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		return nil, nil, err
	}
	return encoded, hash, nil
}

func (c serviceIssuerCarrier) IssueBlindRSA(tokenNonce, redemptionContextHash []byte, expiryUnix uint64) ([]byte, error) {
	if c.service == nil || !c.service.AllowsUntrustedCarrierIssuance() {
		return nil, fmt.Errorf("server: issuer unavailable")
	}
	proof, err := c.service.IssueBlindRSA2048(issuerd.IssueBlindRSA2048Request{
		TokenNonce:            tokenNonce,
		RedemptionContextHash: redemptionContextHash,
		ExpiryUnix:            expiryUnix,
	})
	if err != nil {
		return nil, err
	}
	return protocol.Encode(proof)
}

func (c serviceIssuerCarrier) SpendToken(admissionProof []byte) ([]byte, error) {
	if c.service == nil || !c.service.AllowsUntrustedCarrierIssuance() {
		return nil, fmt.Errorf("server: issuer unavailable")
	}
	proof, err := issuerd.DecodeAdmissionProofBytes(admissionProof)
	if err != nil {
		return nil, err
	}
	return c.service.SpendToken(proof)
}

func EncodeCarrier(t CarrierType, payload []byte) []byte {
	return carrier.Encode(t, payload)
}

func DecodeCarrier(body []byte) (CarrierType, []byte, error) {
	return carrier.Decode(body)
}

func EncodeCarrierIssueRequest(tokenNonce, redemptionContextHash []byte, expiryUnix uint64) ([]byte, error) {
	return carrier.EncodeIssueRequest(tokenNonce, redemptionContextHash, expiryUnix)
}

func DecodeCarrierIssueRequest(payload []byte) (tokenNonce, redemptionContextHash []byte, expiryUnix uint64, err error) {
	return carrier.DecodeIssueRequest(payload)
}

func EncodeCarrierMetadataResponse(encoded, hash []byte) ([]byte, error) {
	return carrier.EncodeMetadataResponse(encoded, hash)
}

func DecodeCarrierMetadataResponse(payload []byte) (encoded, hash []byte, err error) {
	return carrier.DecodeMetadataResponse(payload)
}

// serveCoverCarrier reads the carrier body and dispatches by message type. Any
// malformed body, unknown type, or downstream failure maps to cover-neutral
// behaviour so the surface is indistinguishable from an ordinary origin.
func serveCoverCarrier(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, exchanger PacketExchanger, issuer IssuerCarrier) {
	if r.Context().Err() != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	carrierType, payload, err := readCarrierRequest(r.Body)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	defer zeroCarrierPayload(payload)
	if r.Context().Err() != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	switch carrierType {
	case CarrierPacketBatch:
		serveCarrierPacketBatch(w, r, origin, coverOrigin, exchanger, payload)
	case CarrierIssuerMetadataReq:
		if len(payload) != 0 {
			serveCoverFailure(w, r, origin, coverOrigin)
			return
		}
		serveCarrierIssuerMetadata(w, r, origin, coverOrigin, issuer)
	case CarrierBlindRSAIssueReq:
		serveCarrierBlindRSAIssue(w, r, origin, coverOrigin, issuer, payload)
	case CarrierTokenSpendReq:
		serveCarrierTokenSpend(w, r, origin, coverOrigin, issuer, payload)
	default:
		serveCoverFailure(w, r, origin, coverOrigin)
	}
}

func readCarrierRequest(body io.Reader) (CarrierType, []byte, error) {
	var kind [1]byte
	if _, err := io.ReadFull(body, kind[:]); err != nil {
		return 0, nil, fmt.Errorf("server: read carrier type: %w", err)
	}
	carrierType := CarrierType(kind[0])
	maximumPayloadBytes := maxCarrierControlPayloadBytes
	if carrierType == CarrierPacketBatch {
		maximumPayloadBytes = maxPacketBatchBytes
	}
	payload, err := io.ReadAll(io.LimitReader(body, int64(maximumPayloadBytes)+1))
	if err != nil {
		zeroCarrierPayload(payload)
		return 0, nil, fmt.Errorf("server: read carrier payload: %w", err)
	}
	if len(payload) > maximumPayloadBytes {
		zeroCarrierPayload(payload)
		return 0, nil, fmt.Errorf("server: carrier payload exceeds limit")
	}
	return carrierType, payload, nil
}

func writeCarrier(w http.ResponseWriter, t CarrierType, payload []byte) {
	encoded := EncodeCarrier(t, payload)
	defer zeroCarrierPayload(encoded)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func serveCarrierPacketBatch(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, exchanger PacketExchanger, payload []byte) {
	if exchanger == nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	inbound, err := DecodePacketBatch(payload)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	defer zeroPacketBatch(&inbound)
	outbound, err := exchanger.ExchangePacketBatch(inbound)
	defer zeroPacketBatch(&outbound)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	encoded, err := EncodePacketBatch(outbound)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	defer zeroCarrierPayload(encoded)
	writeCarrier(w, CarrierPacketBatch, encoded)
}

func serveCarrierIssuerMetadata(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, issuer IssuerCarrier) {
	if issuer == nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	encoded, hash, err := issuer.IssuerMetadata()
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	response, err := EncodeCarrierMetadataResponse(encoded, hash)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	writeCarrier(w, CarrierIssuerMetadataResp, response)
}

func serveCarrierBlindRSAIssue(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, issuer IssuerCarrier, payload []byte) {
	if issuer == nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	tokenNonce, redemptionContextHash, expiryUnix, err := DecodeCarrierIssueRequest(payload)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	defer zeroCarrierPayload(tokenNonce)
	defer zeroCarrierPayload(redemptionContextHash)
	proof, err := issuer.IssueBlindRSA(tokenNonce, redemptionContextHash, expiryUnix)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	defer zeroCarrierPayload(proof)
	writeCarrier(w, CarrierBlindRSAIssueResp, proof)
}

func serveCarrierTokenSpend(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, issuer IssuerCarrier, payload []byte) {
	if issuer == nil || len(payload) == 0 {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	spentKey, err := issuer.SpendToken(payload)
	if err != nil {
		// Only the authenticated replay-cache result is safe to expose in-band.
		// Decode, signature, policy, expiry, and storage failures remain cover-
		// neutral so malformed probes cannot reach a typed carrier response.
		if errors.Is(err, issuerd.ErrTokenAlreadySpent) {
			writeCarrier(w, CarrierTokenSpendConflict, nil)
			return
		}
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	defer zeroCarrierPayload(spentKey)
	writeCarrier(w, CarrierTokenSpendResp, spentKey)
}

// doCarrierExchangeHTTP posts a carrier message to a live server and returns
// the decoded response carrier. Used by the client interop harness.
func doCarrierExchangeHTTP(client *http.Client, url string, reqType CarrierType, payload []byte) (CarrierType, []byte, error) {
	resp, err := client.Post(url, "application/octet-stream", bytes.NewReader(EncodeCarrier(reqType, payload)))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("server: carrier status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		return 0, nil, fmt.Errorf("server: unexpected carrier content-type %q", resp.Header.Get("Content-Type"))
	}
	if resp.ContentLength > int64(maxCarrierBodyBytes) {
		return 0, nil, fmt.Errorf("server: carrier response exceeds limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxCarrierBodyBytes)+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maxCarrierBodyBytes {
		return 0, nil, fmt.Errorf("server: carrier response exceeds limit")
	}
	responseType, responsePayload, err := DecodeCarrier(body)
	if err != nil {
		return 0, nil, err
	}
	maximumPayloadBytes := maxCarrierControlPayloadBytes
	if responseType == CarrierPacketBatch {
		maximumPayloadBytes = maxPacketBatchBytes
	}
	if len(responsePayload) > maximumPayloadBytes {
		return 0, nil, fmt.Errorf("server: carrier response payload exceeds limit")
	}
	return responseType, responsePayload, nil
}

// doCarrierExchangeHandler exchanges a carrier message against an in-process
// handler. Used by the readiness harness.
func doCarrierExchangeHandler(handler http.Handler, reqType CarrierType, payload []byte) (CarrierType, []byte, harnessResponse) {
	resp := serveHarnessRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, EncodeCarrier(reqType, payload), "application/octet-stream")
	if resp.status != http.StatusOK {
		return 0, nil, resp
	}
	respType, respPayload, err := DecodeCarrier(resp.body)
	if err != nil {
		return 0, nil, resp
	}
	return respType, respPayload, resp
}

func zeroCarrierPayload(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
