package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/relay"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

// CarrierType identifies the cover-carrier message kind multiplexed over the
// single application/octet-stream cover surface (DefaultPacketExchangePath).
//
// Issuance shares the same cover-neutral carrier as packet exchange. This
// implements the Section 27.2 "cover-issuance" transport: there is no
// distinguishable public issuer or health path on the Aurora wire. An
// adversarial probe that does not carry a well-formed carrier message falls
// through to byte-identical cover-origin behaviour, exactly like an invalid
// packet batch. A response is only produced for a holder of the matching
// carrier payload (e.g. a valid encrypted packet batch or a parseable issuance
// message).
type CarrierType uint8

const (
	// CarrierPacketBatch carries an encoded PacketBatch (the P6/P8 packet slot).
	CarrierPacketBatch CarrierType = 0x01
	// CarrierIssuerMetadataReq requests published IssuerMetadata. Empty payload.
	CarrierIssuerMetadataReq CarrierType = 0x02
	// CarrierIssuerMetadataResp carries encoded IssuerMetadata plus its hash.
	CarrierIssuerMetadataResp CarrierType = 0x03
	// CarrierBlindRSAIssueReq requests a Blind RSA admission token.
	CarrierBlindRSAIssueReq CarrierType = 0x04
	// CarrierBlindRSAIssueResp carries the encoded AdmissionProof.
	CarrierBlindRSAIssueResp CarrierType = 0x05
	// CarrierTokenSpendReq spends a previously issued AdmissionProof.
	CarrierTokenSpendReq CarrierType = 0x06
	// CarrierTokenSpendResp carries the resulting token_spent_key.
	CarrierTokenSpendResp CarrierType = 0x07
	// CarrierTokenSpendConflict reports a replayed (already-spent) token. It is
	// only reachable by a holder of a valid AdmissionProof, so it is not an
	// adversary-observable distinguisher.
	CarrierTokenSpendConflict CarrierType = 0x08
)

const (
	carrierTokenNonceLen        = 32
	carrierRedemptionContextLen = 48
	carrierIssueRequestLen      = carrierTokenNonceLen + carrierRedemptionContextLen + 8
	carrierSpentKeyLen          = 48
	carrierMetadataHashLen      = 48
	maxCarrierBodyBytes         = 1 << 20
)

// IssuerCarrier is the minimal issuer capability the cover carrier forwards to.
// The relay carries issuance over its cover surface and delegates the actual
// admission logic to the issuer trust domain; it never reimplements it.
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
	if c.service == nil {
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
	if c.service == nil {
		return nil, fmt.Errorf("server: issuer unavailable")
	}
	proof, err := issuerd.DecodeAdmissionProofBytes(admissionProof)
	if err != nil {
		return nil, err
	}
	return c.service.SpendToken(proof)
}

func EncodeCarrier(t CarrierType, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(t)
	copy(out[1:], payload)
	return out
}

func DecodeCarrier(body []byte) (CarrierType, []byte, error) {
	if len(body) < 1 {
		return 0, nil, fmt.Errorf("server: empty carrier body")
	}
	return CarrierType(body[0]), body[1:], nil
}

func EncodeCarrierIssueRequest(tokenNonce, redemptionContextHash []byte, expiryUnix uint64) ([]byte, error) {
	if len(tokenNonce) != carrierTokenNonceLen {
		return nil, fmt.Errorf("server: token nonce length %d, want %d", len(tokenNonce), carrierTokenNonceLen)
	}
	if len(redemptionContextHash) != carrierRedemptionContextLen {
		return nil, fmt.Errorf("server: redemption context length %d, want %d", len(redemptionContextHash), carrierRedemptionContextLen)
	}
	out := make([]byte, carrierIssueRequestLen)
	copy(out[:carrierTokenNonceLen], tokenNonce)
	copy(out[carrierTokenNonceLen:carrierTokenNonceLen+carrierRedemptionContextLen], redemptionContextHash)
	binary.BigEndian.PutUint64(out[carrierTokenNonceLen+carrierRedemptionContextLen:], expiryUnix)
	return out, nil
}

func DecodeCarrierIssueRequest(payload []byte) (tokenNonce, redemptionContextHash []byte, expiryUnix uint64, err error) {
	if len(payload) != carrierIssueRequestLen {
		return nil, nil, 0, fmt.Errorf("server: issue request length %d, want %d", len(payload), carrierIssueRequestLen)
	}
	tokenNonce = append([]byte(nil), payload[:carrierTokenNonceLen]...)
	redemptionContextHash = append([]byte(nil), payload[carrierTokenNonceLen:carrierTokenNonceLen+carrierRedemptionContextLen]...)
	expiryUnix = binary.BigEndian.Uint64(payload[carrierTokenNonceLen+carrierRedemptionContextLen:])
	return tokenNonce, redemptionContextHash, expiryUnix, nil
}

func EncodeCarrierMetadataResponse(encoded, hash []byte) ([]byte, error) {
	if len(hash) != carrierMetadataHashLen {
		return nil, fmt.Errorf("server: issuer metadata hash length %d, want %d", len(hash), carrierMetadataHashLen)
	}
	out := make([]byte, 4+len(encoded)+carrierMetadataHashLen)
	binary.BigEndian.PutUint32(out[:4], uint32(len(encoded)))
	copy(out[4:4+len(encoded)], encoded)
	copy(out[4+len(encoded):], hash)
	return out, nil
}

func DecodeCarrierMetadataResponse(payload []byte) (encoded, hash []byte, err error) {
	if len(payload) < 4 {
		return nil, nil, fmt.Errorf("server: metadata response missing length")
	}
	n := int(binary.BigEndian.Uint32(payload[:4]))
	if len(payload) != 4+n+carrierMetadataHashLen {
		return nil, nil, fmt.Errorf("server: metadata response length mismatch")
	}
	encoded = append([]byte(nil), payload[4:4+n]...)
	hash = append([]byte(nil), payload[4+n:]...)
	return encoded, hash, nil
}

// serveCoverCarrier reads the carrier body and dispatches by message type. Any
// malformed body, unknown type, or downstream failure maps to cover-neutral
// behaviour so the surface is indistinguishable from an ordinary origin.
func serveCoverCarrier(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, exchanger PacketExchanger, issuer IssuerCarrier) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCarrierBodyBytes+1))
	if err != nil || len(body) > maxCarrierBodyBytes {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	carrierType, payload, err := DecodeCarrier(body)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	switch carrierType {
	case CarrierPacketBatch:
		serveCarrierPacketBatch(w, r, origin, coverOrigin, exchanger, payload)
	case CarrierIssuerMetadataReq:
		serveCarrierIssuerMetadata(w, r, origin, coverOrigin, issuer)
	case CarrierBlindRSAIssueReq:
		serveCarrierBlindRSAIssue(w, r, origin, coverOrigin, issuer, payload)
	case CarrierTokenSpendReq:
		serveCarrierTokenSpend(w, r, origin, coverOrigin, issuer, payload)
	default:
		serveCoverFailure(w, r, origin, coverOrigin)
	}
}

func writeCarrier(w http.ResponseWriter, t CarrierType, payload []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(EncodeCarrier(t, payload))
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
	outbound, err := exchanger.ExchangePacketBatch(inbound)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	encoded, err := EncodePacketBatch(outbound)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
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
	proof, err := issuer.IssueBlindRSA(tokenNonce, redemptionContextHash, expiryUnix)
	if err != nil {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	writeCarrier(w, CarrierBlindRSAIssueResp, proof)
}

func serveCarrierTokenSpend(w http.ResponseWriter, r *http.Request, origin relay.Origin, coverOrigin http.Handler, issuer IssuerCarrier, payload []byte) {
	if issuer == nil || len(payload) == 0 {
		serveCoverFailure(w, r, origin, coverOrigin)
		return
	}
	spentKey, err := issuer.SpendToken(payload)
	if err != nil {
		// A decodeable proof that fails to spend is a replay (already spent).
		// Report it in-band; only a holder of a valid proof can reach here.
		writeCarrier(w, CarrierTokenSpendConflict, nil)
		return
	}
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCarrierBodyBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("server: carrier status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		return 0, nil, fmt.Errorf("server: unexpected carrier content-type %q", resp.Header.Get("Content-Type"))
	}
	return DecodeCarrier(body)
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
