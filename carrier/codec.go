package carrier

import (
	"encoding/binary"
	"fmt"
)

// Type identifies a message carried over the opaque cover exchange surface.
type Type uint8

const (
	PacketBatch            Type = 0x01
	IssuerMetadataRequest  Type = 0x02
	IssuerMetadataResponse Type = 0x03
	BlindRSAIssueRequest   Type = 0x04
	BlindRSAIssueResponse  Type = 0x05
	TokenSpendRequest      Type = 0x06
	TokenSpendResponse     Type = 0x07
	TokenSpendConflict     Type = 0x08
)

const (
	TokenNonceLength        = 32
	RedemptionContextLength = 48
	issueRequestLength      = TokenNonceLength + RedemptionContextLength + 8
	metadataHashLength      = 48
)

func Encode(kind Type, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(kind)
	copy(out[1:], payload)
	return out
}

func Decode(body []byte) (Type, []byte, error) {
	if len(body) < 1 {
		return 0, nil, fmt.Errorf("carrier: empty body")
	}
	return Type(body[0]), body[1:], nil
}

func EncodeIssueRequest(tokenNonce, redemptionContextHash []byte, expiryUnix uint64) ([]byte, error) {
	if len(tokenNonce) != TokenNonceLength {
		return nil, fmt.Errorf("carrier: token nonce length %d, want %d", len(tokenNonce), TokenNonceLength)
	}
	if len(redemptionContextHash) != RedemptionContextLength {
		return nil, fmt.Errorf("carrier: redemption context length %d, want %d", len(redemptionContextHash), RedemptionContextLength)
	}
	out := make([]byte, issueRequestLength)
	copy(out[:TokenNonceLength], tokenNonce)
	copy(out[TokenNonceLength:TokenNonceLength+RedemptionContextLength], redemptionContextHash)
	binary.BigEndian.PutUint64(out[TokenNonceLength+RedemptionContextLength:], expiryUnix)
	return out, nil
}

func DecodeIssueRequest(payload []byte) (tokenNonce, redemptionContextHash []byte, expiryUnix uint64, err error) {
	if len(payload) != issueRequestLength {
		return nil, nil, 0, fmt.Errorf("carrier: issue request length %d, want %d", len(payload), issueRequestLength)
	}
	tokenNonce = append([]byte(nil), payload[:TokenNonceLength]...)
	redemptionContextHash = append([]byte(nil), payload[TokenNonceLength:TokenNonceLength+RedemptionContextLength]...)
	expiryUnix = binary.BigEndian.Uint64(payload[TokenNonceLength+RedemptionContextLength:])
	return tokenNonce, redemptionContextHash, expiryUnix, nil
}

func EncodeMetadataResponse(encoded, hash []byte) ([]byte, error) {
	if len(hash) != metadataHashLength {
		return nil, fmt.Errorf("carrier: issuer metadata hash length is invalid")
	}
	out := make([]byte, 4+len(encoded)+len(hash))
	binary.BigEndian.PutUint32(out[:4], uint32(len(encoded)))
	copy(out[4:4+len(encoded)], encoded)
	copy(out[4+len(encoded):], hash)
	return out, nil
}

func DecodeMetadataResponse(payload []byte) (encoded, hash []byte, err error) {
	if len(payload) < 4 {
		return nil, nil, fmt.Errorf("carrier: metadata response missing length")
	}
	length := int(binary.BigEndian.Uint32(payload[:4]))
	if len(payload) != 4+length+metadataHashLength {
		return nil, nil, fmt.Errorf("carrier: metadata response length mismatch")
	}
	encoded = append([]byte(nil), payload[4:4+length]...)
	hash = append([]byte(nil), payload[4+length:]...)
	return encoded, hash, nil
}
