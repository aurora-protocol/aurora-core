package admission

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/wire"
)

const maximumAccessHintCredentialSet = 4096

// EncodeAccessHintCredential returns the canonical binary encoding of one access hint credential.
func EncodeAccessHintCredential(credential AccessHintCredential) ([]byte, error) {
	if err := credential.validate(); err != nil {
		return nil, err
	}
	encoder := wire.NewEncoder()
	encodeAccessHintCredential(encoder, credential)
	return encoder.Bytes()
}

// DecodeAccessHintCredential decodes one complete canonical access hint credential.
func DecodeAccessHintCredential(encoded []byte) (AccessHintCredential, error) {
	reader := wire.NewReader(encoded)
	credential := decodeAccessHintCredential(reader)
	if err := reader.Err(); err != nil || !reader.EOF() {
		return AccessHintCredential{}, fmt.Errorf("admission: malformed access hint credential")
	}
	if err := credential.validate(); err != nil {
		return AccessHintCredential{}, err
	}
	return credential, nil
}

// EncodeAccessHintCredentialSet returns a bounded canonical credential set for static relay lookup.
func EncodeAccessHintCredentialSet(credentials []AccessHintCredential) ([]byte, error) {
	if len(credentials) == 0 || len(credentials) > maximumAccessHintCredentialSet {
		return nil, fmt.Errorf("admission: access hint credential count is invalid")
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(uint64(len(credentials)))
	for _, credential := range credentials {
		if err := credential.validate(); err != nil {
			return nil, err
		}
		encodeAccessHintCredential(encoder, credential)
	}
	return encoder.Bytes()
}

// DecodeAccessHintCredentialSet decodes a complete bounded canonical credential set.
func DecodeAccessHintCredentialSet(encoded []byte) ([]AccessHintCredential, error) {
	reader := wire.NewReader(encoded)
	count := reader.ReadVectorCount("access hint credential")
	if reader.Err() != nil || count == 0 || count > maximumAccessHintCredentialSet {
		return nil, fmt.Errorf("admission: access hint credential count is invalid")
	}
	credentials := make([]AccessHintCredential, 0, count)
	for range count {
		credential := decodeAccessHintCredential(reader)
		if err := reader.Err(); err != nil {
			return nil, fmt.Errorf("admission: malformed access hint credential")
		}
		if err := credential.validate(); err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	if !reader.EOF() {
		return nil, fmt.Errorf("admission: malformed access hint credential set")
	}
	return credentials, nil
}

func encodeAccessHintCredential(encoder *wire.Encoder, credential AccessHintCredential) {
	encoder.WriteOpaqueFixed(credential.HintIssuerID, 16)
	encoder.WriteOpaqueFixed(credential.RelayBucketID, 16)
	encoder.WriteUint64(credential.HintEpochID)
	encoder.WriteOpaqueFixed(credential.HintSelector, 16)
	encoder.WriteOpaqueFixed(credential.HintSecret, 32)
	encoder.WriteUint64(credential.ExpiryUnix)
	encoder.WriteUint16(credential.MaxUses)
}

func decodeAccessHintCredential(reader *wire.Reader) AccessHintCredential {
	return AccessHintCredential{
		HintIssuerID:  reader.ReadOpaqueFixed(16),
		RelayBucketID: reader.ReadOpaqueFixed(16),
		HintEpochID:   reader.ReadUint64(),
		HintSelector:  reader.ReadOpaqueFixed(16),
		HintSecret:    reader.ReadOpaqueFixed(32),
		ExpiryUnix:    reader.ReadUint64(),
		MaxUses:       reader.ReadUint16(),
	}
}
