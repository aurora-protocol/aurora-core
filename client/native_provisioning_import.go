package client

import (
	"encoding/binary"
	"fmt"
)

const (
	nativeProvisioningImportSourceLengthBytes = 4
	nativeProvisioningImportCountBytes        = 1
	// NativeProvisioningImportSpentHintKeyBytes is the fixed spent-hint-key
	// field width in the import envelope.
	NativeProvisioningImportSpentHintKeyBytes = 48
	// MaximumNativeProvisioningImportSpentHintKeys bounds the spent-hint-key
	// list in one import envelope.
	MaximumNativeProvisioningImportSpentHintKeys = 64
	// MaximumNativeProvisioningImportEnvelopeBytes bounds a complete import
	// envelope: one bounded provisioning source plus the bounded spent-key
	// list.
	MaximumNativeProvisioningImportEnvelopeBytes = MaximumNativeProvisioningWalletBytes + nativeProvisioningImportSourceLengthBytes + nativeProvisioningImportCountBytes + MaximumNativeProvisioningImportSpentHintKeys*NativeProvisioningImportSpentHintKeyBytes
)

// The native provisioning import envelope is the mobile-FFI interchange
// format for moving a provisioning source (single bundle or wallet) plus the
// spent hint keys a client must skip into a client application, typically as
// canonical base64 pasted into an "import provisioning code" field. It is a
// local interchange envelope, not an Aurora network message. Layout:
//
//	uint32-BE sourceLength || source || uint8 spentKeyCount || count×48-byte spent hint keys

// EncodeNativeProvisioningImportEnvelope encodes one bounded provisioning
// source and its spent hint keys into the canonical import envelope.
func EncodeNativeProvisioningImportEnvelope(source []byte, spentHintKeys [][]byte) ([]byte, error) {
	if len(source) == 0 || len(source) > MaximumNativeProvisioningWalletBytes || len(spentHintKeys) > MaximumNativeProvisioningImportSpentHintKeys {
		return nil, fmt.Errorf("client: native provisioning import envelope is invalid")
	}
	encoded := make([]byte, nativeProvisioningImportSourceLengthBytes+len(source)+nativeProvisioningImportCountBytes+len(spentHintKeys)*NativeProvisioningImportSpentHintKeyBytes)
	binary.BigEndian.PutUint32(encoded[:nativeProvisioningImportSourceLengthBytes], uint32(len(source)))
	copy(encoded[nativeProvisioningImportSourceLengthBytes:], source)
	offset := nativeProvisioningImportSourceLengthBytes + len(source)
	encoded[offset] = byte(len(spentHintKeys))
	offset += nativeProvisioningImportCountBytes
	for _, spentHintKey := range spentHintKeys {
		if len(spentHintKey) != NativeProvisioningImportSpentHintKeyBytes {
			zeroNativeProvisioningBytes(encoded)
			return nil, fmt.Errorf("client: native provisioning import envelope spent hint key is invalid")
		}
		copy(encoded[offset:], spentHintKey)
		offset += NativeProvisioningImportSpentHintKeyBytes
	}
	return encoded, nil
}

// DecodeNativeProvisioningImportEnvelope validates one canonical import
// envelope. The returned source and spent hint keys are caller-owned copies
// (not aliases of encoded), so the caller may erase encoded immediately and
// must erase the returned values when done.
func DecodeNativeProvisioningImportEnvelope(encoded []byte) ([]byte, [][]byte, error) {
	if len(encoded) < nativeProvisioningImportSourceLengthBytes+nativeProvisioningImportCountBytes || len(encoded) > MaximumNativeProvisioningImportEnvelopeBytes {
		return nil, nil, fmt.Errorf("client: native provisioning import envelope size is invalid")
	}
	encodedSourceLength := binary.BigEndian.Uint32(encoded[:nativeProvisioningImportSourceLengthBytes])
	if encodedSourceLength == 0 || uint64(encodedSourceLength) > uint64(MaximumNativeProvisioningWalletBytes) {
		return nil, nil, fmt.Errorf("client: native provisioning import envelope source is invalid")
	}
	sourceLength := int(encodedSourceLength)
	offset := nativeProvisioningImportSourceLengthBytes
	if sourceLength > len(encoded)-offset-nativeProvisioningImportCountBytes {
		return nil, nil, fmt.Errorf("client: native provisioning import envelope source is truncated")
	}
	source := append([]byte(nil), encoded[offset:offset+sourceLength]...)
	offset += sourceLength
	count := int(encoded[offset])
	offset += nativeProvisioningImportCountBytes
	if count > MaximumNativeProvisioningImportSpentHintKeys || len(encoded)-offset != count*NativeProvisioningImportSpentHintKeyBytes {
		zeroNativeProvisioningBytes(source)
		return nil, nil, fmt.Errorf("client: native provisioning import envelope spent hint keys are invalid")
	}
	spentHintKeys := make([][]byte, count)
	for index := range count {
		spentHintKeys[index] = append([]byte(nil), encoded[offset:offset+NativeProvisioningImportSpentHintKeyBytes]...)
		offset += NativeProvisioningImportSpentHintKeyBytes
	}
	return source, spentHintKeys, nil
}
