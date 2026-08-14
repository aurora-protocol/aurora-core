package client

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	nativeProvisioningTrustFormat uint64 = 1
	// MaximumNativeProvisioningTrustBytes bounds a separately configured root set.
	MaximumNativeProvisioningTrustBytes           = 64 << 10
	maximumNativeProvisioningSignedSeedTrustRoots = 16
)

// ErrNativeProvisioningTrustRequired indicates that a provisioning bundle was
// offered without an independently supplied signed-seed trust anchor.
var ErrNativeProvisioningTrustRequired = errors.New("client: native provisioning requires independently configured signed-seed trust")

// NativeProvisioningTrust holds immutable bootstrap roots supplied outside a
// provisioning bundle.
type NativeProvisioningTrust struct {
	roots []protocol.AuthorityKeyRecord
}

// NewNativeProvisioningTrust validates and defensively copies canonical
// signed-seed bootstrap roots.
func NewNativeProvisioningTrust(roots []protocol.AuthorityKeyRecord) (NativeProvisioningTrust, error) {
	if len(roots) == 0 || len(roots) > maximumNativeProvisioningSignedSeedTrustRoots {
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning trust root count is invalid")
	}
	store, err := trust.NewSignedSeedTrustStore(roots)
	if err != nil {
		return NativeProvisioningTrust{}, err
	}
	trustedRoots := store.AuthorityKeys()
	if len(trustedRoots) != len(roots) {
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning trust roots are invalid")
	}
	sortNativeProvisioningAuthorityKeys(trustedRoots)
	return NativeProvisioningTrust{roots: trustedRoots}, nil
}

// EncodeNativeProvisioningTrust encodes a canonical root set for a separately
// authenticated local or application configuration channel.
func EncodeNativeProvisioningTrust(value NativeProvisioningTrust) ([]byte, error) {
	if err := value.validate(); err != nil {
		return nil, fmt.Errorf("client: encode native provisioning trust: %w", err)
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(nativeProvisioningTrustFormat)
	encoder.WriteVarint(uint64(len(value.roots)))
	for _, root := range value.roots {
		root.EncodeTo(encoder)
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("client: encode native provisioning trust: %w", err)
	}
	if len(encoded) > MaximumNativeProvisioningTrustBytes {
		return nil, fmt.Errorf("client: native provisioning trust exceeds size limit")
	}
	return encoded, nil
}

// ParseNativeProvisioningTrust validates a canonical independently supplied
// root-set encoding.
func ParseNativeProvisioningTrust(encoded []byte) (NativeProvisioningTrust, error) {
	if len(encoded) == 0 || len(encoded) > MaximumNativeProvisioningTrustBytes {
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning trust size is invalid")
	}
	reader := wire.NewReader(encoded)
	if format := reader.ReadVarint(); format != nativeProvisioningTrustFormat {
		return NativeProvisioningTrust{}, fmt.Errorf("client: unsupported native provisioning trust format")
	}
	count := reader.ReadVectorCount("native provisioning trust root")
	if reader.Err() != nil || count == 0 || count > maximumNativeProvisioningSignedSeedTrustRoots {
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning trust root count is invalid")
	}
	roots := make([]protocol.AuthorityKeyRecord, 0, count)
	for range count {
		roots = append(roots, protocol.DecodeAuthorityKeyRecord(reader))
	}
	if reader.Err() != nil || !reader.EOF() {
		return NativeProvisioningTrust{}, fmt.Errorf("client: malformed native provisioning trust")
	}
	value, err := NewNativeProvisioningTrust(roots)
	zeroNativeProvisioningAuthorityKeys(roots)
	if err != nil {
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning trust: %w", err)
	}
	canonical, err := EncodeNativeProvisioningTrust(value)
	if err != nil {
		return NativeProvisioningTrust{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		zeroNativeProvisioningBytes(canonical)
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning trust is not canonical")
	}
	zeroNativeProvisioningBytes(canonical)
	return value, nil
}

func (value NativeProvisioningTrust) validate() error {
	if len(value.roots) == 0 || len(value.roots) > maximumNativeProvisioningSignedSeedTrustRoots {
		return ErrNativeProvisioningTrustRequired
	}
	store, err := trust.NewSignedSeedTrustStore(value.roots)
	if err != nil {
		return err
	}
	roots := store.AuthorityKeys()
	defer zeroNativeProvisioningAuthorityKeys(roots)
	if !nativeProvisioningAuthorityKeysEqual(value.roots, roots) {
		return fmt.Errorf("client: native provisioning trust roots are not canonical")
	}
	return nil
}

func (value NativeProvisioningTrust) newStore() (*trust.SignedSeedTrustStore, error) {
	if err := value.validate(); err != nil {
		return nil, err
	}
	return trust.NewSignedSeedTrustStore(value.roots)
}

func sortNativeProvisioningAuthorityKeys(keys []protocol.AuthorityKeyRecord) {
	sort.Slice(keys, func(left, right int) bool {
		leftEncoded, leftErr := protocol.Encode(keys[left])
		rightEncoded, rightErr := protocol.Encode(keys[right])
		if leftErr != nil || rightErr != nil {
			return false
		}
		defer zeroNativeProvisioningBytes(leftEncoded)
		defer zeroNativeProvisioningBytes(rightEncoded)
		return bytes.Compare(leftEncoded, rightEncoded) < 0
	})
}

func nativeProvisioningAuthorityKeysEqual(left, right []protocol.AuthorityKeyRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		leftEncoded, leftErr := protocol.Encode(left[index])
		rightEncoded, rightErr := protocol.Encode(right[index])
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftEncoded, rightEncoded) {
			zeroNativeProvisioningBytes(leftEncoded)
			zeroNativeProvisioningBytes(rightEncoded)
			return false
		}
		zeroNativeProvisioningBytes(leftEncoded)
		zeroNativeProvisioningBytes(rightEncoded)
	}
	return true
}

func zeroNativeProvisioningAuthorityKeys(keys []protocol.AuthorityKeyRecord) {
	for index := range keys {
		zeroNativeProvisioningBytes(keys[index].AuthorityID)
		zeroNativeProvisioningBytes(keys[index].AuthorityKeyID)
		zeroNativeProvisioningBytes(keys[index].PublicKey.PublicKey)
	}
}

func cloneNativeProvisioningAuthorityKeys(keys []protocol.AuthorityKeyRecord) []protocol.AuthorityKeyRecord {
	cloned := make([]protocol.AuthorityKeyRecord, len(keys))
	for index, key := range keys {
		cloned[index] = key
		cloned[index].AuthorityID = append([]byte(nil), key.AuthorityID...)
		cloned[index].AuthorityKeyID = append([]byte(nil), key.AuthorityKeyID...)
		cloned[index].PublicKey.PublicKey = append([]byte(nil), key.PublicKey.PublicKey...)
	}
	return cloned
}
