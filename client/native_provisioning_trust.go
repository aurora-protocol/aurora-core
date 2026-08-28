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
	nativeProvisioningTrustFormat uint64 = 2
	// MaximumNativeProvisioningTrustBytes bounds a separately configured root
	// and deployment trust set.
	MaximumNativeProvisioningTrustBytes           = 64 << 10
	maximumNativeProvisioningSignedSeedTrustRoots = 16
	maximumNativeProvisioningDeploymentTrusts     = 256
)

// ErrNativeProvisioningTrustRequired indicates that a provisioning bundle was
// offered without an independently supplied signed-seed trust anchor.
var ErrNativeProvisioningTrustRequired = errors.New("client: native provisioning requires independently configured signed-seed trust")

// ErrNativeProvisioningDeploymentTrustRequired indicates that a provisioning
// bundle's relay deployment was not authorized outside the bundle itself.
var ErrNativeProvisioningDeploymentTrustRequired = errors.New("client: native provisioning requires independently configured relay deployment trust")

// NativeProvisioningDeploymentTrust binds a relay descriptor and cover
// template to the template authority key that authenticated the template.
// These values must come from a verified directory, BridgeBundle, or another
// authenticated local configuration channel rather than the provisioning
// bundle that they authorize.
type NativeProvisioningDeploymentTrust struct {
	DescriptorHash       []byte
	CoverTemplateHash    []byte
	TemplateAuthorityKey protocol.PublicKeyRecord
}

// NativeProvisioningTrust holds immutable bootstrap roots and relay deployment
// commitments supplied outside a provisioning bundle.
type NativeProvisioningTrust struct {
	roots       []protocol.AuthorityKeyRecord
	deployments []NativeProvisioningDeploymentTrust
}

// NewNativeProvisioningTrust validates and defensively copies canonical
// signed-seed bootstrap roots and independently authenticated deployments.
// A root-only value remains useful for signed-seed and issuer validation, but
// complete native provisioning validation requires a matching deployment.
func NewNativeProvisioningTrust(roots []protocol.AuthorityKeyRecord, deployments ...NativeProvisioningDeploymentTrust) (NativeProvisioningTrust, error) {
	if len(roots) == 0 || len(roots) > maximumNativeProvisioningSignedSeedTrustRoots {
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning trust root count is invalid")
	}
	if len(deployments) > maximumNativeProvisioningDeploymentTrusts {
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning deployment trust count is invalid")
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
	trustedDeployments := cloneNativeProvisioningDeploymentTrusts(deployments)
	if err := validateNativeProvisioningDeploymentTrusts(trustedDeployments); err != nil {
		zeroNativeProvisioningDeploymentTrusts(trustedDeployments)
		return NativeProvisioningTrust{}, err
	}
	sortNativeProvisioningDeploymentTrusts(trustedDeployments)
	return NativeProvisioningTrust{roots: trustedRoots, deployments: trustedDeployments}, nil
}

// EncodeNativeProvisioningTrust encodes canonical root and deployment trust
// sets for a separately authenticated local or application configuration
// channel.
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
	encoder.WriteVarint(uint64(len(value.deployments)))
	for _, deployment := range value.deployments {
		encoder.WritePreHash(deployment.DescriptorHash)
		encoder.WritePreHash(deployment.CoverTemplateHash)
		deployment.TemplateAuthorityKey.EncodeTo(encoder)
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
	deploymentCount := reader.ReadVectorCount("native provisioning deployment trust")
	if reader.Err() != nil || deploymentCount > maximumNativeProvisioningDeploymentTrusts {
		zeroNativeProvisioningAuthorityKeys(roots)
		return NativeProvisioningTrust{}, fmt.Errorf("client: native provisioning deployment trust count is invalid")
	}
	deployments := make([]NativeProvisioningDeploymentTrust, 0, deploymentCount)
	for range deploymentCount {
		deployments = append(deployments, NativeProvisioningDeploymentTrust{
			DescriptorHash:       reader.ReadPreHash(),
			CoverTemplateHash:    reader.ReadPreHash(),
			TemplateAuthorityKey: protocol.DecodePublicKeyRecord(reader),
		})
	}
	if reader.Err() != nil || !reader.EOF() {
		zeroNativeProvisioningAuthorityKeys(roots)
		zeroNativeProvisioningDeploymentTrusts(deployments)
		return NativeProvisioningTrust{}, fmt.Errorf("client: malformed native provisioning trust")
	}
	value, err := NewNativeProvisioningTrust(roots, deployments...)
	zeroNativeProvisioningAuthorityKeys(roots)
	zeroNativeProvisioningDeploymentTrusts(deployments)
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
	if len(value.deployments) > maximumNativeProvisioningDeploymentTrusts {
		return fmt.Errorf("client: native provisioning deployment trust count is invalid")
	}
	deployments := cloneNativeProvisioningDeploymentTrusts(value.deployments)
	defer zeroNativeProvisioningDeploymentTrusts(deployments)
	if err := validateNativeProvisioningDeploymentTrusts(deployments); err != nil {
		return err
	}
	sortNativeProvisioningDeploymentTrusts(deployments)
	if !nativeProvisioningDeploymentTrustsEqual(value.deployments, deployments) {
		return fmt.Errorf("client: native provisioning deployment trust is not canonical")
	}
	return nil
}

func (value NativeProvisioningTrust) newStore() (*trust.SignedSeedTrustStore, error) {
	if err := value.validate(); err != nil {
		return nil, err
	}
	return trust.NewSignedSeedTrustStore(value.roots)
}

func (value NativeProvisioningTrust) authorizeDeployment(descriptorHash, templateHash []byte, authorityKey protocol.PublicKeyRecord) (NativeProvisioningDeploymentTrust, error) {
	if err := value.validate(); err != nil {
		return NativeProvisioningDeploymentTrust{}, err
	}
	if len(value.deployments) == 0 {
		return NativeProvisioningDeploymentTrust{}, ErrNativeProvisioningDeploymentTrustRequired
	}
	for _, deployment := range value.deployments {
		if bytes.Equal(deployment.DescriptorHash, descriptorHash) &&
			bytes.Equal(deployment.CoverTemplateHash, templateHash) &&
			nativeProvisioningPublicKeysEqual(deployment.TemplateAuthorityKey, authorityKey) {
			return cloneNativeProvisioningDeploymentTrusts([]NativeProvisioningDeploymentTrust{deployment})[0], nil
		}
	}
	return NativeProvisioningDeploymentTrust{}, fmt.Errorf("client: native provisioning relay deployment is not independently trusted")
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

func sortNativeProvisioningDeploymentTrusts(deployments []NativeProvisioningDeploymentTrust) {
	sort.Slice(deployments, func(left, right int) bool {
		if compared := bytes.Compare(deployments[left].DescriptorHash, deployments[right].DescriptorHash); compared != 0 {
			return compared < 0
		}
		if compared := bytes.Compare(deployments[left].CoverTemplateHash, deployments[right].CoverTemplateHash); compared != 0 {
			return compared < 0
		}
		leftKey, leftErr := protocol.Encode(deployments[left].TemplateAuthorityKey)
		rightKey, rightErr := protocol.Encode(deployments[right].TemplateAuthorityKey)
		if leftErr != nil || rightErr != nil {
			return false
		}
		defer zeroNativeProvisioningBytes(leftKey)
		defer zeroNativeProvisioningBytes(rightKey)
		return bytes.Compare(leftKey, rightKey) < 0
	})
}

func validateNativeProvisioningDeploymentTrusts(deployments []NativeProvisioningDeploymentTrust) error {
	for index, deployment := range deployments {
		if !hasNativeNonZeroPreHash(deployment.DescriptorHash) || !hasNativeNonZeroPreHash(deployment.CoverTemplateHash) {
			return fmt.Errorf("client: native provisioning deployment trust hash is invalid")
		}
		if err := deployment.TemplateAuthorityKey.ValidateCompatibility(); err != nil {
			return fmt.Errorf("client: native provisioning deployment template authority key: %w", err)
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(deployment.DescriptorHash, deployments[previous].DescriptorHash) &&
				bytes.Equal(deployment.CoverTemplateHash, deployments[previous].CoverTemplateHash) &&
				nativeProvisioningPublicKeysEqual(deployment.TemplateAuthorityKey, deployments[previous].TemplateAuthorityKey) {
				return fmt.Errorf("client: duplicate native provisioning deployment trust")
			}
		}
	}
	return nil
}

func nativeProvisioningDeploymentTrustsEqual(left, right []NativeProvisioningDeploymentTrust) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index].DescriptorHash, right[index].DescriptorHash) ||
			!bytes.Equal(left[index].CoverTemplateHash, right[index].CoverTemplateHash) ||
			!nativeProvisioningPublicKeysEqual(left[index].TemplateAuthorityKey, right[index].TemplateAuthorityKey) {
			return false
		}
	}
	return true
}

func nativeProvisioningPublicKeysEqual(left, right protocol.PublicKeyRecord) bool {
	return left.SignatureScheme == right.SignatureScheme &&
		left.KeyEncoding == right.KeyEncoding &&
		bytes.Equal(left.PublicKey, right.PublicKey)
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

func zeroNativeProvisioningDeploymentTrusts(deployments []NativeProvisioningDeploymentTrust) {
	for index := range deployments {
		zeroNativeProvisioningBytes(deployments[index].DescriptorHash)
		zeroNativeProvisioningBytes(deployments[index].CoverTemplateHash)
		zeroNativeProvisioningBytes(deployments[index].TemplateAuthorityKey.PublicKey)
	}
}

func cloneNativeProvisioningDeploymentTrusts(deployments []NativeProvisioningDeploymentTrust) []NativeProvisioningDeploymentTrust {
	cloned := make([]NativeProvisioningDeploymentTrust, len(deployments))
	for index, deployment := range deployments {
		cloned[index] = NativeProvisioningDeploymentTrust{
			DescriptorHash:    append([]byte(nil), deployment.DescriptorHash...),
			CoverTemplateHash: append([]byte(nil), deployment.CoverTemplateHash...),
			TemplateAuthorityKey: protocol.PublicKeyRecord{
				SignatureScheme: deployment.TemplateAuthorityKey.SignatureScheme,
				KeyEncoding:     deployment.TemplateAuthorityKey.KeyEncoding,
				PublicKey:       append([]byte(nil), deployment.TemplateAuthorityKey.PublicKey...),
			},
		}
	}
	return cloned
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
