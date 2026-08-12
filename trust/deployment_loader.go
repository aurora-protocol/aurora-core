package trust

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

const maximumCanonicalDeploymentObjectBytes = 1 << 20

// CanonicalRelayDeploymentInput supplies trusted deployment objects in complete canonical encodings.
type CanonicalRelayDeploymentInput struct {
	Descriptor               []byte
	TrustedDescriptorHash    []byte
	Template                 []byte
	TemplateAuthorityKey     []byte
	RequestClassID           uint64
	Suite                    uint64
	Method                   uint64
	NowUnix                  uint64
	MaxTemplateFutureSkew    uint64
	RequirePQDescriptorProof bool
}

// VerifyCanonicalRelayDeployment decodes complete canonical objects and verifies their deployment binding.
func VerifyCanonicalRelayDeployment(input CanonicalRelayDeploymentInput) (VerifiedRelayDeployment, error) {
	descriptor, err := decodeCanonicalRelayDescriptor(input.Descriptor)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	template, err := decodeCanonicalCoverTemplate(input.Template)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	authorityKey, err := decodeCanonicalPublicKeyRecord(input.TemplateAuthorityKey)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	if len(input.TrustedDescriptorHash) != 48 {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: trusted relay descriptor hash length is invalid")
	}
	return VerifyRelayDeployment(RelayDeploymentVerification{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    append([]byte(nil), input.TrustedDescriptorHash...),
		Template:                 template,
		TemplateAuthorityKey:     authorityKey,
		RequestClassID:           input.RequestClassID,
		Suite:                    input.Suite,
		Method:                   input.Method,
		NowUnix:                  input.NowUnix,
		MaxTemplateFutureSkew:    input.MaxTemplateFutureSkew,
		RequirePQDescriptorProof: input.RequirePQDescriptorProof,
	})
}

func decodeCanonicalRelayDescriptor(encoded []byte) (protocol.RelayDescriptor, error) {
	if err := validateCanonicalDeploymentObject(encoded); err != nil {
		return protocol.RelayDescriptor{}, fmt.Errorf("trust: canonical relay descriptor: %w", err)
	}
	reader := wire.NewReader(encoded)
	descriptor := protocol.DecodeRelayDescriptor(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.RelayDescriptor{}, fmt.Errorf("trust: canonical relay descriptor is malformed")
	}
	return descriptor, nil
}

func decodeCanonicalCoverTemplate(encoded []byte) (protocol.CoverTemplate, error) {
	if err := validateCanonicalDeploymentObject(encoded); err != nil {
		return protocol.CoverTemplate{}, fmt.Errorf("trust: canonical cover template: %w", err)
	}
	reader := wire.NewReader(encoded)
	template := protocol.DecodeCoverTemplate(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.CoverTemplate{}, fmt.Errorf("trust: canonical cover template is malformed")
	}
	return template, nil
}

func decodeCanonicalPublicKeyRecord(encoded []byte) (protocol.PublicKeyRecord, error) {
	if err := validateCanonicalDeploymentObject(encoded); err != nil {
		return protocol.PublicKeyRecord{}, fmt.Errorf("trust: canonical template authority key: %w", err)
	}
	reader := wire.NewReader(encoded)
	key := protocol.DecodePublicKeyRecord(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.PublicKeyRecord{}, fmt.Errorf("trust: canonical template authority key is malformed")
	}
	return key, nil
}

func validateCanonicalDeploymentObject(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maximumCanonicalDeploymentObjectBytes {
		return fmt.Errorf("object length is invalid")
	}
	return nil
}
