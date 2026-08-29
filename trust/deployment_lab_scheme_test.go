package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func ed25519LabRecord(t *testing.T) (protocol.PublicKeyRecord, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigEd25519Lab,
		KeyEncoding:     registry.KeyEd25519RawPublic,
		PublicKey:       append([]byte(nil), public...),
	}, private
}

func requireLabSchemeRejection(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "lab") {
		t.Fatalf("%s: production deployment accepted a lab signature scheme: err = %v", label, err)
	}
}

// The production relay-deployment verifier already rejects lab suites and
// non-HTTP/2 methods; the lab-only Ed25519 signature scheme must be rejected
// on every key it accepts too, matching signed-seed and issuer-metadata trust.
func TestVerifyRelayDeploymentRejectsLabSignatureSchemes(t *testing.T) {
	t.Run("long-term classical key", func(t *testing.T) {
		input := newDeploymentFixture(t).input
		record, private := ed25519LabRecord(t)
		descriptor := input.Descriptor
		descriptor.RelayLongtermClassicalKey = record
		descriptor.SignatureByLongtermPQ = nil
		descriptorInput, err := RelayDescriptorSignatureInput(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.SignatureByLongtermClassical = ed25519.Sign(private, descriptorInput)
		descriptorHash, err := RelayDescriptorHash(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		template := input.Template
		instanceInput, err := CoverTemplateInstanceSignatureInput(descriptorHash, template)
		if err != nil {
			t.Fatal(err)
		}
		template.TemplateInstanceSignature = ed25519.Sign(private, instanceInput)
		input.Descriptor = descriptor
		input.TrustedDescriptorHash = descriptorHash
		input.Template = template
		input.RequirePQDescriptorProof = false
		_, err = VerifyRelayDeployment(input)
		requireLabSchemeRejection(t, "long-term classical", err)
	})

	t.Run("epoch classical key", func(t *testing.T) {
		descriptor := newDeploymentFixture(t).input.Descriptor
		record, _ := ed25519LabRecord(t)
		descriptor.EpochAuthClassicalKey = record
		requireLabSchemeRejection(t, "epoch classical", validateDeploymentDescriptor(descriptor, deploymentNow))
	})

	t.Run("template authority key", func(t *testing.T) {
		input := newDeploymentFixture(t).input
		record, private := ed25519LabRecord(t)
		template := input.Template
		familyInput, err := CoverTemplateFamilySignatureInput(template)
		if err != nil {
			t.Fatal(err)
		}
		template.TemplateFamilySignature = ed25519.Sign(private, familyInput)
		input.Template = template
		input.TemplateAuthorityKey = record
		_, err = VerifyRelayDeployment(input)
		requireLabSchemeRejection(t, "template authority", err)
	})
}
