package trust

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestVerifyCanonicalRelayDeploymentAcceptsCompleteTrustedObjects(t *testing.T) {
	fixture := newDeploymentFixture(t)
	input := canonicalDeploymentInputForTest(t, fixture.input)
	verified, err := VerifyCanonicalRelayDeployment(input)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid() || !bytes.Equal(verified.DescriptorHash(), fixture.input.TrustedDescriptorHash) {
		t.Fatalf("canonical deployment verification = %+v", verified)
	}
}

func TestVerifyCanonicalRelayDeploymentRejectsMalformedObjects(t *testing.T) {
	fixture := newDeploymentFixture(t)
	input := canonicalDeploymentInputForTest(t, fixture.input)
	for name, mutate := range map[string]func(*CanonicalRelayDeploymentInput){
		"missing descriptor":     func(in *CanonicalRelayDeploymentInput) { in.Descriptor = nil },
		"trailing descriptor":    func(in *CanonicalRelayDeploymentInput) { in.Descriptor = append(in.Descriptor, 0) },
		"truncated template":     func(in *CanonicalRelayDeploymentInput) { in.Template = in.Template[:len(in.Template)-1] },
		"trailing authority key": func(in *CanonicalRelayDeploymentInput) { in.TemplateAuthorityKey = append(in.TemplateAuthorityKey, 0) },
		"short trusted hash":     func(in *CanonicalRelayDeploymentInput) { in.TrustedDescriptorHash = in.TrustedDescriptorHash[:47] },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneCanonicalDeploymentInput(input)
			mutate(&candidate)
			if _, err := VerifyCanonicalRelayDeployment(candidate); err == nil {
				t.Fatal("malformed canonical deployment accepted")
			}
		})
	}
}

func canonicalDeploymentInputForTest(t testing.TB, input RelayDeploymentVerification) CanonicalRelayDeploymentInput {
	t.Helper()
	descriptor, err := protocol.Encode(input.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	template, err := protocol.Encode(input.Template)
	if err != nil {
		t.Fatal(err)
	}
	authorityKey, err := protocol.Encode(input.TemplateAuthorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return CanonicalRelayDeploymentInput{
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
	}
}

func cloneCanonicalDeploymentInput(input CanonicalRelayDeploymentInput) CanonicalRelayDeploymentInput {
	input.Descriptor = append([]byte(nil), input.Descriptor...)
	input.TrustedDescriptorHash = append([]byte(nil), input.TrustedDescriptorHash...)
	input.Template = append([]byte(nil), input.Template...)
	input.TemplateAuthorityKey = append([]byte(nil), input.TemplateAuthorityKey...)
	return input
}
