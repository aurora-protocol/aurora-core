package trust

// Adversarial coverage for trust/hashes.go. The existing hashes_test.go and
// deployment tests exercise the happy paths; this file targets the error
// branches reachable only through malformed inputs:
//
//   - protocol.Encode failures when a fixed-length PreHash/opaque field has the
//     wrong length (DirectoryConsensusHash, RelayDescriptorHash, CoverTemplateHash);
//   - wire.Encoder write errors surfaced by e.Bytes() when an entry field is the
//     wrong length (DirectoryConsensusSignatureInput, CoverOriginCommitment);
//   - LocateAuthorityKey mismatch/validate/ambiguity continues;
//   - verifyDirectoryConsensusSignaturesWithUsage default-quorum, empty-sig,
//     key-lookup and signature-input propagation;
//   - ValidateAuthorityKeyRotation empty/invalid/quorum-failure paths;
//   - ValidateCoverTemplateTime interval and not-yet-valid guards;
//   - ValidateRequestClass unknown-class and pass-through-material guards.
//
// The wire.Encoder stores the first write error in e.err (via SetErr) and
// surfaces it from e.Bytes(), so the e.Bytes() error branches are reachable by
// feeding a wrong-length fixed field after the encoder has already accepted
// earlier writes — not dead-by-design.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// mustGenerateECDSA returns a freshly generated P-256 key, failing the test on
// any generation error. Used where a real ECDSA key is needed only to construct
// a structurally-valid AuthorityKeyRecord (the signature itself is never
// verified on the adversarial paths below).
func mustGenerateECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// validRelayDescriptor returns a structurally-valid descriptor whose EncodeTo
// succeeds, used as the base for adversarial mutants.
func validRelayDescriptor() protocol.RelayDescriptor {
	return protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      rb(1, 32),
		ValidFromUnix:                10,
		ValidUntilUnix:               20,
		RelayLongtermClassicalKey:    testPK(),
		RelayLongtermPQKey:           testPK(),
		EpochAuthClassicalKey:        testPK(),
		EpochAuthPQKey:               testPK(),
		ReplayWindowID:               rb(2, 16),
		SupportedPolicyIDsCommitment: rb(3, 48),
		SupportedShapeIDsCommitment:  rb(4, 48),
		ExitPolicyCommitment:         rb(5, 48),
		AbusePolicyCommitment:        rb(6, 48),
		SignatureByLongtermClassical: []byte("sig"),
		SignatureByLongtermPQ:        []byte("sig"),
	}
}

// validCoverTemplate returns a structurally-valid template whose EncodeTo and
// CoverOriginCommitment both succeed, used as the base for adversarial mutants.
func validCoverTemplate() protocol.CoverTemplate {
	return protocol.CoverTemplate{
		TemplateVersion:       registry.Version20,
		TemplateID:            rb(0x01, 16),
		TemplateFamilyID:      rb(0x02, 16),
		ValidFromUnix:         100,
		ValidUntilUnix:        400,
		OriginSPKIHash:        rb(0x03, 48),
		PublicNameHash:        rb(0x04, 48),
		CoverOriginCommitment: rb(0x05, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             registry.RequestGatewayOwnedSlot,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      rb(0x06, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{rb(0x07, 48)},
		OriginPassThroughSlotCommitments: [][]byte{rb(0x08, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  rb(0x09, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: rb(0x0a, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               rb(0x0b, 16),
			BodySizeDistributionID:   rb(0x0c, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                1,
			RecordSizeDistributionID: rb(0x0d, 16),
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  2,
			DatagramSizeDistributionID: rb(0x0e, 16),
			DatagramRateDistributionID: rb(0x0f, 16),
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               3,
			FrameSizeDistributionID: rb(0x10, 16),
		},
		CacheCookiePolicy:         protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:            protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: rb(0x11, 16)},
		TemplateFamilySignature:   []byte("family"),
		TemplateInstanceSignature: []byte("instance"),
	}
}

// --- DirectoryConsensus hash + signature input ---

func TestDirectoryConsensusHashRejectsMalformedConsensus(t *testing.T) {
	c := directoryConsensusForSignatureTest(protocol.SignatureEntry{
		AuthorityID:     rb(0xaa, 16),
		AuthorityKeyID:  rb(0xbb, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	})
	c.PreviousConsensusHash = rb(0, 47) // PreHash wants 48
	if _, err := DirectoryConsensusHash(c); err == nil {
		t.Fatal("malformed directory consensus accepted by DirectoryConsensusHash")
	}
}

func TestDirectoryConsensusSignatureInputAdversarial(t *testing.T) {
	validEntry := protocol.SignatureEntry{
		AuthorityID:     rb(0xaa, 16),
		AuthorityKeyID:  rb(0xbb, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	}
	validC := directoryConsensusForSignatureTest(validEntry)

	// Hash propagation: malformed consensus makes DirectoryConsensusHash fail.
	malformed := validC
	malformed.PreviousConsensusHash = rb(0, 47)
	if _, err := DirectoryConsensusSignatureInput(malformed, validEntry); err == nil {
		t.Fatal("malformed consensus accepted by DirectoryConsensusSignatureInput")
	}

	// Encoder error surfaced by e.Bytes(): valid consensus but the entry's
	// AuthorityID is the wrong length, so WriteOpaqueFixed(entry.AuthorityID,16)
	// records an error that e.Bytes() returns.
	shortIDEntry := validEntry
	shortIDEntry.AuthorityID = rb(0xaa, 15)
	if _, err := DirectoryConsensusSignatureInput(validC, shortIDEntry); err == nil {
		t.Fatal("wrong-length authority id accepted by DirectoryConsensusSignatureInput")
	}
}

// --- LocateAuthorityKey ---

func TestLocateAuthorityKeyAdversarial(t *testing.T) {
	priv := mustGenerateECDSA(t)
	entry := protocol.SignatureEntry{
		AuthorityID:     rb(0xaa, 16),
		AuthorityKeyID:  rb(0xbb, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	}

	// Scheme/encoding mismatch continue (IDs match, scheme differs): the key
	// is skipped, leaving zero matches.
	wrongScheme := authorityKeyForECDSA(t, entry.AuthorityID, entry.AuthorityKeyID, priv, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus)
	wrongScheme.PublicKey.SignatureScheme = registry.SigEd25519Lab
	if _, err := LocateAuthorityKey([]protocol.AuthorityKeyRecord{wrongScheme}, entry, 20, registry.UsageMaySignDirectoryConsensus); err == nil {
		t.Fatal("scheme-mismatched authority key accepted")
	}

	// Validate failure continue (expired key): IDs/scheme/encoding match but the
	// key is outside its validity interval, so it is skipped -> zero matches.
	expired := authorityKeyForECDSA(t, entry.AuthorityID, entry.AuthorityKeyID, priv, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus)
	if _, err := LocateAuthorityKey([]protocol.AuthorityKeyRecord{expired}, entry, 40, registry.UsageMaySignDirectoryConsensus); err == nil {
		t.Fatal("expired authority key accepted")
	}

	// Ambiguous match: two fully-valid keys match the entry -> len(matches) != 1.
	dup := authorityKeyForECDSA(t, entry.AuthorityID, entry.AuthorityKeyID, priv, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus)
	if _, err := LocateAuthorityKey([]protocol.AuthorityKeyRecord{dup, dup}, entry, 20, registry.UsageMaySignDirectoryConsensus); err == nil {
		t.Fatal("ambiguous authority key lookup accepted")
	}
}

// --- verifyDirectoryConsensusSignaturesWithUsage ---

func TestVerifyDirectoryConsensusSignaturesAdversarial(t *testing.T) {
	entry := protocol.SignatureEntry{
		AuthorityID:     rb(0xaa, 16),
		AuthorityKeyID:  rb(0xbb, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	}

	// minValid<=0 defaults to 1 (covered), then empty signatures errors.
	emptySig := directoryConsensusForSignatureTest(entry)
	emptySig.AuthoritySignatures = nil
	if err := VerifyDirectoryConsensusSignatures(emptySig, nil, 20, 0); err == nil {
		t.Fatal("empty authority signatures accepted")
	}

	// LocateAuthorityKey error propagation: a signature is present but no key
	// matches it.
	noKey := directoryConsensusForSignatureTest(entry)
	if err := VerifyDirectoryConsensusSignatures(noKey, nil, 20, 1); err == nil {
		t.Fatal("signature with no matching authority key accepted")
	}

	// DirectoryConsensusSignatureInput error propagation: a matching key exists
	// but the consensus is malformed, so the signature-input hash fails.
	priv := mustGenerateECDSA(t)
	key := authorityKeyForECDSA(t, entry.AuthorityID, entry.AuthorityKeyID, priv, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus)
	malformed := directoryConsensusForSignatureTest(entry)
	malformed.PreviousConsensusHash = rb(0, 47)
	if err := VerifyDirectoryConsensusSignatures(malformed, []protocol.AuthorityKeyRecord{key}, 20, 1); err == nil {
		t.Fatal("malformed consensus accepted during signature verification")
	}
}

// --- RelayDescriptor hash + signature input ---

func TestRelayDescriptorHashAdversarial(t *testing.T) {
	d := validRelayDescriptor()
	d.RelayID = rb(1, 31) // WriteOpaqueFixed(RelayID,32) wants 32
	if _, err := RelayDescriptorHash(d); err == nil {
		t.Fatal("malformed relay descriptor accepted by RelayDescriptorHash")
	}
}

func TestRelayDescriptorSignatureInputAdversarial(t *testing.T) {
	d := validRelayDescriptor()
	d.SupportedPolicyIDsCommitment = rb(3, 47) // PreHash wants 48
	if _, err := RelayDescriptorSignatureInput(d); err == nil {
		t.Fatal("malformed relay descriptor accepted by RelayDescriptorSignatureInput")
	}
}

// --- CoverOriginCommitment ---

func TestCoverOriginCommitmentAdversarial(t *testing.T) {
	// Gateway slot commitment wrong length -> encodePreHashVector error.
	tpl := validCoverTemplate()
	tpl.GatewayOwnedSlotCommitments = [][]byte{rb(0x07, 47)}
	if _, err := CoverOriginCommitment(tpl); err == nil {
		t.Fatal("wrong-length gateway commitment accepted")
	}

	// Pass-through slot commitment wrong length -> encodePreHashVector error
	// (gateway vector is empty/valid so the pass-through vector is reached).
	tpl = validCoverTemplate()
	tpl.GatewayOwnedSlotCommitments = nil
	tpl.OriginPassThroughSlotCommitments = [][]byte{rb(0x08, 47)}
	if _, err := CoverOriginCommitment(tpl); err == nil {
		t.Fatal("wrong-length pass-through commitment accepted")
	}

	// Encoder error surfaced by e.Bytes(): both commitment vectors are empty
	// (valid) but OriginSPKIHash is the wrong length, so WritePreHash records
	// an error that e.Bytes() returns.
	tpl = validCoverTemplate()
	tpl.GatewayOwnedSlotCommitments = nil
	tpl.OriginPassThroughSlotCommitments = nil
	tpl.OriginSPKIHash = rb(0x03, 47)
	if _, err := CoverOriginCommitment(tpl); err == nil {
		t.Fatal("wrong-length origin SPKI hash accepted by CoverOriginCommitment")
	}
}

// --- CoverTemplate hash + signature inputs ---

func TestCoverTemplateHashAdversarial(t *testing.T) {
	tpl := validCoverTemplate()
	tpl.OriginSPKIHash = rb(0x03, 47) // PreHash wants 48
	if _, err := CoverTemplateHash(tpl); err == nil {
		t.Fatal("malformed cover template accepted by CoverTemplateHash")
	}
}

func TestCoverTemplateFamilySignatureInputAdversarial(t *testing.T) {
	tpl := validCoverTemplate()
	tpl.PublicNameHash = rb(0x04, 47) // PreHash wants 48
	if _, err := CoverTemplateFamilySignatureInput(tpl); err == nil {
		t.Fatal("malformed cover template accepted by CoverTemplateFamilySignatureInput")
	}
}

func TestCoverTemplateInstanceSignatureInputAdversarial(t *testing.T) {
	// relayDescriptorHash wrong length -> immediate error before hashing template.
	tpl := validCoverTemplate()
	if _, err := CoverTemplateInstanceSignatureInput(rb(0x99, 47), tpl); err == nil {
		t.Fatal("wrong-length relay descriptor hash accepted")
	}

	// Valid relay descriptor hash but malformed template -> CoverTemplateHash error.
	malformed := validCoverTemplate()
	malformed.OriginSPKIHash = rb(0x03, 47)
	if _, err := CoverTemplateInstanceSignatureInput(rb(0x99, 48), malformed); err == nil {
		t.Fatal("malformed template accepted by CoverTemplateInstanceSignatureInput")
	}
}

// --- ValidateCoverTemplateTime ---

func TestValidateCoverTemplateTimeAdversarial(t *testing.T) {
	tpl := validCoverTemplate()

	// Invalid interval: ValidUntil <= ValidFrom.
	tpl.ValidFromUnix = 100
	tpl.ValidUntilUnix = 100
	if err := ValidateCoverTemplateTime(tpl, 50, 120); err == nil {
		t.Fatal("empty cover-template interval accepted")
	}

	// Not yet valid: now+maxFutureSkew < ValidFrom (and interval is valid).
	tpl.ValidFromUnix = 100
	tpl.ValidUntilUnix = 400
	if err := ValidateCoverTemplateTime(tpl, 0, 50); err == nil {
		t.Fatal("not-yet-valid cover template accepted")
	}
}

// --- ValidateRequestClass ---

func TestValidateRequestClassAdversarial(t *testing.T) {
	// Unknown class type -> default branch error.
	if err := ValidateRequestClass(protocol.RequestClass{ClassType: 0xff}); err == nil {
		t.Fatal("unknown request class type accepted")
	}

	// Origin-pass-through class carrying protocol material -> rejected.
	if err := ValidateRequestClass(protocol.RequestClass{
		ClassType:       registry.RequestOriginPassThrough,
		MayCarryPrelude: true,
	}); err == nil {
		t.Fatal("origin-pass-through class carrying prelude accepted")
	}
}

// --- ValidateAuthorityKeyRotation ---

func TestValidateAuthorityKeyRotationAdversarial(t *testing.T) {
	priv := mustGenerateECDSA(t)
	valid := authorityKeyForECDSA(t, rb(0xa0, 16), rb(0x01, 16), priv, registry.AuthorityActive,
		registry.UsageMaySignDirectoryConsensus|registry.UsageMayRotateDirectoryAuthority)

	// Empty next key set.
	if err := ValidateAuthorityKeyRotation(AuthorityKeyRotationInput{
		PreviousKeys: []protocol.AuthorityKeyRecord{valid},
		NextKeys:     nil,
		NowUnix:      20,
	}); err == nil {
		t.Fatal("empty next key set accepted")
	}

	// Invalid next key: structurally valid but outside its validity interval.
	expired := valid
	expired.ValidUntilUnix = 10
	if err := ValidateAuthorityKeyRotation(AuthorityKeyRotationInput{
		PreviousKeys: []protocol.AuthorityKeyRecord{valid},
		NextKeys:     []protocol.AuthorityKeyRecord{expired},
		NowUnix:      20,
	}); err == nil {
		t.Fatal("expired next authority key accepted")
	}

	// Previous quorum failure: next keys are valid, no pinned root, and the
	// next consensus carries no signatures so the previous-key quorum check
	// fails (wrapped as the rotation-lacks-previous-quorum error).
	noSigs := directoryConsensusForSignatureTest(protocol.SignatureEntry{
		AuthorityID:     valid.AuthorityID,
		AuthorityKeyID:  valid.AuthorityKeyID,
		SignatureScheme: valid.PublicKey.SignatureScheme,
		KeyEncoding:     valid.PublicKey.KeyEncoding,
	})
	noSigs.AuthoritySignatures = nil
	if err := ValidateAuthorityKeyRotation(AuthorityKeyRotationInput{
		PreviousKeys:  []protocol.AuthorityKeyRecord{valid},
		NextKeys:      []protocol.AuthorityKeyRecord{valid},
		NextConsensus: noSigs,
		NowUnix:       20,
	}); err == nil {
		t.Fatal("rotation without previous-key quorum accepted")
	}
}
