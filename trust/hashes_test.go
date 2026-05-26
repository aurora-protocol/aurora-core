package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func rb(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func testPK() protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigEd25519Lab,
		KeyEncoding:     registry.KeyEd25519RawPublic,
		PublicKey:       rb(0x11, 32),
	}
}

func TestDirectoryConsensusHashIgnoresAuthoritySignatureBytes(t *testing.T) {
	c := protocol.DirectoryConsensus{
		Version:                 registry.Version20,
		Epoch:                   1,
		ValidFromUnix:           10,
		ValidUntilUnix:          20,
		PreviousConsensusHash:   rb(0, 48),
		RelayDescriptorRoot:     rb(1, 48),
		CoverTemplateFamilyRoot: rb(2, 48),
		RevocationRoot:          rb(3, 48),
		PolicyRoot:              rb(4, 48),
		BridgeBucketCommitment:  rb(5, 48),
		IssuerMetadataRoot:      rb(6, 48),
		AuthoritySignatures: []protocol.SignatureEntry{{
			AuthorityID:     rb(0xaa, 16),
			AuthorityKeyID:  rb(0xbb, 16),
			SignatureScheme: registry.SigEd25519Lab,
			KeyEncoding:     registry.KeyEd25519RawPublic,
			Signature:       []byte("first"),
		}},
	}
	h1, err := DirectoryConsensusHash(c)
	if err != nil {
		t.Fatal(err)
	}
	c.AuthoritySignatures[0].Signature = []byte("second")
	h2, err := DirectoryConsensusHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("consensus hash included signature bytes")
	}
}

func TestVerifyDirectoryConsensusSignaturesAcceptsValidECDSAAuthority(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := protocol.SignatureEntry{
		AuthorityID:     rb(0xaa, 16),
		AuthorityKeyID:  rb(0xbb, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	}
	c := directoryConsensusForSignatureTest(entry)
	input, err := DirectoryConsensusSignatureInput(c, entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Signature, err = ecdsa.SignASN1(rand.Reader, priv, input)
	if err != nil {
		t.Fatal(err)
	}
	c.AuthoritySignatures = []protocol.SignatureEntry{entry}
	keys := []protocol.AuthorityKeyRecord{{
		AuthorityID:    entry.AuthorityID,
		AuthorityKeyID: entry.AuthorityKeyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: entry.SignatureScheme,
			KeyEncoding:     entry.KeyEncoding,
			PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus,
	}}
	if err := VerifyDirectoryConsensusSignatures(c, keys, 20, 1); err != nil {
		t.Fatalf("valid directory consensus signature rejected: %v", err)
	}
	c.RelayDescriptorRoot = rb(0xee, 48)
	if err := VerifyDirectoryConsensusSignatures(c, keys, 20, 1); err == nil {
		t.Fatalf("tampered directory consensus accepted")
	}
}

func TestVerifyDirectoryConsensusSignaturesRequiresDistinctAuthoritiesForThreshold(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := protocol.SignatureEntry{
		AuthorityID:     rb(0xaa, 16),
		AuthorityKeyID:  rb(0xbb, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	}
	c := directoryConsensusForSignatureTest(entry)
	input, err := DirectoryConsensusSignatureInput(c, entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Signature, err = ecdsa.SignASN1(rand.Reader, priv, input)
	if err != nil {
		t.Fatal(err)
	}
	c.AuthoritySignatures = []protocol.SignatureEntry{entry, entry}
	keys := []protocol.AuthorityKeyRecord{{
		AuthorityID:    entry.AuthorityID,
		AuthorityKeyID: entry.AuthorityKeyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: entry.SignatureScheme,
			KeyEncoding:     entry.KeyEncoding,
			PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus,
	}}
	if err := VerifyDirectoryConsensusSignatures(c, keys, 20, 2); err == nil {
		t.Fatalf("duplicate authority signatures satisfied threshold")
	}
}

func TestVerifyStrictDirectoryConsensusSignaturesRequiresDistinctMLDSAQuorum(t *testing.T) {
	classicalPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pqSeed [mldsa65.SeedSize]byte
	for i := range pqSeed {
		pqSeed[i] = byte(i + 1)
	}
	pqPublic, pqPrivate := mldsa65.NewKeyFromSeed(&pqSeed)
	classicalEntry := protocol.SignatureEntry{
		AuthorityID:     rb(0xa1, 16),
		AuthorityKeyID:  rb(0x01, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
	}
	pqEntry := protocol.SignatureEntry{
		AuthorityID:     rb(0xa2, 16),
		AuthorityKeyID:  rb(0x02, 16),
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
	}
	c := directoryConsensusForSignatureTest(classicalEntry)
	c.AuthoritySignatures = []protocol.SignatureEntry{classicalEntry, pqEntry}
	c.AuthoritySignatures[0].Signature = signDirectoryEntry(t, c, classicalEntry, classicalPriv)
	c.AuthoritySignatures[1].Signature = signDirectoryEntryMLDSA65(t, c, pqEntry, pqPrivate)
	keys := []protocol.AuthorityKeyRecord{
		authorityKeyForECDSA(classicalEntry.AuthorityID, classicalEntry.AuthorityKeyID, classicalPriv, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus),
		authorityKeyForMLDSA65(pqEntry.AuthorityID, pqEntry.AuthorityKeyID, pqPublic, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus),
	}

	if err := VerifyDirectoryConsensusSignatures(c, keys, 20, 2); err != nil {
		t.Fatalf("standard total authority quorum rejected: %v", err)
	}
	if err := VerifyStrictDirectoryConsensusSignatures(c, keys, 20, 2); err == nil {
		t.Fatalf("strict quorum accepted only one distinct ML-DSA authority")
	}

	var secondPQSeed [mldsa65.SeedSize]byte
	for i := range secondPQSeed {
		secondPQSeed[i] = byte(0x80 + i)
	}
	secondPQPublic, secondPQPrivate := mldsa65.NewKeyFromSeed(&secondPQSeed)
	secondPQEntry := protocol.SignatureEntry{
		AuthorityID:     rb(0xa3, 16),
		AuthorityKeyID:  rb(0x03, 16),
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
	}
	c.AuthoritySignatures = []protocol.SignatureEntry{pqEntry, secondPQEntry}
	c.AuthoritySignatures[0].Signature = signDirectoryEntryMLDSA65(t, c, pqEntry, pqPrivate)
	c.AuthoritySignatures[1].Signature = signDirectoryEntryMLDSA65(t, c, secondPQEntry, secondPQPrivate)
	keys = []protocol.AuthorityKeyRecord{
		authorityKeyForMLDSA65(pqEntry.AuthorityID, pqEntry.AuthorityKeyID, pqPublic, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus),
		authorityKeyForMLDSA65(secondPQEntry.AuthorityID, secondPQEntry.AuthorityKeyID, secondPQPublic, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus),
	}
	if err := VerifyStrictDirectoryConsensusSignatures(c, keys, 20, 2); err != nil {
		t.Fatalf("strict distinct ML-DSA authority quorum rejected: %v", err)
	}
}

func TestValidateAuthorityKeyRotationRequiresOverlapUnlessPinned(t *testing.T) {
	oldPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := authorityKeyForECDSA(rb(0xa0, 16), rb(0x01, 16), oldPriv, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus|registry.UsageMayRotateDirectoryAuthority)
	newKey := authorityKeyForECDSA(rb(0xa1, 16), rb(0x02, 16), newPriv, registry.AuthorityActive, registry.UsageMaySignDirectoryConsensus|registry.UsageMayRotateDirectoryAuthority)

	next := directoryConsensusForSignatureTest(protocol.SignatureEntry{
		AuthorityID:     oldKey.AuthorityID,
		AuthorityKeyID:  oldKey.AuthorityKeyID,
		SignatureScheme: oldKey.PublicKey.SignatureScheme,
		KeyEncoding:     oldKey.PublicKey.KeyEncoding,
	})
	next.Epoch = 2
	next.AuthoritySignatures[0].Signature = signDirectoryEntry(t, next, next.AuthoritySignatures[0], oldPriv)

	retiringOld := oldKey
	retiringOld.KeyStatus = registry.AuthorityRetiringVerifyOnly
	if err := ValidateAuthorityKeyRotation(AuthorityKeyRotationInput{
		PreviousKeys:                  []protocol.AuthorityKeyRecord{oldKey},
		NextKeys:                      []protocol.AuthorityKeyRecord{retiringOld, newKey},
		NextConsensus:                 next,
		NowUnix:                       20,
		MinValidDistinctAuthorities:   1,
		PinnedBootstrapRootAuthorized: false,
	}); err != nil {
		t.Fatalf("overlapping authority rotation rejected: %v", err)
	}

	if err := ValidateAuthorityKeyRotation(AuthorityKeyRotationInput{
		PreviousKeys:                  []protocol.AuthorityKeyRecord{oldKey},
		NextKeys:                      []protocol.AuthorityKeyRecord{newKey},
		NextConsensus:                 next,
		NowUnix:                       20,
		MinValidDistinctAuthorities:   1,
		PinnedBootstrapRootAuthorized: false,
	}); err == nil {
		t.Fatalf("same-transition old-key removal without pinned root accepted")
	}

	if err := ValidateAuthorityKeyRotation(AuthorityKeyRotationInput{
		PreviousKeys:                  []protocol.AuthorityKeyRecord{oldKey},
		NextKeys:                      []protocol.AuthorityKeyRecord{newKey},
		NextConsensus:                 next,
		NowUnix:                       20,
		MinValidDistinctAuthorities:   1,
		PinnedBootstrapRootAuthorized: true,
	}); err != nil {
		t.Fatalf("pinned-root-authorized old-key removal rejected: %v", err)
	}
}

func TestRelayDescriptorHashIgnoresSignatureBytes(t *testing.T) {
	d := protocol.RelayDescriptor{
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
		SignatureByLongtermClassical: []byte("first"),
		SignatureByLongtermPQ:        []byte("first"),
	}
	h1, err := RelayDescriptorHash(d)
	if err != nil {
		t.Fatal(err)
	}
	d.SignatureByLongtermClassical = []byte("second")
	d.SignatureByLongtermPQ = []byte("second")
	h2, err := RelayDescriptorHash(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("descriptor hash included signature bytes")
	}
}

func authorityKeyForECDSA(authorityID, keyID []byte, priv *ecdsa.PrivateKey, status uint8, usage uint32) protocol.AuthorityKeyRecord {
	return protocol.AuthorityKeyRecord{
		AuthorityID:    authorityID,
		AuthorityKeyID: keyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      status,
		UsageFlags:     usage,
	}
}

func authorityKeyForMLDSA65(authorityID, keyID []byte, publicKey *mldsa65.PublicKey, status uint8, usage uint32) protocol.AuthorityKeyRecord {
	return protocol.AuthorityKeyRecord{
		AuthorityID:    authorityID,
		AuthorityKeyID: keyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       publicKey.Bytes(),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      status,
		UsageFlags:     usage,
	}
}

func signDirectoryEntry(t *testing.T, c protocol.DirectoryConsensus, entry protocol.SignatureEntry, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	input, err := DirectoryConsensusSignatureInput(c, entry)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, input)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func signDirectoryEntryMLDSA65(t *testing.T, c protocol.DirectoryConsensus, entry protocol.SignatureEntry, priv *mldsa65.PrivateKey) []byte {
	t.Helper()
	input, err := DirectoryConsensusSignatureInput(c, entry)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(priv, input, nil, false, sig); err != nil {
		t.Fatal(err)
	}
	return sig
}

func directoryConsensusForSignatureTest(entry protocol.SignatureEntry) protocol.DirectoryConsensus {
	return protocol.DirectoryConsensus{
		Version:                 registry.Version20,
		Epoch:                   1,
		ValidFromUnix:           10,
		ValidUntilUnix:          30,
		PreviousConsensusHash:   rb(0, 48),
		RelayDescriptorRoot:     rb(1, 48),
		CoverTemplateFamilyRoot: rb(2, 48),
		RevocationRoot:          rb(3, 48),
		PolicyRoot:              rb(4, 48),
		BridgeBucketCommitment:  rb(5, 48),
		IssuerMetadataRoot:      rb(6, 48),
		AuthoritySignatures:     []protocol.SignatureEntry{entry},
	}
}

func TestCoverTemplateHashAndValidation(t *testing.T) {
	tpl := protocol.CoverTemplate{
		TemplateVersion:       registry.Version20,
		TemplateID:            rb(1, 16),
		TemplateFamilyID:      rb(2, 16),
		ValidFromUnix:         10,
		ValidUntilUnix:        20,
		OriginSPKIHash:        rb(3, 48),
		PublicNameHash:        rb(4, 48),
		CoverOriginCommitment: rb(5, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             registry.RequestGatewayOwnedSlot,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      rb(6, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{rb(7, 48)},
		OriginPassThroughSlotCommitments: [][]byte{rb(8, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  rb(9, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: rb(10, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               rb(11, 16),
			BodySizeDistributionID:   rb(12, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                1,
			RecordSizeDistributionID: rb(13, 16),
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  2,
			DatagramSizeDistributionID: rb(14, 16),
			DatagramRateDistributionID: rb(15, 16),
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               3,
			FrameSizeDistributionID: rb(16, 16),
		},
		CacheCookiePolicy:         protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:            protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: rb(17, 16)},
		TemplateFamilySignature:   []byte("family"),
		TemplateInstanceSignature: []byte("instance"),
	}
	if err := ValidateCoverTemplateTime(tpl, 12, 120); err != nil {
		t.Fatal(err)
	}
	for _, class := range tpl.RequestClasses {
		if err := ValidateRequestClass(class); err != nil {
			t.Fatal(err)
		}
	}
	h1, err := CoverTemplateHash(tpl)
	if err != nil {
		t.Fatal(err)
	}
	tpl.TemplateFamilySignature = []byte("other")
	tpl.TemplateInstanceSignature = []byte("other")
	h2, err := CoverTemplateHash(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("cover template hash included signature bytes")
	}
}
