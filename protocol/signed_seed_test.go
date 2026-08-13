package protocol

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestSignedSeedRecordRoundTripAndStructuralValidation(t *testing.T) {
	seed := signedSeedRecordFixture()
	if err := seed.ValidateStructural(200); err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(seed)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytesReader(encoded)
	decoded := DecodeSignedSeedRecord(reader)
	if reader.Err() != nil || !reader.EOF() {
		t.Fatalf("decode signed seed: %v", reader.Err())
	}
	if !bytes.Equal(decoded.SeedID, seed.SeedID) || !bytes.Equal(decoded.NextSeedCommitment, seed.NextSeedCommitment) || len(decoded.BootstrapAuthorityKeys) != 1 || len(decoded.AuthorityKeyUpdates) != 1 {
		t.Fatalf("signed seed round trip mismatch: %+v", decoded)
	}
	unsigned := seed.Unsigned()
	if len(unsigned.SeedSignature.Signature) != 0 || !bytes.Equal(unsigned.SeedSignature.SignerKeyID, seed.SeedSignature.SignerKeyID) {
		t.Fatalf("signed seed unsigned form did not preserve signer fields: %+v", unsigned.SeedSignature)
	}
}

func TestSignedSeedRecordRejectsInvalidStructure(t *testing.T) {
	for name, mutate := range map[string]func(*SignedSeedRecord){
		"expired":                 func(seed *SignedSeedRecord) { seed.ValidUntilUnix = 200 },
		"missing next commitment": func(seed *SignedSeedRecord) { seed.NextSeedCommitment = nil },
		"lab signature": func(seed *SignedSeedRecord) {
			seed.SeedSignature.SignatureScheme = registry.SigEd25519Lab
			seed.SeedSignature.KeyEncoding = registry.KeyEd25519RawPublic
		},
		"duplicate authorities": func(seed *SignedSeedRecord) {
			duplicate := seed.BootstrapAuthorityKeys[0]
			duplicate.AuthorityID = fill(0x06, 16)
			seed.AuthorityKeyUpdates = append(seed.AuthorityKeyUpdates, duplicate)
		},
	} {
		t.Run(name, func(t *testing.T) {
			seed := signedSeedRecordFixture()
			mutate(&seed)
			if err := seed.ValidateStructural(200); err == nil {
				t.Fatal("invalid signed seed accepted")
			}
		})
	}
}

func signedSeedRecordFixture() SignedSeedRecord {
	key := AuthorityKeyRecord{
		AuthorityID:    fill(0x01, 16),
		AuthorityKeyID: fill(0x02, 16),
		AuthorityRole:  1,
		PublicKey: PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       append([]byte{0x04}, fill(0x03, 64)...),
		},
		ValidFromUnix:  100,
		ValidUntilUnix: 300,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignSignedSeedRecord,
	}
	update := key
	update.AuthorityID = fill(0x04, 16)
	update.AuthorityKeyID = fill(0x05, 16)
	return SignedSeedRecord{
		SeedVersion:                registry.Version20,
		SeedID:                     fill(0x10, 16),
		ValidFromUnix:              100,
		ValidUntilUnix:             300,
		DirectoryConsensusHint:     []byte("directory"),
		BridgeBucketHint:           []byte("bridge"),
		TokenIssuerHint:            fill(0x11, 16),
		IssuerMetadataHash:         fill(0x12, 48),
		BootstrapAuthorityKeys:     []AuthorityKeyRecord{key},
		BootstrapCoverTemplateHash: fill(0x13, 48),
		AuthorityKeyUpdates:        []AuthorityKeyRecord{update},
		NextSeedCommitment:         fill(0x14, 48),
		SoftwareUpdateEpoch:        9,
		SeedSignature: ObjectSignature{
			SignerKeyID:     fill(0x15, 16),
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			Signature:       []byte("signature"),
		},
	}
}
