package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestVerifySignedSeedRecordRequiresAuthorizedRoot(t *testing.T) {
	root, rootPrivate := signedSeedAuthorityForTest(t, 0x10, registry.UsageMaySignSignedSeedRecord)
	seed := signedSeedForTest(t, root, rootPrivate, 200, []protocol.AuthorityKeyRecord{root}, nil)
	if err := VerifySignedSeedRecord(seed, []protocol.AuthorityKeyRecord{root}, 200); err != nil {
		t.Fatal(err)
	}
	noBootstrapKeys := signedSeedForTest(t, root, rootPrivate, 201, nil, nil)
	if err := VerifySignedSeedRecord(noBootstrapKeys, []protocol.AuthorityKeyRecord{root}, 201); err != nil {
		t.Fatal(err)
	}
	tampered := seed
	tampered.TokenIssuerHint[0] ^= 0xff
	if err := VerifySignedSeedRecord(tampered, []protocol.AuthorityKeyRecord{root}, 200); err == nil {
		t.Fatal("tampered signed seed accepted")
	}
	wrongUsage := root
	wrongUsage.UsageFlags = registry.UsageMaySignIssuerMetadata
	if err := VerifySignedSeedRecord(seed, []protocol.AuthorityKeyRecord{wrongUsage}, 200); err == nil {
		t.Fatal("seed signer without signed-seed usage accepted")
	}
	ambiguous := root
	ambiguous.AuthorityID = bytes.Repeat([]byte{0x11}, 16)
	if err := VerifySignedSeedRecord(seed, []protocol.AuthorityKeyRecord{root, ambiguous}, 200); err == nil {
		t.Fatal("ambiguous seed signer accepted")
	}
}

func TestSignedSeedTrustStorePromotesAndRevokesAuthorities(t *testing.T) {
	root, rootPrivate := signedSeedAuthorityForTest(t, 0x20, registry.UsageMaySignSignedSeedRecord)
	first, firstPrivate := signedSeedAuthorityForTest(t, 0x21, registry.UsageMaySignSignedSeedRecord)
	second, _ := signedSeedAuthorityForTest(t, 0x22, registry.UsageMaySignIssuerMetadata)
	store, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{root})
	if err != nil {
		t.Fatal(err)
	}
	seedOne := signedSeedForTest(t, root, rootPrivate, 200, []protocol.AuthorityKeyRecord{first}, nil)
	if err := store.Accept(seedOne, 200); err != nil {
		t.Fatal(err)
	}
	seedTwo := signedSeedForTest(t, first, firstPrivate, 210, []protocol.AuthorityKeyRecord{second}, nil)
	if err := store.Accept(seedTwo, 210); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedSeedRecord(seedTwo, store.AuthorityKeys(), 210); err != nil {
		t.Fatalf("promoted seed authority did not verify the next seed: %v", err)
	}
	revokedFirst := first
	revokedFirst.KeyStatus = registry.AuthorityRevoked
	seedThree := signedSeedForTest(t, root, rootPrivate, 220, []protocol.AuthorityKeyRecord{second}, []protocol.AuthorityKeyRecord{revokedFirst})
	if err := store.Accept(seedThree, 220); err != nil {
		t.Fatal(err)
	}
	seedFour := signedSeedForTest(t, first, firstPrivate, 230, []protocol.AuthorityKeyRecord{second}, nil)
	if err := store.Accept(seedFour, 230); err == nil {
		t.Fatal("revoked seed authority accepted a later seed")
	}
}

func TestSignedSeedTrustStoreConcurrentReplayAndRead(t *testing.T) {
	root, rootPrivate := signedSeedAuthorityForTest(t, 0x30, registry.UsageMaySignSignedSeedRecord)
	child, _ := signedSeedAuthorityForTest(t, 0x31, registry.UsageMaySignSignedSeedRecord)
	store, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{root})
	if err != nil {
		t.Fatal(err)
	}
	seed := signedSeedForTest(t, root, rootPrivate, 200, []protocol.AuthorityKeyRecord{child}, nil)

	const workers = 32
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if err := store.Accept(seed, 200); err != nil {
				errCh <- err
			}
			_ = store.AuthorityKeys()
		}()
	}
	close(start)
	group.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if got := len(store.AuthorityKeys()); got != 2 {
		t.Fatalf("authority count = %d, want 2", got)
	}
	if err := store.Accept(seed, 900); err == nil {
		t.Fatal("expired replay accepted")
	}
}

func TestSignedSeedTrustStoreRejectsAmbiguousSigner(t *testing.T) {
	root, _ := signedSeedAuthorityForTest(t, 0x40, registry.UsageMaySignSignedSeedRecord)
	duplicate := root
	duplicate.AuthorityID = bytes.Repeat([]byte{0x41}, 16)
	if _, err := NewSignedSeedTrustStore([]protocol.AuthorityKeyRecord{root, duplicate}); err == nil {
		t.Fatal("ambiguous signed-seed signer accepted")
	}
}

func signedSeedAuthorityForTest(t testing.TB, marker byte, usage uint32) (protocol.AuthorityKeyRecord, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := privateKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	keyID := signedSeedAuthorityKeyID(t, protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       publicKey,
	})
	return protocol.AuthorityKeyRecord{
		AuthorityID:    bytes.Repeat([]byte{marker}, 16),
		AuthorityKeyID: keyID,
		AuthorityRole:  1,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       publicKey,
		},
		ValidFromUnix:  100,
		ValidUntilUnix: 1000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     usage,
	}, privateKey
}

func signedSeedForTest(t testing.TB, signer protocol.AuthorityKeyRecord, privateKey *ecdsa.PrivateKey, now uint64, bootstrapKeys, updates []protocol.AuthorityKeyRecord) protocol.SignedSeedRecord {
	t.Helper()
	seed := protocol.SignedSeedRecord{
		SeedVersion:                registry.Version20,
		SeedID:                     bytes.Repeat([]byte{byte(now)}, 16),
		ValidFromUnix:              100,
		ValidUntilUnix:             900,
		DirectoryConsensusHint:     []byte("directory"),
		BridgeBucketHint:           []byte("bridge"),
		TokenIssuerHint:            bytes.Repeat([]byte{0x44}, 16),
		IssuerMetadataHash:         bytes.Repeat([]byte{0x45}, 48),
		BootstrapAuthorityKeys:     bootstrapKeys,
		BootstrapCoverTemplateHash: bytes.Repeat([]byte{0x46}, 48),
		AuthorityKeyUpdates:        updates,
		NextSeedCommitment:         bytes.Repeat([]byte{0x47}, 48),
		SoftwareUpdateEpoch:        now,
		SeedSignature: protocol.ObjectSignature{
			SignerKeyID:     append([]byte(nil), signer.AuthorityKeyID...),
			SignatureScheme: signer.PublicKey.SignatureScheme,
			KeyEncoding:     signer.PublicKey.KeyEncoding,
		},
	}
	input, err := SignedSeedRecordSignatureInput(seed)
	if err != nil {
		t.Fatal(err)
	}
	seed.SeedSignature.Signature, err = ecdsa.SignASN1(rand.Reader, privateKey, input)
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

func signedSeedAuthorityKeyID(t testing.TB, key protocol.PublicKeyRecord) []byte {
	t.Helper()
	encoded, err := protocol.Encode(key)
	if err != nil {
		t.Fatal(err)
	}
	return AuthorityKeyID(encoded)
}
