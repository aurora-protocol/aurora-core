package trust

import (
	"bytes"
	"fmt"
	"sync"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

// AuthorityKeyID derives the canonical identifier for an encoded public key.
func AuthorityKeyID(encodedPublicKey []byte) []byte {
	return auroracrypto.Truncate128(auroracrypto.PreHashLabel("aurora v2.0 authority key id", encodedPublicKey))
}

func SignedSeedRecordHash(seed protocol.SignedSeedRecord) ([]byte, error) {
	encoded, err := protocol.Encode(seed.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 signed seed hash", encoded), nil
}

func SignedSeedRecordSignatureInput(seed protocol.SignedSeedRecord) ([]byte, error) {
	hash, err := SignedSeedRecordHash(seed)
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHashLabel("aurora v2.0 signed seed signature", hash), nil
}

// VerifySignedSeedRecord verifies a seed against its currently authorized signer set.
func VerifySignedSeedRecord(seed protocol.SignedSeedRecord, keys []protocol.AuthorityKeyRecord, now uint64) error {
	if err := seed.ValidateStructural(now); err != nil {
		return err
	}
	if err := rejectDuplicateAuthorityKeys(keys); err != nil {
		return err
	}
	if err := validateSignedSeedAuthorityKeys(seed.BootstrapAuthorityKeys); err != nil {
		return err
	}
	if err := validateSignedSeedAuthorityKeys(seed.AuthorityKeyUpdates); err != nil {
		return err
	}
	signer, err := LocateAuthorityKeyByID(keys, seed.SeedSignature.SignerKeyID, seed.SeedSignature.SignatureScheme, seed.SeedSignature.KeyEncoding, now, registry.UsageMaySignSignedSeedRecord)
	if err != nil {
		return fmt.Errorf("trust: locate signed seed signer: %w", err)
	}
	if err := validateAuthorityKeyID(signer); err != nil {
		return err
	}
	input, err := SignedSeedRecordSignatureInput(seed)
	if err != nil {
		return err
	}
	if err := auroracrypto.VerifySignature(seed.SeedSignature.SignatureScheme, seed.SeedSignature.KeyEncoding, signer.PublicKey.PublicKey, input, seed.SeedSignature.Signature); err != nil {
		return fmt.Errorf("trust: signed seed signature verification failed: %w", err)
	}
	return nil
}

// SignedSeedTrustStore retains pinned roots and authorities promoted only by verified seeds.
type SignedSeedTrustStore struct {
	mu sync.RWMutex

	pinnedRoots      []protocol.AuthorityKeyRecord
	promotedKeys     []protocol.AuthorityKeyRecord
	acceptedSeedHash map[string][]byte
}

func NewSignedSeedTrustStore(pinnedRoots []protocol.AuthorityKeyRecord) (*SignedSeedTrustStore, error) {
	if len(pinnedRoots) == 0 {
		return nil, fmt.Errorf("trust: signed seed trust store requires pinned bootstrap roots")
	}
	roots, err := cloneSignedSeedAuthorityKeys(pinnedRoots)
	if err != nil {
		return nil, err
	}
	if err := validateSignedSeedAuthorityKeys(roots); err != nil {
		return nil, err
	}
	if err := rejectDuplicateAuthorityKeys(roots); err != nil {
		return nil, err
	}
	return &SignedSeedTrustStore{
		pinnedRoots:      roots,
		acceptedSeedHash: make(map[string][]byte),
	}, nil
}

// Accept verifies a seed and only then promotes its bootstrap keys and updates.
func (s *SignedSeedTrustStore) Accept(seed protocol.SignedSeedRecord, now uint64) error {
	if s == nil {
		return fmt.Errorf("trust: nil signed seed trust store")
	}
	if err := seed.ValidateStructural(now); err != nil {
		return err
	}
	seedHash, err := SignedSeedRecordHash(seed)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, exists := s.acceptedSeedHash[string(seed.SeedID)]; exists {
		if bytes.Equal(previous, seedHash) {
			return nil
		}
		return fmt.Errorf("trust: signed seed id conflicts with an accepted record")
	}
	trusted, err := s.authorityKeysLocked()
	if err != nil {
		return err
	}
	if err := VerifySignedSeedRecord(seed, trusted, now); err != nil {
		return err
	}
	promoted, err := cloneSignedSeedAuthorityKeys(s.promotedKeys)
	if err != nil {
		return err
	}
	if err := addSignedSeedBootstrapKeys(s.pinnedRoots, &promoted, seed.BootstrapAuthorityKeys); err != nil {
		return err
	}
	if err := applySignedSeedAuthorityUpdates(s.pinnedRoots, &promoted, seed.AuthorityKeyUpdates); err != nil {
		return err
	}
	combined := make([]protocol.AuthorityKeyRecord, 0, len(s.pinnedRoots)+len(promoted))
	combined = append(combined, s.pinnedRoots...)
	combined = append(combined, promoted...)
	if err := rejectDuplicateAuthorityKeys(combined); err != nil {
		return err
	}
	s.promotedKeys = promoted
	s.acceptedSeedHash[string(seed.SeedID)] = append([]byte(nil), seedHash...)
	return nil
}

// AuthorityKeys returns a defensive copy of pinned and promoted keys.
func (s *SignedSeedTrustStore) AuthorityKeys() []protocol.AuthorityKeyRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys, err := s.authorityKeysLocked()
	if err != nil {
		return nil
	}
	return keys
}

func (s *SignedSeedTrustStore) authorityKeysLocked() ([]protocol.AuthorityKeyRecord, error) {
	keys := make([]protocol.AuthorityKeyRecord, 0, len(s.pinnedRoots)+len(s.promotedKeys))
	keys = append(keys, s.pinnedRoots...)
	keys = append(keys, s.promotedKeys...)
	return cloneSignedSeedAuthorityKeys(keys)
}

func addSignedSeedBootstrapKeys(pinnedRoots []protocol.AuthorityKeyRecord, promoted *[]protocol.AuthorityKeyRecord, additions []protocol.AuthorityKeyRecord) error {
	for _, key := range additions {
		if existing, found := locateSignedSeedAuthorityKey(pinnedRoots, key); found {
			if !authorityKeysEqual(existing, key) {
				return fmt.Errorf("trust: signed seed bootstrap key conflicts with pinned root")
			}
			continue
		}
		if existing, found := locateSignedSeedAuthorityKey(*promoted, key); found {
			if !authorityKeysEqual(existing, key) {
				return fmt.Errorf("trust: signed seed bootstrap key conflicts with promoted key")
			}
			continue
		}
		cloned, err := cloneSignedSeedAuthorityKeys([]protocol.AuthorityKeyRecord{key})
		if err != nil {
			return err
		}
		*promoted = append(*promoted, cloned[0])
	}
	return nil
}

func applySignedSeedAuthorityUpdates(pinnedRoots []protocol.AuthorityKeyRecord, promoted *[]protocol.AuthorityKeyRecord, updates []protocol.AuthorityKeyRecord) error {
	for _, update := range updates {
		if _, found := locateSignedSeedAuthorityKey(pinnedRoots, update); found {
			return fmt.Errorf("trust: signed seed cannot update pinned bootstrap root")
		}
		cloned, err := cloneSignedSeedAuthorityKeys([]protocol.AuthorityKeyRecord{update})
		if err != nil {
			return err
		}
		if index := locateSignedSeedAuthorityKeyIndex(*promoted, update); index >= 0 {
			(*promoted)[index] = cloned[0]
		} else {
			*promoted = append(*promoted, cloned[0])
		}
	}
	return nil
}

func validateSignedSeedAuthorityKeys(keys []protocol.AuthorityKeyRecord) error {
	for _, key := range keys {
		if err := validateAuthorityKeyID(key); err != nil {
			return err
		}
	}
	return nil
}

func validateAuthorityKeyID(key protocol.AuthorityKeyRecord) error {
	if err := key.ValidateStructural(); err != nil {
		return err
	}
	if key.PublicKey.SignatureScheme == registry.SigEd25519Lab {
		return fmt.Errorf("trust: lab authority key is disabled")
	}
	encoded, err := protocol.Encode(key.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(key.AuthorityKeyID, AuthorityKeyID(encoded)) {
		return fmt.Errorf("trust: authority key id is not canonical")
	}
	return nil
}

func rejectDuplicateAuthorityKeys(keys []protocol.AuthorityKeyRecord) error {
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		identity := signedSeedAuthoritySignerIdentity(key)
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("trust: duplicate authority key")
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func locateSignedSeedAuthorityKey(keys []protocol.AuthorityKeyRecord, want protocol.AuthorityKeyRecord) (protocol.AuthorityKeyRecord, bool) {
	if index := locateSignedSeedAuthorityKeyIndex(keys, want); index >= 0 {
		return keys[index], true
	}
	return protocol.AuthorityKeyRecord{}, false
}

func locateSignedSeedAuthorityKeyIndex(keys []protocol.AuthorityKeyRecord, want protocol.AuthorityKeyRecord) int {
	wantIdentity := signedSeedAuthorityRecordIdentity(want)
	for index, key := range keys {
		if signedSeedAuthorityRecordIdentity(key) == wantIdentity {
			return index
		}
	}
	return -1
}

func signedSeedAuthorityRecordIdentity(key protocol.AuthorityKeyRecord) string {
	encoder := wire.NewEncoder()
	encoder.WriteOpaqueFixed(key.AuthorityID, 16)
	encoder.WriteOpaqueFixed(key.AuthorityKeyID, 16)
	encoder.WriteVarint(key.PublicKey.SignatureScheme)
	encoder.WriteVarint(key.PublicKey.KeyEncoding)
	encoded, err := encoder.Bytes()
	if err != nil {
		return ""
	}
	return string(encoded)
}

func signedSeedAuthoritySignerIdentity(key protocol.AuthorityKeyRecord) string {
	encoder := wire.NewEncoder()
	encoder.WriteOpaqueFixed(key.AuthorityKeyID, 16)
	encoder.WriteVarint(key.PublicKey.SignatureScheme)
	encoder.WriteVarint(key.PublicKey.KeyEncoding)
	encoded, err := encoder.Bytes()
	if err != nil {
		return ""
	}
	return string(encoded)
}

func authorityKeysEqual(left, right protocol.AuthorityKeyRecord) bool {
	leftEncoded, leftErr := protocol.Encode(left)
	rightEncoded, rightErr := protocol.Encode(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftEncoded, rightEncoded)
}

func cloneSignedSeedAuthorityKeys(keys []protocol.AuthorityKeyRecord) ([]protocol.AuthorityKeyRecord, error) {
	cloned := make([]protocol.AuthorityKeyRecord, len(keys))
	for index, key := range keys {
		encoded, err := protocol.Encode(key)
		if err != nil {
			return nil, err
		}
		reader := wire.NewReader(encoded)
		cloned[index] = protocol.DecodeAuthorityKeyRecord(reader)
		if reader.Err() != nil || !reader.EOF() {
			return nil, fmt.Errorf("trust: clone authority key failed")
		}
	}
	return cloned, nil
}
