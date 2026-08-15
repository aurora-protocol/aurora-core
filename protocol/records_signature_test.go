package protocol

import (
	"bytes"
	"testing"
)

// TestAuthorityKeyRecordMatchesSignature covers the three-field signature
// match (authority key id, signature scheme, key encoding) and each mismatch.
func TestAuthorityKeyRecordMatchesSignature(t *testing.T) {
	keyID := bytes.Repeat([]byte{0xa1}, 16)
	rec := AuthorityKeyRecord{
		AuthorityKeyID: keyID,
		PublicKey: PublicKeyRecord{
			SignatureScheme: 0x1002,
			KeyEncoding:     0x2003,
		},
	}
	match := ObjectSignature{
		SignerKeyID:     keyID,
		SignatureScheme: 0x1002,
		KeyEncoding:     0x2003,
	}
	if !rec.MatchesSignature(match) {
		t.Fatal("matching signature rejected")
	}

	mismatched := match
	mismatched.SignerKeyID = bytes.Repeat([]byte{0xa2}, 16)
	if rec.MatchesSignature(mismatched) {
		t.Fatal("different signer key id accepted")
	}
	mismatched = match
	mismatched.SignatureScheme = 0x9999
	if rec.MatchesSignature(mismatched) {
		t.Fatal("different signature scheme accepted")
	}
	mismatched = match
	mismatched.KeyEncoding = 0x9999
	if rec.MatchesSignature(mismatched) {
		t.Fatal("different key encoding accepted")
	}
}