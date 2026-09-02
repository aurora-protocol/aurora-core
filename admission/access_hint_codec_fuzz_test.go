package admission

import (
	"bytes"
	"testing"
)

// FuzzDecodeAccessHintCredential drives the canonical credential decoder used
// on the static relay lookup path, i.e. on bytes that originate outside this
// process. Beyond not panicking, an accepted credential must satisfy the
// validate() contract (16-byte IDs, 32-byte secret, max_uses == 1) and
// re-encode to the exact input, because the decoder rejects trailing bytes.
func FuzzDecodeAccessHintCredential(f *testing.F) {
	credential := AccessHintCredential{HintIssuerID: rep(0x31, 16), RelayBucketID: rep(0x32, 16), HintEpochID: 6, HintSelector: rep(0x33, 16), HintSecret: rep(0x34, 32), MaxUses: 1}
	valid, err := EncodeAccessHintCredential(credential)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(valid[:len(valid)-1])                        // truncated
	f.Add(append(append([]byte(nil), valid...), 0x00)) // trailing byte
	f.Add(bytes.Repeat([]byte{0xff}, len(valid)))      // garbage at valid length (max_uses != 1)

	f.Fuzz(func(t *testing.T, encoded []byte) {
		decoded, err := DecodeAccessHintCredential(encoded)
		if err != nil {
			return
		}
		if err := decoded.validate(); err != nil {
			t.Fatalf("accepted credential violates validate(): %v", err)
		}
		reencoded, err := EncodeAccessHintCredential(decoded)
		if err != nil {
			t.Fatalf("decoded credential failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("credential re-encoded to %x, want %x", reencoded, encoded)
		}
	})
}

// FuzzDecodeAccessHintCredentialSet drives the bounded set decoder. Beyond not
// panicking, an accepted set must be non-empty and within the 4096-credential
// bound, every member must satisfy validate(), and the whole set must
// re-encode to the exact input bytes.
func FuzzDecodeAccessHintCredentialSet(f *testing.F) {
	credentials := []AccessHintCredential{
		{HintIssuerID: rep(0x11, 16), RelayBucketID: rep(0x12, 16), HintEpochID: 4, HintSelector: rep(0x13, 16), HintSecret: rep(0x14, 32), ExpiryUnix: 1234, MaxUses: 1},
		{HintIssuerID: rep(0x21, 16), RelayBucketID: rep(0x22, 16), HintEpochID: 5, HintSelector: rep(0x23, 16), HintSecret: rep(0x24, 32), ExpiryUnix: 5678, MaxUses: 1},
	}
	validTwo, err := EncodeAccessHintCredentialSet(credentials)
	if err != nil {
		f.Fatal(err)
	}
	validOne, err := EncodeAccessHintCredentialSet(credentials[:1])
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validTwo)
	f.Add(validOne)
	f.Add([]byte{})
	f.Add([]byte{0x00})                                   // count 0
	f.Add(validTwo[:len(validTwo)-1])                     // truncated mid-credential
	f.Add(append(append([]byte(nil), validTwo...), 0x00)) // trailing byte
	f.Add([]byte{0x50, 0x01})                             // count 4097, over the bound

	f.Fuzz(func(t *testing.T, encoded []byte) {
		decoded, err := DecodeAccessHintCredentialSet(encoded)
		if err != nil {
			return
		}
		if len(decoded) == 0 || len(decoded) > maximumAccessHintCredentialSet {
			t.Fatalf("accepted credential set of %d entries", len(decoded))
		}
		for i, credential := range decoded {
			if err := credential.validate(); err != nil {
				t.Fatalf("accepted credential %d violates validate(): %v", i, err)
			}
		}
		reencoded, err := EncodeAccessHintCredentialSet(decoded)
		if err != nil {
			t.Fatalf("decoded credential set failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("credential set re-encoded to %x, want %x", reencoded, encoded)
		}
	})
}
