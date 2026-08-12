package admission

import (
	"bytes"
	"testing"
)

func TestAccessHintCredentialCanonicalRoundTrip(t *testing.T) {
	credentials := []AccessHintCredential{
		{HintIssuerID: rep(0x11, 16), RelayBucketID: rep(0x12, 16), HintEpochID: 4, HintSelector: rep(0x13, 16), HintSecret: rep(0x14, 32), ExpiryUnix: 1234, MaxUses: 1},
		{HintIssuerID: rep(0x21, 16), RelayBucketID: rep(0x22, 16), HintEpochID: 5, HintSelector: rep(0x23, 16), HintSecret: rep(0x24, 32), ExpiryUnix: 5678, MaxUses: 1},
	}
	encoded, err := EncodeAccessHintCredentialSet(credentials)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAccessHintCredentialSet(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(credentials) || !bytes.Equal(decoded[0].HintSecret, credentials[0].HintSecret) || !bytes.Equal(decoded[1].HintIssuerID, credentials[1].HintIssuerID) {
		t.Fatalf("access hint credential round trip = %+v", decoded)
	}
	decoded[0].HintSecret[0] ^= 0xff
	if bytes.Equal(decoded[0].HintSecret, credentials[0].HintSecret) {
		t.Fatal("decoded access hint credential aliases caller input")
	}
}

func TestAccessHintCredentialSetRejectsMalformedInput(t *testing.T) {
	credential := AccessHintCredential{HintIssuerID: rep(0x31, 16), RelayBucketID: rep(0x32, 16), HintEpochID: 6, HintSelector: rep(0x33, 16), HintSecret: rep(0x34, 32), MaxUses: 1}
	encoded, err := EncodeAccessHintCredentialSet([]AccessHintCredential{credential})
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{nil, encoded[:len(encoded)-1], append(append([]byte(nil), encoded...), 0)} {
		if _, err := DecodeAccessHintCredentialSet(malformed); err == nil {
			t.Fatalf("malformed access hint credential set accepted: %x", malformed)
		}
	}
	if _, err := EncodeAccessHintCredentialSet(nil); err == nil {
		t.Fatal("empty access hint credential set accepted")
	}
}
