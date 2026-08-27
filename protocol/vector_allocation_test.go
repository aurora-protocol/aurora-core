package protocol

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/wire"
)

func TestMinimumEncodedVectorItemSizesMatchEncoders(t *testing.T) {
	tests := []struct {
		name string
		item wire.Encodable
		want int
	}{
		{"signature entry", SignatureEntry{AuthorityID: make([]byte, 16), AuthorityKeyID: make([]byte, 16)}, minimumEncodedSignatureEntryBytes},
		{"routing record", RoutingRecord{}, minimumEncodedRoutingRecordBytes},
		{"request class", RequestClass{PathTemplateID: make([]byte, 16)}, minimumEncodedRequestClassBytes},
		{"issuer token key", IssuerTokenKeyRecord{TokenKeyID: make([]byte, 32)}, minimumEncodedIssuerTokenKeyBytes},
		{"origin info policy", OriginInfoPolicy{}, minimumEncodedOriginInfoPolicyBytes},
		{"relay bucket scope", RelayBucketScope{RelayBucketID: make([]byte, 16), TokenScopeID: make([]byte, 16)}, minimumEncodedRelayBucketScopeBytes},
		{"auxiliary binding policy", AuxiliaryBindingPolicy{}, minimumEncodedAuxiliaryBindingBytes},
		{"verifier service", IssuerVerifierServiceRecord{ServiceID: make([]byte, 16)}, minimumEncodedVerifierServiceBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := wire.Encode(test.item)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) != test.want {
				t.Fatalf("minimum encoding length = %d, want %d", len(encoded), test.want)
			}
		})
	}
}

func TestDecodeDirectoryConsensusRejectsImpossibleSignatureCountBeforeAllocation(t *testing.T) {
	e := wire.NewEncoder()
	e.WriteVarint(0)
	e.WriteUint64(0)
	e.WriteUint64(0)
	e.WriteUint64(0)
	for range 7 {
		e.WritePreHash(make([]byte, 48))
	}
	e.WriteVarint(2)
	e.WriteBytes([]byte{0, 0})
	encoded, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	r := wire.NewReader(encoded)
	consensus := DecodeDirectoryConsensus(r)
	if r.Err() == nil || !strings.Contains(r.Err().Error(), "authority signature count 2 cannot fit") {
		t.Fatalf("impossible signature count error = %v, want fit rejection", r.Err())
	}
	if consensus.AuthoritySignatures != nil {
		t.Fatalf("decoder allocated or synthesized %d signatures for an impossible vector", len(consensus.AuthoritySignatures))
	}
}

func TestDecodeIssuerMetadataRejectsImpossibleTokenKeyCountBeforeAllocation(t *testing.T) {
	e := wire.NewEncoder()
	e.WriteVarint(0)
	e.WriteOpaqueFixed(make([]byte, 16), 16)
	e.WriteUint64(0)
	e.WriteUint64(0)
	e.WriteOpaque16(nil)
	e.WriteVarintVector(nil)
	e.WriteVarint(2)
	e.WriteBytes([]byte{0, 0})
	encoded, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	r := wire.NewReader(encoded)
	metadata := DecodeIssuerMetadata(r)
	if r.Err() == nil || !strings.Contains(r.Err().Error(), "issuer token key count 2 cannot fit") {
		t.Fatalf("impossible issuer token-key count error = %v, want fit rejection", r.Err())
	}
	if metadata.TokenKeyMappings != nil {
		t.Fatalf("decoder allocated or synthesized %d token keys for an impossible vector", len(metadata.TokenKeyMappings))
	}
}

func TestDecodeVerifierServiceRejectsImpossibleRelayBucketCount(t *testing.T) {
	e := wire.NewEncoder()
	e.WriteOpaqueFixed(make([]byte, 16), 16)
	e.WriteVarint(0)
	e.WriteVarint(0)
	RoutingRecord{}.EncodeTo(e)
	PublicKeyRecord{}.EncodeTo(e)
	e.WriteVarintVector(nil)
	e.WriteVarint(2)
	e.WriteBytes([]byte{0, 0})
	encoded, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	r := wire.NewReader(encoded)
	service := DecodeIssuerVerifierServiceRecord(r)
	if r.Err() == nil || !strings.Contains(r.Err().Error(), "allowed relay bucket count 2 cannot fit") {
		t.Fatalf("impossible relay-bucket count error = %v, want fit rejection", r.Err())
	}
	if service.AllowedRelayBucketIDs != nil {
		t.Fatalf("decoder synthesized %d relay bucket IDs for an impossible vector", len(service.AllowedRelayBucketIDs))
	}
}

func TestDecodeVerifierServicePreservesNilEmptyRelayBucketAllowlist(t *testing.T) {
	encoded, err := wire.Encode(IssuerVerifierServiceRecord{ServiceID: make([]byte, 16)})
	if err != nil {
		t.Fatal(err)
	}
	r := wire.NewReader(encoded)
	service := DecodeIssuerVerifierServiceRecord(r)
	if r.Err() != nil || !r.EOF() {
		t.Fatalf("decode empty relay-bucket allowlist: err=%v remaining=%d", r.Err(), r.Remaining())
	}
	if service.AllowedRelayBucketIDs != nil {
		t.Fatalf("empty relay-bucket allowlist = %#v, want nil for decoder compatibility", service.AllowedRelayBucketIDs)
	}
}
