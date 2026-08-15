//go:build cgo

package main

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/server"
)

func TestEncodeNativeIssueCarrierZeroesInnerPayload(t *testing.T) {
	body := []byte("temporary blind-rsa request payload")
	encoded := encodeNativeIssueCarrier(body)
	defer zeroNativeBytes(encoded)

	for index, value := range body {
		if value != 0 {
			t.Fatalf("inner payload byte %d = %d after carrier encoding, want zero", index, value)
		}
	}
	carrierType, payload, err := server.DecodeCarrier(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if carrierType != server.CarrierBlindRSAIssueReq {
		t.Fatalf("carrier type = %d, want %d", carrierType, server.CarrierBlindRSAIssueReq)
	}
	if !bytes.Equal(payload, []byte("temporary blind-rsa request payload")) {
		t.Fatalf("carrier payload = %q", payload)
	}
}

func TestEncodeParsedAdmissionProofZeroesDecodedCredentialFields(t *testing.T) {
	proof := nativeBridgeAdmissionProof(t)
	encoded, err := encodeParsedAdmissionProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encoded)
	for _, field := range [][]byte{
		proof.IssuerID,
		proof.TokenKeyID,
		proof.RelayBucketID,
		proof.TokenScopeID,
		proof.TokenNonce,
		proof.RedemptionContextHash,
		proof.TokenPublicMetadata,
		proof.TokenAuthenticator,
		proof.BindingProof,
		proof.Extensions[0].Body,
	} {
		for index, value := range field {
			if value != 0 {
				t.Fatalf("credential byte %d = %d after bridge encoding, want zero", index, value)
			}
		}
	}
}

func TestZeroNativeTokenMetadataZeroesAllFields(t *testing.T) {
	metadata := protocol.AuroraTokenMetadata{
		RFC9577ChallengeDigest: bytes.Repeat([]byte{0x41}, 32),
		RFC9577TokenKeyID:      bytes.Repeat([]byte{0x42}, 32),
		IssuerName:             []byte("issuer.example"),
		OriginInfo:             []byte("origin.example"),
		IssuerMetadataHash:     bytes.Repeat([]byte{0x43}, 48),
	}
	zeroNativeTokenMetadata(&metadata)
	if metadata.RFC9577TokenType != 0 ||
		len(metadata.RFC9577ChallengeDigest) != 0 ||
		len(metadata.RFC9577TokenKeyID) != 0 ||
		len(metadata.IssuerName) != 0 ||
		len(metadata.OriginInfo) != 0 ||
		len(metadata.IssuerMetadataHash) != 0 {
		t.Fatalf("metadata = %+v after zeroing, want zero value", metadata)
	}
}

func nativeBridgeAdmissionProof(t testing.TB) protocol.AdmissionProof {
	t.Helper()
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              bytes.Repeat([]byte{0x11}, 16),
		TokenKeyID:            bytes.Repeat([]byte{0x12}, 32),
		RelayBucketID:         bytes.Repeat([]byte{0x13}, 16),
		TokenScopeID:          bytes.Repeat([]byte{0x14}, 16),
		ExpiryUnix:            1_700_000_000,
		TokenNonce:            bytes.Repeat([]byte{0x15}, 32),
		RedemptionContextHash: bytes.Repeat([]byte{0x16}, 48),
		TokenAuthenticator:    []byte("authenticator"),
		BindingProof:          []byte("binding"),
		Extensions:            []protocol.Extension{{ExtensionType: 0x7005, Body: []byte("extension")}},
	}
	metadata, err := protocol.Encode(protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: bytes.Repeat([]byte{0x21}, 32),
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             []byte("issuer.example"),
		OriginInfo:             []byte("origin.example"),
		IssuerMetadataHash:     bytes.Repeat([]byte{0x22}, 48),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof.TokenPublicMetadata = metadata
	return proof
}
