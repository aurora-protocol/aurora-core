//go:build cgo

package main

import (
	"bytes"
	"testing"

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
