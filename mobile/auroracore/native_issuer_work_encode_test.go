//go:build cgo

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/wire"
)

func TestNativeIssuerWorkEncodeRoundTripsCanonicalFields(t *testing.T) {
	work := nativeIssuerWork{
		Handle:            42,
		IssuerURL:         "https://issuer.example",
		IssuerCarrierPath: "/assets/issue",
		RequestBody:       []byte("issuer-request"),
	}
	encoded, err := work.encode()
	if err != nil {
		t.Fatal(err)
	}

	reader := wire.NewReader(encoded)
	if handle := reader.ReadVarint(); handle != work.Handle {
		t.Fatalf("encoded handle = %d, want %d", handle, work.Handle)
	}
	if issuerURL := string(reader.ReadOpaque16()); issuerURL != work.IssuerURL {
		t.Fatalf("encoded issuer URL = %q, want %q", issuerURL, work.IssuerURL)
	}
	if carrierPath := string(reader.ReadOpaque16()); carrierPath != work.IssuerCarrierPath {
		t.Fatalf("encoded carrier path = %q, want %q", carrierPath, work.IssuerCarrierPath)
	}
	if requestBody := reader.ReadOpaque24(); !bytes.Equal(requestBody, work.RequestBody) {
		t.Fatalf("encoded request body = %q, want %q", requestBody, work.RequestBody)
	}
	if reader.Err() != nil || !reader.EOF() {
		t.Fatalf("encoded issuer work was not canonical: err=%v eof=%t", reader.Err(), reader.EOF())
	}
}

func TestNativeIssuerWorkEncodeRejectsInvalidFields(t *testing.T) {
	valid := nativeIssuerWork{
		Handle:            1,
		IssuerURL:         "https://issuer.example",
		IssuerCarrierPath: "/issue",
		RequestBody:       []byte("request"),
	}
	cases := []struct {
		name   string
		mutate func(*nativeIssuerWork)
	}{
		{"zero handle", func(work *nativeIssuerWork) { work.Handle = 0 }},
		{"empty issuer URL", func(work *nativeIssuerWork) { work.IssuerURL = "" }},
		{"oversized issuer URL", func(work *nativeIssuerWork) {
			work.IssuerURL = strings.Repeat("x", maximumNativeIssuerWorkBytes+1)
		}},
		{"empty carrier path", func(work *nativeIssuerWork) { work.IssuerCarrierPath = "" }},
		{"oversized carrier path", func(work *nativeIssuerWork) {
			work.IssuerCarrierPath = strings.Repeat("x", maximumNativeIssuerWorkBytes+1)
		}},
		{"empty request body", func(work *nativeIssuerWork) { work.RequestBody = nil }},
		{"oversized request body", func(work *nativeIssuerWork) {
			work.RequestBody = make([]byte, maximumNativeIssuerWorkBytes+1)
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			work := valid
			test.mutate(&work)
			if _, err := work.encode(); err == nil {
				t.Fatal("invalid native issuer work was encoded")
			}
		})
	}
}
