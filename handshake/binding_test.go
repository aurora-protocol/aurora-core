package handshake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/registry"
)

const bindingTestTLSHandshakeTimeout = 15 * time.Second

func TestDeriveHTTP2FirstHopBindingAgreesAcrossLiveTLS(t *testing.T) {
	clientState, serverState := liveHTTP2TLSStates(t)
	metadata := testHTTP2BindingMetadata()
	coverRandom := hx(0x31, 32)

	clientBinding, err := DeriveHTTP2FirstHopBinding(clientState, metadata, coverRandom)
	if err != nil {
		t.Fatal(err)
	}
	serverBinding, err := DeriveHTTP2FirstHopBinding(serverState, metadata, coverRandom)
	if err != nil {
		t.Fatal(err)
	}
	assertFirstHopBindingsEqual(t, clientBinding, serverBinding)

	wantConnectionHash := auroracrypto.PreHash([]byte("h2"), clientBinding.TLSExporterChannelID, make([]byte, 48))
	if !bytes.Equal(clientBinding.ConnectionIDHash, wantConnectionHash) {
		t.Fatal("HTTP/2 connection ID hash mismatch")
	}
	wantStreamBinding, err := CoverStreamBinding(CoverStreamBindingInput{
		OuterExporterValue:       clientBinding.OuterExporterValue,
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         wantConnectionHash,
		StreamIDOrRequestID:      1,
		MethodFamilyID:           metadata.MethodFamilyID,
		NormalizedAuthorityHash:  metadata.NormalizedAuthorityHash,
		NormalizedPathTemplateID: metadata.PathTemplateID,
		RequestClassID:           metadata.RequestClassID,
		ClientCoverRandom:        coverRandom,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientBinding.CoverStreamBinding, wantStreamBinding) {
		t.Fatal("live binding did not use HTTP/2 stream ID 1")
	}
}

func TestDeriveHTTP2FirstHopBindingBindsEveryMetadataField(t *testing.T) {
	clientState, _ := liveHTTP2TLSStates(t)
	metadata := testHTTP2BindingMetadata()
	coverRandom := hx(0x41, 32)
	baseline, err := DeriveHTTP2FirstHopBinding(clientState, metadata, coverRandom)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*HTTP2BindingMetadata, []byte) []byte
	}{
		{name: "authority", mutate: func(m *HTTP2BindingMetadata, r []byte) []byte { m.NormalizedAuthorityHash[0] ^= 0xff; return r }},
		{name: "path template", mutate: func(m *HTTP2BindingMetadata, r []byte) []byte { m.PathTemplateID[0] ^= 0xff; return r }},
		{name: "request class", mutate: func(m *HTTP2BindingMetadata, r []byte) []byte { m.RequestClassID++; return r }},
		{name: "cover random", mutate: func(m *HTTP2BindingMetadata, r []byte) []byte { r[0] ^= 0xff; return r }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedMetadata := testHTTP2BindingMetadata()
			changedRandom := test.mutate(&changedMetadata, append([]byte(nil), coverRandom...))
			changed, err := DeriveHTTP2FirstHopBinding(clientState, changedMetadata, changedRandom)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(baseline.CoverStreamBinding, changed.CoverStreamBinding) {
				t.Fatal("cover-stream binding ignored changed metadata")
			}
		})
	}
}

func TestDeriveHTTP2FirstHopBindingReturnsOwnedBytes(t *testing.T) {
	clientState, _ := liveHTTP2TLSStates(t)
	metadata := testHTTP2BindingMetadata()
	coverRandom := hx(0x51, 32)
	binding, err := DeriveHTTP2FirstHopBinding(clientState, metadata, coverRandom)
	if err != nil {
		t.Fatal(err)
	}
	want, err := DeriveHTTP2FirstHopBinding(clientState, testHTTP2BindingMetadata(), hx(0x51, 32))
	if err != nil {
		t.Fatal(err)
	}

	metadata.NormalizedAuthorityHash[0] ^= 0xff
	metadata.PathTemplateID[0] ^= 0xff
	coverRandom[0] ^= 0xff
	binding.OuterExporterValue[0] ^= 0xff
	binding.TLSExporterChannelID[0] ^= 0xff
	binding.ConnectionIDHash[0] ^= 0xff
	binding.CoverStreamBinding[0] ^= 0xff
	binding.HandshakeBindingContext[0] ^= 0xff

	recomputed, err := DeriveHTTP2FirstHopBinding(clientState, testHTTP2BindingMetadata(), hx(0x51, 32))
	if err != nil {
		t.Fatal(err)
	}
	assertFirstHopBindingsEqual(t, want, recomputed)
}

func TestDeriveHTTP2FirstHopBindingRejectsInvalidStateOrMetadata(t *testing.T) {
	validState, _ := liveHTTP2TLSStates(t)
	tests := []struct {
		name     string
		state    tls.ConnectionState
		metadata HTTP2BindingMetadata
		random   []byte
	}{
		{name: "handshake incomplete", state: func() tls.ConnectionState { s := validState; s.HandshakeComplete = false; return s }(), metadata: testHTTP2BindingMetadata(), random: hx(1, 32)},
		{name: "tls12", state: tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS12, NegotiatedProtocol: "h2"}, metadata: testHTTP2BindingMetadata(), random: hx(1, 32)},
		{name: "http1", state: tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, NegotiatedProtocol: "http/1.1"}, metadata: testHTTP2BindingMetadata(), random: hx(1, 32)},
		{name: "resumed", state: func() tls.ConnectionState { s := validState; s.DidResume = true; return s }(), metadata: testHTTP2BindingMetadata(), random: hx(1, 32)},
		{name: "authority length", state: validState, metadata: HTTP2BindingMetadata{NormalizedAuthorityHash: hx(1, 47), PathTemplateID: hx(2, 16), RequestClassID: 1, MethodFamilyID: registry.MethodWebH2Stream}, random: hx(1, 32)},
		{name: "path length", state: validState, metadata: HTTP2BindingMetadata{NormalizedAuthorityHash: hx(1, 48), PathTemplateID: hx(2, 15), RequestClassID: 1, MethodFamilyID: registry.MethodWebH2Stream}, random: hx(1, 32)},
		{name: "zero class", state: validState, metadata: HTTP2BindingMetadata{NormalizedAuthorityHash: hx(1, 48), PathTemplateID: hx(2, 16), MethodFamilyID: registry.MethodWebH2Stream}, random: hx(1, 32)},
		{name: "wrong method", state: validState, metadata: HTTP2BindingMetadata{NormalizedAuthorityHash: hx(1, 48), PathTemplateID: hx(2, 16), RequestClassID: 1, MethodFamilyID: registry.MethodWebH1WS}, random: hx(1, 32)},
		{name: "random length", state: validState, metadata: testHTTP2BindingMetadata(), random: hx(1, 31)},
		{name: "exporter unavailable", state: tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, NegotiatedProtocol: "h2"}, metadata: testHTTP2BindingMetadata(), random: hx(1, 32)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DeriveHTTP2FirstHopBinding(test.state, test.metadata, test.random); err == nil {
				t.Fatal("invalid live binding input accepted")
			}
		})
	}
}

func testHTTP2BindingMetadata() HTTP2BindingMetadata {
	return HTTP2BindingMetadata{
		NormalizedAuthorityHash: hx(0x21, 48),
		PathTemplateID:          hx(0x22, 16),
		RequestClassID:          9,
		MethodFamilyID:          registry.MethodWebH2Stream,
	}
}

func liveHTTP2TLSStates(t *testing.T) (tls.ConnectionState, tls.ConnectionState) {
	t.Helper()
	certificate, roots := bindingTestCertificate(t)
	clientRaw, serverRaw := net.Pipe()
	serverTLS := tls.Server(serverRaw, &tls.Config{
		Certificates:           []tls.Certificate{certificate},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{"h2"},
		SessionTicketsDisabled: true,
	})
	clientTLS := tls.Client(clientRaw, &tls.Config{
		RootCAs:       roots,
		ServerName:    "localhost",
		MinVersion:    tls.VersionTLS13,
		MaxVersion:    tls.VersionTLS13,
		NextProtos:    []string{"h2"},
		Renegotiation: tls.RenegotiateNever,
	})
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), bindingTestTLSHandshakeTimeout)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- serverTLS.HandshakeContext(ctx) }()
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server TLS handshake: %v", err)
	}
	return clientTLS.ConnectionState(), serverTLS.ConnectionState()
}

func bindingTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: parsed}, roots
}

func assertFirstHopBindingsEqual(t *testing.T, left, right FirstHopBinding) {
	t.Helper()
	if !bytes.Equal(left.OuterExporterValue, right.OuterExporterValue) ||
		!bytes.Equal(left.TLSExporterChannelID, right.TLSExporterChannelID) ||
		!bytes.Equal(left.ConnectionIDHash, right.ConnectionIDHash) ||
		!bytes.Equal(left.CoverStreamBinding, right.CoverStreamBinding) ||
		!bytes.Equal(left.HandshakeBindingContext, right.HandshakeBindingContext) {
		t.Fatal("first-hop bindings differ")
	}
}
