package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestIssuerWorkCompletesThroughProductionMTLSBackend(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	issuer := newProvisionedSessionProductionIssuer(t, now)
	handler, err := issuerd.NewProductionBlindRSABackendHandler(issuer, issuerd.ProductionBlindRSABackendOptions{MaxConcurrentIssues: 2})
	if err != nil {
		t.Fatal(err)
	}
	backend, backendClient := newProvisionedSessionMTLSBackend(t, handler)
	defer backend.Close()

	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 9,
		Write: session.DirectionConfig{
			Direction: 0,
			Secret:    bytes.Repeat([]byte{0x11}, 48),
			Key:       bytes.Repeat([]byte{0x12}, 32),
			IV:        bytes.Repeat([]byte{0x13}, 12),
		},
		Read: session.DirectionConfig{
			Direction: 1,
			Secret:    bytes.Repeat([]byte{0x21}, 48),
			Key:       bytes.Repeat([]byte{0x22}, 32),
			IV:        bytes.Repeat([]byte{0x23}, 12),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	established := &handshake.EstablishedSession{
		Application:  application,
		ReadCarrier:  io.NopCloser(bytes.NewReader(nil)),
		WriteCarrier: provisionedSessionDiscardWriteCloser{Writer: io.Discard},
	}
	deferred := &provisionedSessionTestHandshake{established: established}
	provisioned, work, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, now, issuer),
		ProvisionedSessionOptions{
			now:    func() time.Time { return now },
			random: bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer work.Zero()
	defer provisioned.Close()
	if kind, payload, decodeErr := carrier.Decode(work.RequestBody); decodeErr != nil || kind != carrier.BlindRSAIssueRequest || len(payload) != carrier.TokenNonceLength+carrier.RedemptionContextLength+8 {
		t.Fatalf("issuer work carrier = kind=%d payload=%d err=%v", kind, len(payload), decodeErr)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, backend.URL+"/", bytes.NewReader(work.RequestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := backendClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	issuerResponse, readErr := io.ReadAll(io.LimitReader(response.Body, maximumProvisionedIssuerResponse+1))
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	defer zeroProvisionedBytes(issuerResponse)
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
		t.Fatalf("production mTLS backend = status=%d protocol=%q body=%q", response.StatusCode, response.Proto, issuerResponse)
	}
	if kind, _, decodeErr := carrier.Decode(issuerResponse); decodeErr != nil || kind != carrier.BlindRSAIssueResponse {
		t.Fatalf("issuer response carrier = kind=%d err=%v", kind, decodeErr)
	}

	got, err := provisioned.Complete(context.Background(), issuerResponse)
	if err != nil {
		t.Fatal(err)
	}
	if got != established || provisioned.Established() != established || !deferred.Completed() {
		t.Fatal("production mTLS issuer response did not complete the provisioned session")
	}
}

func newProvisionedSessionProductionIssuer(t *testing.T, now time.Time) *issuerd.Service {
	t.Helper()
	harness, err := issuerd.NewHarnessService(uint64(now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	metadata := harness.PublishIssuerMetadata()
	blindRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encodedBlindRSAKey := marshalProvisionedSessionRSAPSSPublicKey(t, &blindRSAKey.PublicKey)
	keyID := sha256.Sum256(encodedBlindRSAKey)
	metadata.SupportedProofTypes = []uint64{registry.ProofBlindRSA2048}
	metadata.TokenKeyMappings = []protocol.IssuerTokenKeyRecord{{
		ProofType:  registry.ProofBlindRSA2048,
		TokenKeyID: keyID[:],
		TokenVerificationKey: protocol.TokenVerificationKeyRecord{
			TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
			TokenVerificationKey:       encodedBlindRSAKey,
		},
		ValidFromUnix:  metadata.ValidFromUnix,
		ValidUntilUnix: metadata.ValidUntilUnix,
		KeyStatus:      registry.IssuerStatusActive,
	}}
	metadata.VerifierServices = nil

	authoritySigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityPublicKey, err := authoritySigner.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	metadata.SignatureScheme = registry.SigECDSAP256SHA384DER
	metadata.KeyEncoding = registry.KeyP256SEC1Uncompressed
	authorityPublicRecord := protocol.PublicKeyRecord{
		SignatureScheme: metadata.SignatureScheme,
		KeyEncoding:     metadata.KeyEncoding,
		PublicKey:       authorityPublicKey,
	}
	encodedAuthorityPublicRecord, err := protocol.Encode(authorityPublicRecord)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSigningKeyID = auroratrust.AuthorityKeyID(encodedAuthorityPublicRecord)
	signatureInput, err := auroratrust.IssuerMetadataSignatureInput(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, authoritySigner, signatureInput)
	if err != nil {
		t.Fatal(err)
	}
	authority := protocol.AuthorityKeyRecord{
		AuthorityID:    bytes.Repeat([]byte{0xa5}, 16),
		AuthorityKeyID: append([]byte(nil), metadata.MetadataSigningKeyID...),
		PublicKey:      authorityPublicRecord,
		ValidFromUnix:  metadata.ValidFromUnix,
		ValidUntilUnix: metadata.ValidUntilUnix,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}
	service, err := issuerd.NewProductionBlindRSAService(issuerd.ProductionBlindRSAServiceOptions{
		Metadata:           metadata,
		AuthorityKeys:      []protocol.AuthorityKeyRecord{authority},
		BlindRSAKey:        blindRSAKey,
		SpentTokenCache:    admission.NewMemoryReplayCache(),
		RelayBucketID:      append([]byte(nil), metadata.RelayBucketScopes[0].RelayBucketID...),
		OriginInfoPolicyID: metadata.OriginInfoPolicies[0].PolicyID,
		NowUnix:            func() uint64 { return uint64(now.Unix()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newProvisionedSessionMTLSBackend(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2001),
		Subject:               pkix.Name{CommonName: "Aurora provisioned gateway test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate := &x509.Certificate{
		SerialNumber: big.NewInt(2002),
		Subject:      pkix.Name{CommonName: "Aurora provisioned gateway"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientCertificate, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(parsedCA)
	backend := httptest.NewUnstartedServer(handler)
	backend.EnableHTTP2 = true
	backend.TLS = &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{"h2"},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientCAs,
		SessionTicketsDisabled: true,
	}
	backend.StartTLS()
	client := backend.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test backend transport type = %T", client.Transport)
	}
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	transport.TLSClientConfig.MaxVersion = tls.VersionTLS13
	transport.TLSClientConfig.NextProtos = []string{"h2"}
	transport.TLSClientConfig.Certificates = []tls.Certificate{{
		Certificate: [][]byte{clientDER, caDER},
		PrivateKey:  clientKey,
	}}
	return backend, client
}

func marshalProvisionedSessionRSAPSSPublicKey(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	rsaKey, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{N: key.N, E: key.E})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}},
		SubjectPublicKey: asn1.BitString{Bytes: rsaKey, BitLength: len(rsaKey) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
