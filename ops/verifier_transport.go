package ops

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	issuerVerifierRequestTimeout  = 2 * time.Second
	issuerVerifierMaxResponseSize = 1 << 20
)

type MTLSIssuerVerifierTransport struct {
	Client *http.Client
}

func (t MTLSIssuerVerifierTransport) ExchangeIssuerVerifier(service protocol.IssuerVerifierServiceRecord, req protocol.IssuerVerifierRequest) (protocol.IssuerVerifierResponse, error) {
	if t.Client == nil {
		return protocol.IssuerVerifierResponse{}, fmt.Errorf("ops: missing mTLS verifier HTTP client")
	}
	endpoint, err := issuerVerifierEndpoint(service)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	client, err := issuerVerifierHTTPClient(t.Client)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	encoded, err := protocol.Encode(req)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	httpReq.Header.Set("Accept", "application/octet-stream")
	httpReq.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(httpReq)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	defer resp.Body.Close()
	if err := verifyIssuerVerifierTLSIdentity(resp.TLS, service.ServiceAuthKey); err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return protocol.IssuerVerifierResponse{}, fmt.Errorf("ops: verifier service status %d", resp.StatusCode)
	}
	body, err := readIssuerVerifierResponse(resp)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	reader := wire.NewReader(body)
	out := protocol.DecodeIssuerVerifierResponse(reader)
	if reader.Err() != nil {
		return protocol.IssuerVerifierResponse{}, reader.Err()
	}
	if !reader.EOF() {
		return protocol.IssuerVerifierResponse{}, fmt.Errorf("ops: trailing verifier response bytes")
	}
	return out, nil
}

func issuerVerifierHTTPClient(source *http.Client) (*http.Client, error) {
	transport, err := issuerVerifierHTTPTransport(source.Transport)
	if err != nil {
		return nil, err
	}
	client := *source
	client.Transport = transport
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return fmt.Errorf("ops: verifier service redirects are not allowed")
	}
	if client.Timeout <= 0 || client.Timeout > issuerVerifierRequestTimeout {
		client.Timeout = issuerVerifierRequestTimeout
	}
	return &client, nil
}

func issuerVerifierHTTPTransport(roundTripper http.RoundTripper) (*http.Transport, error) {
	var base *http.Transport
	switch transport := roundTripper.(type) {
	case nil:
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("ops: default verifier HTTP transport is not standard")
		}
		base = defaultTransport
	case *http.Transport:
		base = transport
	default:
		return nil, fmt.Errorf("ops: verifier HTTP client must use a standard HTTP transport")
	}
	transport := base.Clone()
	transport.DisableCompression = true
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	if tlsConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("ops: verifier HTTP client must verify TLS certificates")
	}
	if tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("ops: verifier HTTP client TLS maximum is below TLS 1.3")
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

func readIssuerVerifierResponse(resp *http.Response) ([]byte, error) {
	if resp.ContentLength > issuerVerifierMaxResponseSize {
		return nil, fmt.Errorf("ops: verifier response exceeds %d-byte limit", issuerVerifierMaxResponseSize)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, issuerVerifierMaxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > issuerVerifierMaxResponseSize {
		return nil, fmt.Errorf("ops: verifier response exceeds %d-byte limit", issuerVerifierMaxResponseSize)
	}
	return body, nil
}

func issuerVerifierEndpoint(service protocol.IssuerVerifierServiceRecord) (string, error) {
	if service.ServiceProtocolID != registry.IssuerVerifierVOPRFMTLS13 {
		return "", fmt.Errorf("ops: verifier service protocol 0x%x is not mTLS13", service.ServiceProtocolID)
	}
	if service.ServiceLocator.LocatorType != registry.LocatorAuthority {
		return "", fmt.Errorf("ops: verifier service locator must be authority")
	}
	authority := string(service.ServiceLocator.LocatorBody)
	if authority == "" {
		return "", fmt.Errorf("ops: empty verifier service authority")
	}
	parsed, err := url.Parse("https://" + authority)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("ops: verifier service locator must contain only an authority")
	}
	u := url.URL{Scheme: "https", Host: parsed.Host, Path: "/"}
	return u.String(), nil
}

func verifyIssuerVerifierTLSIdentity(state *tls.ConnectionState, key protocol.PublicKeyRecord) error {
	if state == nil {
		return fmt.Errorf("ops: verifier service did not use TLS")
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("ops: verifier service TLS version 0x%x, want TLS 1.3", state.Version)
	}
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("ops: verifier service did not present a certificate")
	}
	if err := certificatePublicKeyMatchesRecord(state.PeerCertificates[0], key); err != nil {
		return fmt.Errorf("ops: verifier service identity mismatch: %w", err)
	}
	return nil
}

func certificatePublicKeyMatchesRecord(cert *x509.Certificate, key protocol.PublicKeyRecord) error {
	switch key.SignatureScheme {
	case registry.SigECDSAP256SHA256DER, registry.SigECDSAP256SHA384DER:
		return certificateECDSAKeyMatchesRecord(cert, elliptic.P256(), registry.KeyP256SEC1Uncompressed, registry.KeyP256SPKI, key)
	case registry.SigECDSAP384SHA384DER:
		return certificateECDSAKeyMatchesRecord(cert, elliptic.P384(), registry.KeyP384SEC1Uncompressed, registry.KeyP384SPKI, key)
	case registry.SigEd25519Lab:
		if key.KeyEncoding != registry.KeyEd25519RawPublic {
			return fmt.Errorf("Ed25519 lab service key encoding 0x%x", key.KeyEncoding)
		}
		pk, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not Ed25519")
		}
		if !bytes.Equal(pk, key.PublicKey) {
			return fmt.Errorf("certificate public key does not equal service_auth_key")
		}
		return nil
	default:
		return fmt.Errorf("unsupported verifier service signature scheme 0x%x", key.SignatureScheme)
	}
}

func certificateECDSAKeyMatchesRecord(cert *x509.Certificate, curve elliptic.Curve, sec1Encoding, spkiEncoding uint64, key protocol.PublicKeyRecord) error {
	pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not ECDSA")
	}
	if pk.Curve != curve {
		return fmt.Errorf("certificate ECDSA curve mismatch")
	}
	var encoded []byte
	var err error
	switch key.KeyEncoding {
	case sec1Encoding:
		encoded, err = pk.Bytes()
		if err != nil {
			return err
		}
	case spkiEncoding:
		encoded, err = x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("ECDSA service key encoding 0x%x", key.KeyEncoding)
	}
	if !bytes.Equal(encoded, key.PublicKey) {
		return fmt.Errorf("certificate public key does not equal service_auth_key")
	}
	return nil
}
