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
	"strings"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
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
	encoded, err := protocol.Encode(req)
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return protocol.IssuerVerifierResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	resp, err := t.Client.Do(httpReq)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
	if strings.Contains(authority, "://") {
		return "", fmt.Errorf("ops: verifier service locator must not include a URL scheme")
	}
	u := url.URL{Scheme: "https", Host: authority, Path: "/"}
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
