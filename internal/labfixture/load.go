package labfixture

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Loaded is a minted lab deployment loaded back from disk and re-verified
// through the production deployment verifier. It holds private key material.
type Loaded struct {
	Manifest        Manifest
	Dir             string
	Deployment      trust.VerifiedRelayDeployment
	AccessHints     []admission.AccessHintCredential
	TokenKeyDER     []byte
	IssuerMetadata  protocol.IssuerMetadata
	IssuerAuthority protocol.AuthorityKeyRecord
	BlindRSAKey     *rsa.PrivateKey
	Certificate     tls.Certificate

	classicalSigner handshake.TranscriptSigner
	pqSigner        handshake.TranscriptSigner
}

// ClassicalSigner returns the epoch classical transcript signer.
func (l *Loaded) ClassicalSigner() handshake.TranscriptSigner { return l.classicalSigner }

// PQSigner returns the epoch ML-DSA transcript signer.
func (l *Loaded) PQSigner() handshake.TranscriptSigner { return l.pqSigner }

// Load reads a minted deployment directory, re-verifies the deployment
// against the trusted descriptor hash, and reconstructs the epoch signers.
func Load(dir string, now time.Time) (*Loaded, error) {
	if err := validateLabDirPath(dir); err != nil {
		return nil, err
	}
	if now.IsZero() || now.Unix() <= 0 {
		return nil, fmt.Errorf("labfixture: load time is invalid")
	}
	manifest, err := readLabManifest(filepath.Join(dir, FileManifest))
	if err != nil {
		return nil, err
	}
	loaded := &Loaded{Manifest: manifest, Dir: filepath.Clean(dir)}

	descriptor, err := readLabFile(filepath.Join(dir, FileRelayDescriptor), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroLabBytes(descriptor)
	descriptorHash, err := readLabFile(filepath.Join(dir, FileRelayDescriptorHash), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroLabBytes(descriptorHash)
	template, err := readLabFile(filepath.Join(dir, FileCoverTemplate), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroLabBytes(template)
	templateAuthority, err := readLabFile(filepath.Join(dir, FileTemplateAuthorityKey), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroLabBytes(templateAuthority)
	deployment, err := trust.VerifyCanonicalRelayDeployment(trust.CanonicalRelayDeploymentInput{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    descriptorHash,
		Template:                 template,
		TemplateAuthorityKey:     templateAuthority,
		RequestClassID:           manifest.Relay.RequestClassID,
		Suite:                    manifest.Relay.Suite,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  uint64(now.Unix()),
		MaxTemplateFutureSkew:    120,
		RequirePQDescriptorProof: true,
	})
	if err != nil {
		return nil, fmt.Errorf("labfixture: verify minted deployment: %w", err)
	}
	loaded.Deployment = deployment

	classicalSigner, err := loadLabClassicalSigner(filepath.Join(dir, FileEpochClassicalKey))
	if err != nil {
		return nil, err
	}
	loaded.classicalSigner = classicalSigner
	pqSigner, err := loadLabPQSigner(filepath.Join(dir, FileEpochPQKey))
	if err != nil {
		return nil, err
	}
	loaded.pqSigner = pqSigner

	hintsEncoded, err := readLabFile(filepath.Join(dir, FileAccessHints), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	hints, err := admission.DecodeAccessHintCredentialSet(hintsEncoded)
	zeroLabBytes(hintsEncoded)
	if err != nil {
		return nil, fmt.Errorf("labfixture: decode access hints: %w", err)
	}
	loaded.AccessHints = hints

	tokenKeyDER, err := readLabFile(filepath.Join(dir, FileTokenVerificationKey), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	loaded.TokenKeyDER = tokenKeyDER

	metadataEncoded, err := readLabFile(filepath.Join(dir, FileIssuerMetadata), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	reader := wire.NewReader(metadataEncoded)
	metadata := protocol.DecodeIssuerMetadata(reader)
	if reader.Err() != nil || !reader.EOF() {
		zeroLabBytes(metadataEncoded)
		return nil, fmt.Errorf("labfixture: decode issuer metadata failed")
	}
	zeroLabBytes(metadataEncoded)
	loaded.IssuerMetadata = metadata

	authorityEncoded, err := readLabFile(filepath.Join(dir, FileIssuerAuthorityKey), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	authorityReader := wire.NewReader(authorityEncoded)
	authority := protocol.DecodeAuthorityKeyRecord(authorityReader)
	if authorityReader.Err() != nil || !authorityReader.EOF() {
		zeroLabBytes(authorityEncoded)
		return nil, fmt.Errorf("labfixture: decode issuer authority key failed")
	}
	zeroLabBytes(authorityEncoded)
	loaded.IssuerAuthority = authority

	blindRSAKey, err := loadLabBlindRSAKey(filepath.Join(dir, FileIssuerBlindRSAKey))
	if err != nil {
		return nil, err
	}
	loaded.BlindRSAKey = blindRSAKey

	certificatePEM, err := readLabFile(filepath.Join(dir, FileTLSCertificate), maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readLabFile(filepath.Join(dir, FileTLSPrivateKey), maximumLabFileBytes)
	if err != nil {
		zeroLabBytes(certificatePEM)
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	zeroLabBytes(certificatePEM)
	zeroLabBytes(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("labfixture: load TLS certificate: %w", err)
	}
	loaded.Certificate = certificate
	return loaded, nil
}

// loadLabClassicalSigner loads a PEM P-256 epoch transcript signer key.
func loadLabClassicalSigner(path string) (handshake.TranscriptSigner, error) {
	encoded, err := readLabFile(path, maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroLabBytes(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("labfixture: classical signer key must contain one PEM block")
	}
	defer func() {
		zeroLabBytes(block.Bytes)
		*block = pem.Block{}
	}()
	var key any
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("labfixture: classical signer key PEM type is invalid")
	}
	if err != nil {
		return nil, fmt.Errorf("labfixture: parse classical signer key: %w", err)
	}
	private, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("labfixture: classical signer key must be ECDSA")
	}
	return handshake.NewECDSAP256TranscriptSigner(private)
}

// loadLabPQSigner loads a binary ML-DSA-65 epoch transcript signer key.
func loadLabPQSigner(path string) (handshake.TranscriptSigner, error) {
	encoded, err := readLabFile(path, maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroLabBytes(encoded)
	private := new(mldsa65.PrivateKey)
	if err := private.UnmarshalBinary(encoded); err != nil {
		return nil, fmt.Errorf("labfixture: parse PQ signer key: %w", err)
	}
	defer zeroLabMLDSA65Key(private)
	return handshake.NewMLDSA65TranscriptSigner(private)
}

// loadLabBlindRSAKey loads a PEM RSA Blind RSA signing key.
func loadLabBlindRSAKey(path string) (*rsa.PrivateKey, error) {
	encoded, err := readLabFile(path, maximumLabFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroLabBytes(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("labfixture: Blind RSA key must contain one PEM block")
	}
	defer func() {
		zeroLabBytes(block.Bytes)
		*block = pem.Block{}
	}()
	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			privateKey, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = fmt.Errorf("labfixture: Blind RSA key must be RSA")
			}
		}
	default:
		return nil, fmt.Errorf("labfixture: Blind RSA key PEM type is invalid")
	}
	if err != nil {
		return nil, fmt.Errorf("labfixture: parse Blind RSA key: %w", err)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("labfixture: validate Blind RSA key: %w", err)
	}
	return privateKey, nil
}
