package labfixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// ManifestWarning is embedded in every manifest and printed by tooling.
	ManifestWarning = "LOCAL LAB TESTING ONLY: self-signed single-tenant lab deployment; never deploy as production"

	manifestFormat = 1

	// FileManifest describes the minted layout and public endpoints.
	FileManifest = "manifest.json"
	// FileRelayDescriptor is the canonical signed relay descriptor.
	FileRelayDescriptor = "relay-descriptor.bin"
	// FileRelayDescriptorHash is the trusted 48-byte descriptor hash.
	FileRelayDescriptorHash = "relay-descriptor.hash"
	// FileCoverTemplate is the canonical signed cover template.
	FileCoverTemplate = "cover-template.bin"
	// FileTemplateAuthorityKey is the canonical template authority public key.
	FileTemplateAuthorityKey = "template-authority-key.bin"
	// FileEpochClassicalKey is the P-256 epoch transcript signer key (PEM).
	FileEpochClassicalKey = "epoch-classical-key.pem"
	// FileEpochPQKey is the ML-DSA-65 epoch transcript signer key (binary).
	FileEpochPQKey = "epoch-pq-key.bin"
	// FileAccessHints is the canonical access hint credential set.
	FileAccessHints = "access-hints.bin"
	// FileTokenVerificationKey is the Blind RSA verification key (DER).
	FileTokenVerificationKey = "token-verification-key.der"
	// FileIssuerMetadata is the canonical signed issuer metadata.
	FileIssuerMetadata = "issuer-metadata.bin"
	// FileIssuerAuthorityKey is the canonical issuer metadata authority record.
	FileIssuerAuthorityKey = "issuer-authority-key.bin"
	// FileIssuerBlindRSAKey is the Blind RSA signing key (PEM).
	FileIssuerBlindRSAKey = "issuer-blind-rsa-key.pem"
	// FileSeedRootAuthorityKey is the canonical signed-seed trust anchor record.
	FileSeedRootAuthorityKey = "seed-root-authority-key.bin"
	// FileNativeProvisioningTrust is the sealed v2 native provisioning trust
	// file clients load as their signed-seed root configuration.
	FileNativeProvisioningTrust = "native-provisioning-trust.bin"
	// FileWallet is the encoded native provisioning wallet.
	FileWallet = "wallet.bin"
	// FileTLSCertificate is the shared relay/issuer TLS certificate chain
	// (leaf first, then the lab CA) in PEM form.
	FileTLSCertificate = "tls-cert.pem"
	// FileTLSPrivateKey is the shared relay/issuer TLS private key (PEM).
	FileTLSPrivateKey = "tls-key.pem"
	// FileCA is the self-signed lab CA certificate (PEM); client devices
	// install it as a trust anchor for the relay/issuer HTTPS exchange.
	FileCA = "ca.pem"
	// FileCAKey is the lab CA private key (PEM).
	FileCAKey = "ca-key.pem"

	maximumLabFileBytes     = 16 << 20
	maximumLabManifestBytes = 64 << 10
)

// manifestFiles maps manifest labels to minted file names.
func manifestFiles() map[string]string {
	return map[string]string{
		"relay_descriptor":          FileRelayDescriptor,
		"relay_descriptor_hash":     FileRelayDescriptorHash,
		"cover_template":            FileCoverTemplate,
		"template_authority_key":    FileTemplateAuthorityKey,
		"epoch_classical_key":       FileEpochClassicalKey,
		"epoch_pq_key":              FileEpochPQKey,
		"access_hints":              FileAccessHints,
		"token_verification_key":    FileTokenVerificationKey,
		"issuer_metadata":           FileIssuerMetadata,
		"issuer_authority_key":      FileIssuerAuthorityKey,
		"issuer_blind_rsa_key":      FileIssuerBlindRSAKey,
		"seed_root_authority_key":   FileSeedRootAuthorityKey,
		"native_provisioning_trust": FileNativeProvisioningTrust,
		"wallet":                    FileWallet,
		"tls_certificate":           FileTLSCertificate,
		"tls_private_key":           FileTLSPrivateKey,
		"ca":                        FileCA,
		"ca_key":                    FileCAKey,
	}
}

// ManifestRelay describes the minted relay public endpoint.
type ManifestRelay struct {
	URL            string `json:"url"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Authority      string `json:"authority"`
	Path           string `json:"path"`
	RequestClassID uint64 `json:"request_class_id"`
	Suite          uint64 `json:"suite"`
}

// ManifestIssuer describes the minted issuer public endpoint.
type ManifestIssuer struct {
	URL         string `json:"url"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	CarrierPath string `json:"carrier_path"`
}

// Manifest describes one minted lab deployment directory.
type Manifest struct {
	Format         uint64            `json:"format"`
	Warning        string            `json:"warning"`
	CreatedUnix    uint64            `json:"created_unix"`
	ValidUntilUnix uint64            `json:"valid_until_unix"`
	Relay          ManifestRelay     `json:"relay"`
	Issuer         ManifestIssuer    `json:"issuer"`
	Entries        int               `json:"entries"`
	Files          map[string]string `json:"files"`
}

type labFile struct {
	name string
	data []byte
}

// Material is a freshly minted lab deployment held in memory. It contains
// private key material; persist it with WriteTo and erase it with Zero.
type Material struct {
	Manifest Manifest
	files    []labFile
}

// WriteTo persists the minted deployment into dir, which must not already
// contain lab material. The directory is created owner-only (0700) and every
// file is written owner-only (0600) without overwriting existing files.
func (m *Material) WriteTo(dir string) (err error) {
	if m == nil || len(m.files) == 0 {
		return fmt.Errorf("labfixture: minted material is unavailable")
	}
	if err := validateLabDirPath(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("labfixture: create deployment directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("labfixture: restrict deployment directory: %w", err)
		}
	}
	manifestEncoded, err := json.MarshalIndent(m.Manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("labfixture: encode manifest: %w", err)
	}
	manifestEncoded = append(manifestEncoded, '\n')
	written := make([]string, 0, len(m.files)+1)
	defer func() {
		if err != nil {
			for index := len(written) - 1; index >= 0; index-- {
				_ = os.Remove(written[index])
			}
		}
	}()
	for _, file := range m.files {
		path := filepath.Join(dir, file.name)
		if err := writeLabFileExclusive(path, file.data); err != nil {
			return err
		}
		written = append(written, path)
	}
	if err := writeLabFileExclusive(filepath.Join(dir, FileManifest), manifestEncoded); err != nil {
		return err
	}
	return nil
}

// Zero erases every minted file payload retained in memory.
func (m *Material) Zero() {
	if m == nil {
		return
	}
	for index := range m.files {
		zeroLabBytes(m.files[index].data)
		m.files[index] = labFile{}
	}
	m.files = nil
	m.Manifest = Manifest{}
}

// validateLabDirPath rejects empty, untrimmed, or root deployment paths.
func validateLabDirPath(dir string) error {
	if strings.TrimSpace(dir) == "" || strings.TrimSpace(dir) != dir {
		return fmt.Errorf("labfixture: deployment directory path is invalid")
	}
	clean := filepath.Clean(dir)
	if clean == "." || clean == string(filepath.Separator) {
		return fmt.Errorf("labfixture: deployment directory path is invalid")
	}
	return nil
}

// writeLabFileExclusive writes one owner-only file, refusing to overwrite.
func writeLabFileExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("labfixture: create %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("labfixture: write %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("labfixture: close %s: %w", filepath.Base(path), err)
	}
	return nil
}

// readLabManifest reads and strictly decodes a minted manifest.
func readLabManifest(path string) (Manifest, error) {
	encoded, err := readLabFile(path, maximumLabManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	defer zeroLabBytes(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("labfixture: decode manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Manifest{}, fmt.Errorf("labfixture: manifest must contain one JSON object")
	}
	if manifest.Format != manifestFormat {
		return Manifest{}, fmt.Errorf("labfixture: unsupported manifest format %d", manifest.Format)
	}
	if manifest.Warning != ManifestWarning {
		return Manifest{}, fmt.Errorf("labfixture: manifest is missing the lab-only warning")
	}
	if err := validateManifestFiles(manifest.Files); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// validateManifestFiles requires exactly the minted file set with safe names.
func validateManifestFiles(files map[string]string) error {
	want := manifestFiles()
	if len(files) != len(want) {
		return fmt.Errorf("labfixture: manifest file set is incomplete")
	}
	for label, name := range want {
		if files[label] != name {
			return fmt.Errorf("labfixture: manifest file %q is invalid", label)
		}
	}
	return nil
}

// readLabFile reads one bounded regular file.
func readLabFile(path string, maximumBytes int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("labfixture: inspect %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("labfixture: %s must be a regular file", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("labfixture: open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("labfixture: inspect opened %s: %w", filepath.Base(path), err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("labfixture: %s changed while opening", filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if err != nil {
		zeroLabBytes(data)
		return nil, fmt.Errorf("labfixture: read %s: %w", filepath.Base(path), err)
	}
	if len(data) == 0 || len(data) > maximumBytes {
		zeroLabBytes(data)
		return nil, fmt.Errorf("labfixture: %s length is invalid", filepath.Base(path))
	}
	return data, nil
}
