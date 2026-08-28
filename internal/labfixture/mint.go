package labfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/client"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	// RelayPath is the carrier path the lab relay first hop serves.
	RelayPath = "/assets/upload/42"
	// IssuerCarrierPath is the carrier path the lab issuer backend serves.
	IssuerCarrierPath = "/assets/issue/42"

	// DefaultRelayHost binds the minted wallet to loopback.
	DefaultRelayHost = "127.0.0.1"
	// DefaultRelayPort is the default public relay port recorded in the wallet.
	DefaultRelayPort = 9443
	// DefaultIssuerPort is the default issuer port recorded in the wallet.
	DefaultIssuerPort = 9444
	// DefaultEntries is the default number of one-time provisioning entries.
	DefaultEntries = 8
	// MaximumEntries bounds one minted wallet (the production wallet ceiling).
	MaximumEntries = 64
	// DefaultValidity bounds every minted object except the long-lived
	// signed-seed trust anchor.
	DefaultValidity = 24 * time.Hour
	minValidity     = time.Minute
	maxValidity     = 7 * 24 * time.Hour

	labRequestClassID      = 7
	labOriginInfoPolicyID  = 7
	labEpochID             = 9
	labReplayEpochID       = 10
	labHintEpochID         = 3
	labAuthorityValidUntil = 4_102_444_800 // 2100-01-01, lab trust anchor convenience
)

// MintOptions controls one lab deployment mint. The zero value is valid and
// mints a loopback deployment.
type MintOptions struct {
	// RelayHost is the hostname or IP clients dial; it is embedded in the
	// wallet relay/issuer URLs and the minted TLS certificate SANs.
	RelayHost string
	// RelayPort is the public relay port recorded in the wallet.
	RelayPort int
	// IssuerPort is the public issuer port recorded in the wallet.
	IssuerPort int
	// Entries is the number of one-time provisioning entries in the wallet.
	Entries int
	// Validity bounds descriptor, template, issuer metadata, hints, and seed.
	Validity time.Duration
	// Now overrides the mint time; zero uses the current time.
	Now time.Time
}

func (options MintOptions) normalized() (MintOptions, error) {
	if options.RelayHost == "" {
		options.RelayHost = DefaultRelayHost
	}
	if options.RelayPort == 0 {
		options.RelayPort = DefaultRelayPort
	}
	if options.IssuerPort == 0 {
		options.IssuerPort = DefaultIssuerPort
	}
	if options.Entries == 0 {
		options.Entries = DefaultEntries
	}
	if options.Validity == 0 {
		options.Validity = DefaultValidity
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	options.Now = options.Now.UTC().Truncate(time.Second)
	if err := validateLabHost(options.RelayHost); err != nil {
		return MintOptions{}, err
	}
	if options.RelayPort <= 0 || options.RelayPort > 65535 || options.IssuerPort <= 0 || options.IssuerPort > 65535 {
		return MintOptions{}, fmt.Errorf("labfixture: relay and issuer ports must be between 1 and 65535")
	}
	if options.RelayPort == options.IssuerPort {
		return MintOptions{}, fmt.Errorf("labfixture: relay and issuer ports must differ")
	}
	if options.Entries <= 0 || options.Entries > MaximumEntries {
		return MintOptions{}, fmt.Errorf("labfixture: wallet entry count must be between 1 and %d", MaximumEntries)
	}
	if options.Validity < minValidity || options.Validity > maxValidity {
		return MintOptions{}, fmt.Errorf("labfixture: validity must be between %s and %s", minValidity, maxValidity)
	}
	if options.Now.Unix() <= 0 {
		return MintOptions{}, fmt.Errorf("labfixture: mint time is invalid")
	}
	return options, nil
}

// validateLabHost accepts a literal IP address or a conservative DNS name.
func validateLabHost(host string) error {
	if strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host || len(host) > 253 {
		return fmt.Errorf("labfixture: relay host is invalid")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("labfixture: relay host %q is not a valid IP or DNS name", host)
		}
		for index, value := range label {
			isDigit := value >= '0' && value <= '9'
			isLetter := value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
			if !isDigit && !isLetter && value != '-' {
				return fmt.Errorf("labfixture: relay host %q is not a valid IP or DNS name", host)
			}
			if (index == 0 || index == len(label)-1) && value == '-' {
				return fmt.Errorf("labfixture: relay host %q is not a valid IP or DNS name", host)
			}
		}
	}
	return nil
}

// Mint constructs a complete, self-consistent lab deployment in memory using
// only production APIs. The result holds private key material; call WriteTo
// to persist it and Zero to erase it.
func Mint(options MintOptions) (_ *Material, err error) {
	options, err = options.normalized()
	if err != nil {
		return nil, err
	}
	nowUnix := uint64(options.Now.Unix())
	validFrom := nowUnix - 60
	validUntil := nowUnix + uint64(options.Validity.Seconds())
	relayAuthority := net.JoinHostPort(options.RelayHost, fmt.Sprintf("%d", options.RelayPort))
	issuerAuthority := net.JoinHostPort(options.RelayHost, fmt.Sprintf("%d", options.IssuerPort))

	material := &Material{}
	defer func() {
		if err != nil {
			material.Zero()
		}
	}()

	// Relay TLS certificate (self-signed, SANs cover the minted relay host).
	certificateRaw, certificatePEM, keyPEM, err := mintLabTLSCertificate(options.RelayHost, options.Now, options.Validity)
	if err != nil {
		return nil, err
	}
	originSPKIHash := auroracrypto.PreHash(certificateRawSPKI(certificateRaw))

	// Relay deployment: cover template + descriptor + signatures.
	deployment, templateAuthority, epochClassical, epochPQ, descriptorEncoded, descriptorHash, templateEncoded, authorityEncoded, err := mintLabDeployment(nowUnix, validFrom, validUntil, originSPKIHash)
	if err != nil {
		return nil, err
	}

	// Issuer metadata + Blind RSA key + issuer authority.
	issuerMetadata, issuerAuthorityRecord, blindRSAKeyPEM, tokenKeyDER, err := mintLabIssuer(validFrom, validUntil)
	if err != nil {
		return nil, err
	}
	issuerMetadataEncoded, err := protocol.Encode(issuerMetadata)
	if err != nil {
		return nil, err
	}
	issuerAuthorityEncoded, err := protocol.Encode(issuerAuthorityRecord)
	if err != nil {
		return nil, err
	}

	// One-time access hints, one per wallet entry.
	hints := make([]admission.AccessHintCredential, 0, options.Entries)
	for range options.Entries {
		hints = append(hints, admission.AccessHintCredential{
			HintIssuerID:  append([]byte(nil), issuerMetadata.IssuerID...),
			RelayBucketID: append([]byte(nil), issuerMetadata.RelayBucketScopes[0].RelayBucketID...),
			HintEpochID:   labHintEpochID,
			HintSelector:  labRandomBytes(16),
			HintSecret:    labRandomBytes(32),
			ExpiryUnix:    validUntil,
			MaxUses:       1,
		})
	}
	hintsEncoded, err := admission.EncodeAccessHintCredentialSet(hints)
	if err != nil {
		return nil, err
	}

	// Signed seed + long-lived lab trust anchor root.
	seedEncoded, seedRootRecord, err := mintLabSignedSeed(options.Now, validFrom, validUntil, issuerMetadata, issuerAuthorityRecord, deployment.TemplateHash())
	if err != nil {
		return nil, err
	}
	seedRootEncoded, err := protocol.Encode(seedRootRecord)
	if err != nil {
		return nil, err
	}

	// Sealed native provisioning trust (roots + deployment tuple).
	provisioningTrust, err := client.NewNativeProvisioningTrust([]protocol.AuthorityKeyRecord{seedRootRecord}, client.NativeProvisioningDeploymentTrust{
		DescriptorHash:       deployment.DescriptorHash(),
		CoverTemplateHash:    deployment.TemplateHash(),
		TemplateAuthorityKey: templateAuthority,
	})
	if err != nil {
		return nil, err
	}
	trustEncoded, err := client.EncodeNativeProvisioningTrust(provisioningTrust)
	if err != nil {
		return nil, err
	}

	// Wallet with one provisioning entry per access hint.
	trustRoots, err := client.EncodeNativeTrustRoots([][]byte{certificateRaw})
	if err != nil {
		return nil, err
	}
	entries := make([]client.NativeProvisioning, 0, options.Entries)
	for _, hint := range hints {
		entry, entryErr := mintLabProvisioningEntry(mintLabEntryInputs{
			relayURL:          "https://" + relayAuthority + RelayPath,
			issuerURL:         "https://" + issuerAuthority,
			issuerMetadata:    issuerMetadataEncoded,
			signedSeed:        seedEncoded,
			descriptor:        descriptorEncoded,
			descriptorHash:    descriptorHash,
			template:          templateEncoded,
			templateAuthority: authorityEncoded,
			deployment:        deployment,
			hint:              hint,
			trustRoots:        trustRoots,
		})
		if entryErr != nil {
			return nil, entryErr
		}
		entries = append(entries, entry)
	}
	walletEncoded, err := client.EncodeNativeProvisioningWallet(entries)
	if err != nil {
		return nil, err
	}

	// Persisted signer keys.
	epochClassicalPEM, err := mintLabECPrivateKeyPEM(epochClassical)
	if err != nil {
		return nil, err
	}
	epochPQEncoded, err := epochPQ.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("labfixture: encode epoch PQ key: %w", err)
	}
	zeroLabECDSAKey(epochClassical)
	zeroLabMLDSA65Key(epochPQ)

	material.Manifest = Manifest{
		Format:         manifestFormat,
		Warning:        ManifestWarning,
		CreatedUnix:    nowUnix,
		ValidUntilUnix: validUntil,
		Relay: ManifestRelay{
			URL:            "https://" + relayAuthority + RelayPath,
			Host:           options.RelayHost,
			Port:           options.RelayPort,
			Authority:      relayAuthority,
			Path:           RelayPath,
			RequestClassID: labRequestClassID,
			Suite:          registry.SuiteHybrid768P256AESGCM,
		},
		Issuer: ManifestIssuer{
			URL:         "https://" + issuerAuthority,
			Host:        options.RelayHost,
			Port:        options.IssuerPort,
			CarrierPath: IssuerCarrierPath,
		},
		Entries: options.Entries,
		Files:   manifestFiles(),
	}
	material.files = []labFile{
		{name: FileRelayDescriptor, data: descriptorEncoded},
		{name: FileRelayDescriptorHash, data: descriptorHash},
		{name: FileCoverTemplate, data: templateEncoded},
		{name: FileTemplateAuthorityKey, data: authorityEncoded},
		{name: FileEpochClassicalKey, data: epochClassicalPEM},
		{name: FileEpochPQKey, data: epochPQEncoded},
		{name: FileAccessHints, data: hintsEncoded},
		{name: FileTokenVerificationKey, data: tokenKeyDER},
		{name: FileIssuerMetadata, data: issuerMetadataEncoded},
		{name: FileIssuerAuthorityKey, data: issuerAuthorityEncoded},
		{name: FileIssuerBlindRSAKey, data: blindRSAKeyPEM},
		{name: FileSeedRootAuthorityKey, data: seedRootEncoded},
		{name: FileNativeProvisioningTrust, data: trustEncoded},
		{name: FileWallet, data: walletEncoded},
		{name: FileTLSCertificate, data: certificatePEM},
		{name: FileTLSPrivateKey, data: keyPEM},
	}
	return material, nil
}

type mintLabEntryInputs struct {
	relayURL          string
	issuerURL         string
	issuerMetadata    []byte
	signedSeed        []byte
	descriptor        []byte
	descriptorHash    []byte
	template          []byte
	templateAuthority []byte
	deployment        trust.VerifiedRelayDeployment
	hint              admission.AccessHintCredential
	trustRoots        []byte
}

// mintLabProvisioningEntry builds one complete production provisioning bundle.
func mintLabProvisioningEntry(inputs mintLabEntryInputs) (client.NativeProvisioning, error) {
	accessHint, err := admission.EncodeAccessHintCredential(inputs.hint)
	if err != nil {
		return client.NativeProvisioning{}, err
	}
	policyOffer, err := protocol.Encode(protocol.PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{inputs.deployment.Suite()},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream},
		MinimumPolicyID:         registry.PolicyFastWeb,
		RequestedPolicyID:       registry.PolicyBalancedWeb,
		RequestedRouteModeID:    registry.RouteFast1,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
	})
	if err != nil {
		return client.NativeProvisioning{}, err
	}
	transportHints, err := protocol.Encode(protocol.ClientTransportHints{Padding: labRandomBytes(8)})
	if err != nil {
		return client.NativeProvisioning{}, err
	}
	requestHeaders, err := client.EncodeNativeHeaders(http.Header{"Accept": {"application/octet-stream"}})
	if err != nil {
		return client.NativeProvisioning{}, err
	}
	responseHeaders, err := client.EncodeNativeHeaders(http.Header{"Content-Type": {"application/octet-stream"}, "X-Carrier-Mode": {"ordinary"}})
	if err != nil {
		return client.NativeProvisioning{}, err
	}
	return client.NativeProvisioning{
		RelayURL:              inputs.relayURL,
		IssuerURL:             inputs.issuerURL,
		IssuerCarrierPath:     IssuerCarrierPath,
		IssuerMetadata:        append([]byte(nil), inputs.issuerMetadata...),
		SignedSeed:            append([]byte(nil), inputs.signedSeed...),
		Descriptor:            append([]byte(nil), inputs.descriptor...),
		TrustedDescriptorHash: append([]byte(nil), inputs.descriptorHash...),
		Template:              append([]byte(nil), inputs.template...),
		TemplateAuthorityKey:  append([]byte(nil), inputs.templateAuthority...),
		RequestClassID:        labRequestClassID,
		Suite:                 inputs.deployment.Suite(),
		AccessHint:            accessHint,
		PolicyOffer:           policyOffer,
		TransportHints:        transportHints,
		RelayExpectedStatus:   http.StatusCreated,
		RelayRequestHeaders:   requestHeaders,
		RelayResponseHeaders:  responseHeaders,
		RelayTrustRoots:       append([]byte(nil), inputs.trustRoots...),
	}, nil
}

// mintLabDeployment builds and cross-signs the cover template and relay
// descriptor, then verifies the deployment through the production verifier.
// The epoch signer private keys are returned for persistence; all other
// private keys are erased before returning.
func mintLabDeployment(nowUnix, validFrom, validUntil uint64, originSPKIHash []byte) (
	deployment trust.VerifiedRelayDeployment,
	templateAuthority protocol.PublicKeyRecord,
	epochClassical *ecdsa.PrivateKey,
	epochPQ *mldsa65.PrivateKey,
	descriptorEncoded, descriptorHash, templateEncoded, authorityEncoded []byte,
	err error,
) {
	longtermClassical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	defer zeroLabECDSAKey(longtermClassical)
	epochClassical, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	templateAuthorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	defer zeroLabECDSAKey(templateAuthorityKey)
	longtermPQPublic, longtermPQ, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	defer zeroLabMLDSA65Key(longtermPQ)
	epochPQPublic, epochPQKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}

	template := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       labRandomBytes(16),
		TemplateFamilyID: labRandomBytes(16),
		ValidFromUnix:    validFrom,
		ValidUntilUnix:   validUntil,
		OriginSPKIHash:   append([]byte(nil), originSPKIHash...),
		PublicNameHash:   labRandomBytes(48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             labRequestClassID,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      labRandomBytes(16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{labRandomBytes(48)},
		OriginPassThroughSlotCommitments: [][]byte{labRandomBytes(48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  labRandomBytes(16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: labRandomBytes(16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               labRandomBytes(16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   labRandomBytes(16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile:         protocol.H2CoverProfile{ProfileID: 1, RecordSizeDistributionID: labRandomBytes(16)},
		H3Profile:         protocol.H3CoverProfile{ProfileID: 2, DatagramSizeDistributionID: labRandomBytes(16), DatagramRateDistributionID: labRandomBytes(16)},
		WebSocketProfile:  protocol.WebSocketCoverProfile{ProfileID: 3, FrameSizeDistributionID: labRandomBytes(16)},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: labRandomBytes(16)},
	}
	template.CoverOriginCommitment, err = trust.CoverOriginCommitment(template)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	templateHash, err := trust.CoverTemplateHash(template)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      labRandomBytes(32),
		RoleFlags:                    1,
		ValidFromUnix:                validFrom,
		ValidUntilUnix:               validUntil,
		RelayLongtermClassicalKey:    labECDSAPublicRecord(&longtermClassical.PublicKey),
		RelayLongtermPQKey:           protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: longtermPQPublic.Bytes()},
		EpochID:                      labEpochID,
		EpochAuthClassicalKey:        labECDSAPublicRecord(&epochClassical.PublicKey),
		EpochAuthPQKey:               protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: epochPQPublic.Bytes()},
		EpochValidFromUnix:           validFrom,
		EpochValidUntilUnix:          validUntil,
		ReplayEpochID:                labReplayEpochID,
		ReplayEpochValidUntilUnix:    validUntil,
		ReplayWindowID:               labRandomBytes(16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: labRandomBytes(48),
		SupportedShapeIDsCommitment:  labRandomBytes(48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         labRandomBytes(48),
		AbusePolicyCommitment:        labRandomBytes(48),
	}
	descriptorInput, err := trust.RelayDescriptorSignatureInput(descriptor)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	descriptor.SignatureByLongtermClassical, err = ecdsa.SignASN1(rand.Reader, longtermClassical, descriptorInput)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	descriptor.SignatureByLongtermPQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(longtermPQ, descriptorInput, nil, false, descriptor.SignatureByLongtermPQ); err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	descriptorHash, err = trust.RelayDescriptorHash(descriptor)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	familyInput, err := trust.CoverTemplateFamilySignatureInput(template)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthorityKey, familyInput)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	instanceInput, err := trust.CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, instanceInput)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	templateAuthority = labECDSAPublicRecord(&templateAuthorityKey.PublicKey)
	deployment, err = trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    descriptorHash,
		Template:                 template,
		TemplateAuthorityKey:     templateAuthority,
		RequestClassID:           labRequestClassID,
		Suite:                    registry.SuiteHybrid768P256AESGCM,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  nowUnix,
		MaxTemplateFutureSkew:    120,
		RequirePQDescriptorProof: true,
	})
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	descriptorEncoded, err = protocol.Encode(descriptor)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	templateEncoded, err = protocol.Encode(template)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	authorityEncoded, err = protocol.Encode(templateAuthority)
	if err != nil {
		return trust.VerifiedRelayDeployment{}, protocol.PublicKeyRecord{}, nil, nil, nil, nil, nil, nil, err
	}
	return deployment, templateAuthority, epochClassical, epochPQKey, descriptorEncoded, descriptorHash, templateEncoded, authorityEncoded, nil
}

// mintLabIssuer builds issuer metadata carrying exactly one Blind RSA token
// key plus the metadata authority record. The authority private key and the
// in-memory RSA key are erased before returning; their encodings are
// returned for persistence.
func mintLabIssuer(validFrom, validUntil uint64) (metadata protocol.IssuerMetadata, authorityRecord protocol.AuthorityKeyRecord, blindRSAKeyPEM, tokenKeyDER []byte, err error) {
	blindRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return protocol.IssuerMetadata{}, protocol.AuthorityKeyRecord{}, nil, nil, err
	}
	tokenKeyDER, err = marshalLabRSAPSSPublicKey(&blindRSAKey.PublicKey)
	if err != nil {
		zeroLabRSAKey(blindRSAKey)
		return protocol.IssuerMetadata{}, protocol.AuthorityKeyRecord{}, nil, nil, err
	}
	tokenKeyID := sha256.Sum256(tokenKeyDER)
	issuerAuthority, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		zeroLabRSAKey(blindRSAKey)
		return protocol.IssuerMetadata{}, protocol.AuthorityKeyRecord{}, nil, nil, err
	}
	defer zeroLabECDSAKey(issuerAuthority)
	issuerAuthorityPublic := labECDSAPublicRecord(&issuerAuthority.PublicKey)
	encodedIssuerAuthorityPublic, err := protocol.Encode(issuerAuthorityPublic)
	if err != nil {
		zeroLabRSAKey(blindRSAKey)
		return protocol.IssuerMetadata{}, protocol.AuthorityKeyRecord{}, nil, nil, err
	}
	issuerAuthorityKeyID := trust.AuthorityKeyID(encodedIssuerAuthorityPublic)
	metadata = protocol.IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            labRandomBytes(16),
		ValidFromUnix:       validFrom,
		ValidUntilUnix:      validUntil,
		IssuerName:          []byte("issuer.auroralab.invalid"),
		SupportedProofTypes: []uint64{registry.ProofBlindRSA2048},
		TokenKeyMappings: []protocol.IssuerTokenKeyRecord{{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: tokenKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       tokenKeyDER,
			},
			ValidFromUnix:  validFrom,
			ValidUntilUnix: validUntil,
			KeyStatus:      registry.IssuerStatusActive,
		}},
		OriginInfoPolicies: []protocol.OriginInfoPolicy{{
			PolicyID:             labOriginInfoPolicyID,
			OriginInfo:           []byte("origin.auroralab.invalid"),
			AllowEmptyOriginInfo: false,
			ValidFromUnix:        validFrom,
			ValidUntilUnix:       validUntil,
		}},
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         labRandomBytes(16),
			TokenScopeID:          labRandomBytes(16),
			AllowedOriginPolicyID: []uint64{labOriginInfoPolicyID},
			ValidFromUnix:         validFrom,
			ValidUntilUnix:        validUntil,
		}},
		MetadataSigningKeyID: issuerAuthorityKeyID,
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
	metadataInput, err := trust.IssuerMetadataSignatureInput(metadata)
	if err != nil {
		zeroLabRSAKey(blindRSAKey)
		return protocol.IssuerMetadata{}, protocol.AuthorityKeyRecord{}, nil, nil, err
	}
	metadata.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, issuerAuthority, metadataInput)
	if err != nil {
		zeroLabRSAKey(blindRSAKey)
		return protocol.IssuerMetadata{}, protocol.AuthorityKeyRecord{}, nil, nil, err
	}
	authorityRecord = protocol.AuthorityKeyRecord{
		AuthorityID:    labRandomBytes(16),
		AuthorityKeyID: issuerAuthorityKeyID,
		AuthorityRole:  1,
		PublicKey:      issuerAuthorityPublic,
		ValidFromUnix:  validFrom,
		ValidUntilUnix: validUntil,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}
	encodedKey := x509.MarshalPKCS1PrivateKey(blindRSAKey)
	zeroLabRSAKey(blindRSAKey)
	blindRSAKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: encodedKey})
	zeroLabBytes(encodedKey)
	if len(blindRSAKeyPEM) == 0 {
		return protocol.IssuerMetadata{}, protocol.AuthorityKeyRecord{}, nil, nil, fmt.Errorf("labfixture: encode Blind RSA key failed")
	}
	return metadata, authorityRecord, blindRSAKeyPEM, tokenKeyDER, nil
}

// mintLabSignedSeed signs one seed with a fresh lab trust anchor and returns
// the anchor record. The anchor private key is erased before returning.
func mintLabSignedSeed(now time.Time, validFrom, validUntil uint64, metadata protocol.IssuerMetadata, issuerAuthority protocol.AuthorityKeyRecord, bootstrapTemplateHash []byte) (seedEncoded []byte, root protocol.AuthorityKeyRecord, err error) {
	rootPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, protocol.AuthorityKeyRecord{}, err
	}
	defer zeroLabECDSAKey(rootPrivateKey)
	rootPublicKey := labECDSAPublicRecord(&rootPrivateKey.PublicKey)
	encodedRootPublicKey, err := protocol.Encode(rootPublicKey)
	if err != nil {
		return nil, protocol.AuthorityKeyRecord{}, err
	}
	defer zeroLabBytes(encodedRootPublicKey)
	root = protocol.AuthorityKeyRecord{
		AuthorityID:    labRandomBytes(16),
		AuthorityKeyID: trust.AuthorityKeyID(encodedRootPublicKey),
		AuthorityRole:  1,
		PublicKey:      rootPublicKey,
		ValidFromUnix:  1,
		ValidUntilUnix: labAuthorityValidUntil,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignSignedSeedRecord,
	}
	metadataHash, err := trust.IssuerMetadataHash(metadata)
	if err != nil {
		return nil, protocol.AuthorityKeyRecord{}, err
	}
	seed := protocol.SignedSeedRecord{
		SeedVersion:                registry.Version20,
		SeedID:                     labRandomBytes(16),
		ValidFromUnix:              validFrom,
		ValidUntilUnix:             validUntil,
		DirectoryConsensusHint:     []byte("auroralab-directory"),
		BridgeBucketHint:           []byte("auroralab-bridge"),
		TokenIssuerHint:            append([]byte(nil), metadata.IssuerID...),
		IssuerMetadataHash:         metadataHash,
		BootstrapAuthorityKeys:     []protocol.AuthorityKeyRecord{issuerAuthority},
		BootstrapCoverTemplateHash: append([]byte(nil), bootstrapTemplateHash...),
		NextSeedCommitment:         labRandomBytes(48),
		SoftwareUpdateEpoch:        1,
		SeedSignature: protocol.ObjectSignature{
			SignerKeyID:     append([]byte(nil), root.AuthorityKeyID...),
			SignatureScheme: root.PublicKey.SignatureScheme,
			KeyEncoding:     root.PublicKey.KeyEncoding,
		},
	}
	input, err := trust.SignedSeedRecordSignatureInput(seed)
	if err != nil {
		return nil, protocol.AuthorityKeyRecord{}, err
	}
	seed.SeedSignature.Signature, err = ecdsa.SignASN1(rand.Reader, rootPrivateKey, input)
	if err != nil {
		return nil, protocol.AuthorityKeyRecord{}, err
	}
	seedEncoded, err = protocol.Encode(seed)
	if err != nil {
		return nil, protocol.AuthorityKeyRecord{}, err
	}
	return seedEncoded, root, nil
}

// mintLabTLSCertificate creates a self-signed TLS server certificate whose
// SANs cover the minted relay host. It returns the raw leaf DER plus the PEM
// encodings for persistence.
func mintLabTLSCertificate(host string, now time.Time, validity time.Duration) (rawDER, certificatePEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	defer zeroLabECDSAKey(key)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "auroralab lab relay (local lab testing only)"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		template.IPAddresses = []net.IP{net.IP(ip.AsSlice())}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	certificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	zeroLabBytes(keyDER)
	if len(certificatePEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, nil, fmt.Errorf("labfixture: encode TLS certificate failed")
	}
	if _, err := tls.X509KeyPair(certificatePEM, keyPEM); err != nil {
		return nil, nil, nil, fmt.Errorf("labfixture: minted TLS certificate does not parse: %w", err)
	}
	return append([]byte(nil), der...), certificatePEM, keyPEM, nil
}

// mintLabECPrivateKeyPEM encodes one ECDSA private key as SEC1 PEM.
func mintLabECPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("labfixture: encode ECDSA private key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	zeroLabBytes(der)
	if len(encoded) == 0 {
		return nil, fmt.Errorf("labfixture: encode ECDSA private key failed")
	}
	return encoded, nil
}

// labECDSAPublicRecord returns the production public key record for a P-256 key.
func labECDSAPublicRecord(key *ecdsa.PublicKey) protocol.PublicKeyRecord {
	encoded, err := key.Bytes()
	if err != nil {
		return protocol.PublicKeyRecord{}
	}
	return protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA384DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: encoded}
}

// certificateRawSPKI extracts the subject public key info of a raw certificate.
func certificateRawSPKI(raw []byte) []byte {
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil
	}
	return certificate.RawSubjectPublicKeyInfo
}

// marshalLabRSAPSSPublicKey encodes an RSA public key as an RSASSA-PSS
// SubjectPublicKeyInfo, the format the Blind RSA admission verifier expects.
func marshalLabRSAPSSPublicKey(key *rsa.PublicKey) ([]byte, error) {
	rsaKey, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{N: key.N, E: key.E})
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return encoded, nil
}

// labRandomBytes returns fresh random bytes; the process cannot continue
// safely without randomness, so a failure is fatal to the mint.
func labRandomBytes(length int) []byte {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		panic(fmt.Sprintf("labfixture: randomness unavailable: %v", err))
	}
	return value
}
