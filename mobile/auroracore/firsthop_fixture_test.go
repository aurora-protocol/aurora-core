//go:build cgo

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/client"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	fixturePath       = "/assets/upload/42"
	fixtureIssuerPath = "/assets/issue/42"
)

// Fixture owns a strict TLS first hop, a bound issuer, and local echo destinations.
type Fixture struct {
	issuer            *issuerd.Service
	deployment        trust.VerifiedRelayDeployment
	templateAuthority protocol.PublicKeyRecord
	accessHint        admission.AccessHintCredential
	certificateRaw    []byte
	authority         string

	firstHop     *server.ProductionFirstHopServer
	serveResult  chan error
	listener     net.Listener
	cover        *httptest.Server
	tcp          net.Listener
	udp          *net.UDPConn
	replayCaches []*admission.RetentionFileReplayCache
	connections  atomic.Int32
	closeOnce    sync.Once
}

type firstHopFixtureResolver struct{}

func (firstHopFixtureResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if host == "dns.fixture.test" && network == "ip4" {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

type firstHopFixtureDNSResolver struct{}

func (firstHopFixtureDNSResolver) ExchangeDNS(_ context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("fixture DNS query is invalid")
	}
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	return response, nil
}

func newNativeSessionFixture(t testing.TB, now time.Time) *Fixture {
	t.Helper()
	if now.IsZero() || now.Unix() <= 0 {
		t.Fatal("first-hop fixture requires a valid time")
	}
	now = now.UTC().Truncate(time.Second)
	nowUnix := uint64(now.Unix())

	certificate, certificateRaw := firstHopCertificate(t)
	issuer, err := issuerd.NewHarnessService(nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	metadata := issuer.PublishIssuerMetadata()
	accessHint := admission.AccessHintCredential{
		HintIssuerID:  append([]byte(nil), metadata.IssuerID...),
		RelayBucketID: append([]byte(nil), metadata.RelayBucketScopes[0].RelayBucketID...),
		HintEpochID:   3,
		HintSelector:  firstHopRandomBytes(t, 16),
		HintSecret:    firstHopRandomBytes(t, 32),
		ExpiryUnix:    nowUnix + 1800,
		MaxUses:       1,
	}
	deployment, authority, epochClassical, epochPQ := firstHopDeployment(t, now, auroracrypto.PreHash(certificateRawSPKI(t, certificateRaw)))

	resolver, err := handshake.NewStaticAccessHintResolver([]admission.AccessHintCredential{accessHint})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := handshake.NewBlindRSAAdmissionVerifier(metadata.TokenKeyMappings[0].TokenVerificationKey.TokenVerificationKey)
	if err != nil {
		t.Fatal(err)
	}
	classicalSigner, err := handshake.NewECDSAP256TranscriptSigner(epochClassical)
	if err != nil {
		t.Fatal(err)
	}
	pqSigner, err := handshake.NewMLDSA65TranscriptSigner(epochPQ)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := handshake.NewFixedProxyPolicySelector(deployment.Suite(), registry.PolicyBalancedWeb, registry.RouteFast1, registry.ShapeNormal)
	if err != nil {
		t.Fatal(err)
	}
	replayDirectory := t.TempDir()
	hintSpentCache := firstHopRetentionReplayCache(t, filepath.Join(replayDirectory, "spent-hints"), nowUnix)
	tokenSpentCache := firstHopRetentionReplayCache(t, filepath.Join(replayDirectory, "spent-tokens"), nowUnix)
	bootstrapCache := firstHopRetentionReplayCache(t, filepath.Join(replayDirectory, "bootstrap"), nowUnix)
	driver, err := handshake.NewRelayDriver(handshake.RelayDriverConfig{
		Deployment:        deployment,
		HintResolver:      resolver,
		HintSpentCache:    hintSpentCache,
		AdmissionVerifier: verifier,
		TokenSpentCache:   tokenSpentCache,
		BootstrapCache:    bootstrapCache,
		ClassicalSigner:   classicalSigner,
		PQSigner:          pqSigner,
		PolicySelector:    policy,
		RequirePQ:         true,
		SessionLimits:     firstHopSessionLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cover := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	coverTarget, err := url.Parse(cover.URL)
	if err != nil {
		cover.Close()
		t.Fatal(err)
	}
	coverOrigin, err := server.NewProductionReverseProxyCoverOrigin(coverTarget)
	if err != nil {
		cover.Close()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		cover.Close()
		t.Fatal(err)
	}
	firstHop, err := server.NewProductionFirstHopServer(server.ProductionFirstHopOptions{
		Deployment:            deployment,
		Driver:                driver,
		ListenAddress:         "0.0.0.0:8443",
		Authority:             listener.Addr().String(),
		Path:                  fixturePath,
		TLSConfig:             &tls.Config{Certificates: []tls.Certificate{certificate}},
		CarrierStatus:         http.StatusCreated,
		CarrierHeader:         http.Header{"Content-Type": {"application/octet-stream"}, "X-Carrier-Mode": {"ordinary"}},
		CoverOrigin:           coverOrigin,
		ProxySession:          server.FirstHopProxySessionOptions{ExitPolicy: relay.ExitPolicy{AllowPrivate: true}, Dialer: &net.Dialer{}, Resolver: firstHopFixtureResolver{}, DNSResolver: firstHopFixtureDNSResolver{}, Limits: firstHopEgressLimits()},
		MaxConcurrentSessions: 4,
	})
	if err != nil {
		_ = listener.Close()
		cover.Close()
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = listener.Close()
		cover.Close()
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = tcp.Close()
		_ = listener.Close()
		cover.Close()
		t.Fatal(err)
	}
	fixture := &Fixture{
		issuer:            issuer,
		deployment:        deployment,
		templateAuthority: authority,
		accessHint:        accessHint,
		certificateRaw:    certificateRaw,
		authority:         listener.Addr().String(),
		firstHop:          firstHop,
		serveResult:       make(chan error, 1),
		listener:          listener,
		cover:             cover,
		tcp:               tcp,
		udp:               udp,
		replayCaches:      []*admission.RetentionFileReplayCache{hintSpentCache, tokenSpentCache, bootstrapCache},
	}
	go func() {
		fixture.serveResult <- firstHop.Serve(&countingListener{Listener: listener, accepted: &fixture.connections})
	}()
	go fixture.serveTCPEcho()
	go fixture.serveUDPEcho()
	t.Cleanup(func() { fixture.Close(t) })
	return fixture
}

// Provisioning returns a fully authenticated native provisioning bundle for this fixture.
func (f *Fixture) Provisioning(t testing.TB) client.NativeProvisioning {
	t.Helper()
	if f == nil || !f.deployment.Valid() {
		t.Fatal("first-hop fixture is unavailable")
	}
	descriptor, err := protocol.Encode(f.deployment.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	template, err := protocol.Encode(f.deployment.Template())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := protocol.Encode(f.templateAuthority)
	if err != nil {
		t.Fatal(err)
	}
	issuerMetadata, err := protocol.Encode(f.issuer.PublishIssuerMetadata())
	if err != nil {
		t.Fatal(err)
	}
	publishedIssuerMetadata := f.issuer.PublishIssuerMetadata()
	accessHint, err := admission.EncodeAccessHintCredential(f.accessHint)
	if err != nil {
		t.Fatal(err)
	}
	signedSeed, signedSeedRoots := firstHopSignedSeed(t, time.Now().UTC(), publishedIssuerMetadata, f.issuer.AuthorityKeys(), f.accessHint.HintIssuerID)
	policyOffer, err := protocol.Encode(protocol.PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{f.deployment.Suite()},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream},
		MinimumPolicyID:         registry.PolicyFastWeb,
		RequestedPolicyID:       registry.PolicyBalancedWeb,
		RequestedRouteModeID:    registry.RouteFast1,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
	})
	if err != nil {
		t.Fatal(err)
	}
	hints, err := protocol.Encode(protocol.ClientTransportHints{Padding: firstHopRandomBytes(t, 8)})
	if err != nil {
		t.Fatal(err)
	}
	requestHeaders, err := client.EncodeNativeHeaders(http.Header{"Accept": {"application/octet-stream"}})
	if err != nil {
		t.Fatal(err)
	}
	responseHeaders, err := client.EncodeNativeHeaders(http.Header{"Content-Type": {"application/octet-stream"}, "X-Carrier-Mode": {"ordinary"}})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := client.EncodeNativeTrustRoots([][]byte{f.certificateRaw})
	if err != nil {
		t.Fatal(err)
	}
	return client.NativeProvisioning{
		RelayURL:              "https://" + f.authority + fixturePath,
		IssuerURL:             "https://issuer.example",
		IssuerCarrierPath:     fixtureIssuerPath,
		IssuerMetadata:        issuerMetadata,
		SignedSeed:            signedSeed,
		SignedSeedRoots:       signedSeedRoots,
		Descriptor:            descriptor,
		TrustedDescriptorHash: f.deployment.DescriptorHash(),
		Template:              template,
		TemplateAuthorityKey:  authority,
		RequestClassID:        f.deployment.RequestClass().ClassID,
		Suite:                 f.deployment.Suite(),
		AccessHint:            accessHint,
		PolicyOffer:           policyOffer,
		TransportHints:        hints,
		RelayExpectedStatus:   http.StatusCreated,
		RelayRequestHeaders:   requestHeaders,
		RelayResponseHeaders:  responseHeaders,
		RelayTrustRoots:       roots,
	}
}

func firstHopSignedSeed(t testing.TB, now time.Time, metadata protocol.IssuerMetadata, bootstrapKeys []protocol.AuthorityKeyRecord, issuerID []byte) ([]byte, []protocol.AuthorityKeyRecord) {
	t.Helper()
	rootPrivateKey := firstHopECDSAKey(t)
	rootPublicKey := firstHopECDSAPublicRecord(t, rootPrivateKey)
	encodedRootPublicKey, err := protocol.Encode(rootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := protocol.AuthorityKeyRecord{
		AuthorityID:    firstHopRandomBytes(t, 16),
		AuthorityKeyID: trust.AuthorityKeyID(encodedRootPublicKey),
		AuthorityRole:  1,
		PublicKey:      rootPublicKey,
		ValidFromUnix:  uint64(now.Add(-time.Minute).Unix()),
		ValidUntilUnix: uint64(now.Add(time.Hour).Unix()),
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignSignedSeedRecord,
	}
	metadataHash, err := trust.IssuerMetadataHash(metadata)
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.SignedSeedRecord{
		SeedVersion:                registry.Version20,
		SeedID:                     firstHopRandomBytes(t, 16),
		ValidFromUnix:              uint64(now.Add(-time.Minute).Unix()),
		ValidUntilUnix:             uint64(now.Add(time.Hour).Unix()),
		DirectoryConsensusHint:     []byte("directory"),
		BridgeBucketHint:           []byte("bridge"),
		TokenIssuerHint:            append([]byte(nil), issuerID...),
		IssuerMetadataHash:         metadataHash,
		BootstrapAuthorityKeys:     cloneFirstHopAuthorityKeys(bootstrapKeys),
		BootstrapCoverTemplateHash: firstHopRandomBytes(t, 48),
		NextSeedCommitment:         firstHopRandomBytes(t, 48),
		SoftwareUpdateEpoch:        1,
		SeedSignature: protocol.ObjectSignature{
			SignerKeyID:     append([]byte(nil), root.AuthorityKeyID...),
			SignatureScheme: root.PublicKey.SignatureScheme,
			KeyEncoding:     root.PublicKey.KeyEncoding,
		},
	}
	input, err := trust.SignedSeedRecordSignatureInput(seed)
	if err != nil {
		t.Fatal(err)
	}
	seed.SeedSignature.Signature, err = ecdsa.SignASN1(rand.Reader, rootPrivateKey, input)
	if err != nil {
		t.Fatal(err)
	}
	encodedSeed, err := protocol.Encode(seed)
	if err != nil {
		t.Fatal(err)
	}
	return encodedSeed, []protocol.AuthorityKeyRecord{root}
}

func cloneFirstHopAuthorityKeys(keys []protocol.AuthorityKeyRecord) []protocol.AuthorityKeyRecord {
	cloned := make([]protocol.AuthorityKeyRecord, len(keys))
	for index, key := range keys {
		cloned[index] = key
		cloned[index].AuthorityID = append([]byte(nil), key.AuthorityID...)
		cloned[index].AuthorityKeyID = append([]byte(nil), key.AuthorityKeyID...)
		cloned[index].PublicKey.PublicKey = append([]byte(nil), key.PublicKey.PublicKey...)
	}
	return cloned
}

// Issue fulfills a portable-core issuer request with the fixture's bound issuer service.
func (f *Fixture) Issue(t testing.TB, requestBody []byte) []byte {
	t.Helper()
	kind, payload, err := server.DecodeCarrier(requestBody)
	if err != nil || kind != server.CarrierBlindRSAIssueReq {
		t.Fatalf("decode issuer request: kind=%d err=%v", kind, err)
	}
	nonce, contextHash, expiryUnix, err := server.DecodeCarrierIssueRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.issuer.IssueBlindRSA2048(issuerd.IssueBlindRSA2048Request{TokenNonce: nonce, RedemptionContextHash: contextHash, ExpiryUnix: expiryUnix})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	return server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encoded)
}

// TCPAddress returns the loopback address of the fixture TCP echo destination.
func (f *Fixture) TCPAddress(t testing.TB) [4]byte { return firstHopIPv4Address(t, f.tcp.Addr()) }

// TCPPort returns the fixture TCP echo port.
func (f *Fixture) TCPPort(t testing.TB) uint16 { return firstHopPort(t, f.tcp.Addr()) }

// UDPAddress returns the loopback address of the fixture UDP echo destination.
func (f *Fixture) UDPAddress(t testing.TB) [4]byte { return firstHopIPv4Address(t, f.udp.LocalAddr()) }

// UDPPort returns the fixture UDP echo port.
func (f *Fixture) UDPPort(t testing.TB) uint16 { return firstHopPort(t, f.udp.LocalAddr()) }

// ConnectionCount returns the number of TCP connections accepted by the strict first hop.
func (f *Fixture) ConnectionCount() int32 {
	if f == nil {
		return 0
	}
	return f.connections.Load()
}

func (f *Fixture) waitForConnections(t testing.TB, want int32) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if got := f.ConnectionCount(); got >= want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("first-hop connections = %d, want at least %d", f.ConnectionCount(), want)
		case <-tick.C:
		}
	}
}

func (f *Fixture) assertNoAdditionalConnections(t testing.TB, baseline int32, duration time.Duration) {
	t.Helper()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if got := f.ConnectionCount(); got > baseline {
			t.Fatalf("unexpected first-hop connection: got %d, baseline %d", got, baseline)
		}
		select {
		case <-timer.C:
			return
		case <-tick.C:
		}
	}
}

// Close releases every fixture listener and waits for the strict first-hop server to stop.
func (f *Fixture) Close(t testing.TB) {
	if f == nil {
		return
	}
	f.closeOnce.Do(func() {
		if f.firstHop != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := f.firstHop.Shutdown(ctx)
			cancel()
			if err != nil {
				t.Errorf("shutdown first-hop fixture: %v", err)
			}
		}
		if f.listener != nil {
			_ = f.listener.Close()
		}
		if f.tcp != nil {
			_ = f.tcp.Close()
		}
		if f.udp != nil {
			_ = f.udp.Close()
		}
		if f.cover != nil {
			f.cover.Close()
		}
		for _, cache := range f.replayCaches {
			if err := cache.Close(); err != nil {
				t.Errorf("close replay cache: %v", err)
			}
		}
		if f.serveResult != nil {
			select {
			case err := <-f.serveResult:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("serve first-hop fixture: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("first-hop fixture did not stop")
			}
		}
	})
}

func (f *Fixture) serveTCPEcho() {
	for {
		connection, err := f.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func (f *Fixture) serveUDPEcho() {
	buffer := make([]byte, 65535)
	for {
		count, address, err := f.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		_, _ = f.udp.WriteToUDP(buffer[:count], address)
	}
}

type countingListener struct {
	net.Listener
	accepted *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil && l.accepted != nil {
		l.accepted.Add(1)
	}
	return connection, err
}

func firstHopRetentionReplayCache(t testing.TB, path string, nowUnix uint64) *admission.RetentionFileReplayCache {
	t.Helper()
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	cache, err := admission.NewRetentionFileReplayCacheAt(directory, filepath.Base(path), nowUnix)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	if !cache.Durable() {
		_ = cache.Close()
		t.Fatal("first-hop fixture requires durable replay storage")
	}
	return cache
}

func firstHopDeployment(t testing.TB, now time.Time, originSPKIHash []byte) (trust.VerifiedRelayDeployment, protocol.PublicKeyRecord, *ecdsa.PrivateKey, *mldsa65.PrivateKey) {
	t.Helper()
	nowUnix := uint64(now.Unix())
	longtermClassical := firstHopECDSAKey(t)
	epochClassical := firstHopECDSAKey(t)
	templateAuthority := firstHopECDSAKey(t)
	longtermPQPublic, longtermPQ, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochPQPublic, epochPQ, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       firstHopRandomBytes(t, 16),
		TemplateFamilyID: firstHopRandomBytes(t, 16),
		ValidFromUnix:    nowUnix - 60,
		ValidUntilUnix:   nowUnix + 3600,
		OriginSPKIHash:   append([]byte(nil), originSPKIHash...),
		PublicNameHash:   firstHopRandomBytes(t, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             7,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      firstHopRandomBytes(t, 16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{firstHopRandomBytes(t, 48)},
		OriginPassThroughSlotCommitments: [][]byte{firstHopRandomBytes(t, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  firstHopRandomBytes(t, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: firstHopRandomBytes(t, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               firstHopRandomBytes(t, 16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   firstHopRandomBytes(t, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile:         protocol.H2CoverProfile{ProfileID: 1, RecordSizeDistributionID: firstHopRandomBytes(t, 16)},
		H3Profile:         protocol.H3CoverProfile{ProfileID: 2, DatagramSizeDistributionID: firstHopRandomBytes(t, 16), DatagramRateDistributionID: firstHopRandomBytes(t, 16)},
		WebSocketProfile:  protocol.WebSocketCoverProfile{ProfileID: 3, FrameSizeDistributionID: firstHopRandomBytes(t, 16)},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: firstHopRandomBytes(t, 16)},
	}
	commitment, err := trust.CoverOriginCommitment(template)
	if err != nil {
		t.Fatal(err)
	}
	template.CoverOriginCommitment = commitment
	templateHash, err := trust.CoverTemplateHash(template)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      firstHopRandomBytes(t, 32),
		RoleFlags:                    1,
		ValidFromUnix:                nowUnix - 60,
		ValidUntilUnix:               nowUnix + 3600,
		RelayLongtermClassicalKey:    firstHopECDSAPublicRecord(t, longtermClassical),
		RelayLongtermPQKey:           protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: longtermPQPublic.Bytes()},
		EpochID:                      9,
		EpochAuthClassicalKey:        firstHopECDSAPublicRecord(t, epochClassical),
		EpochAuthPQKey:               protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: epochPQPublic.Bytes()},
		EpochValidFromUnix:           nowUnix - 60,
		EpochValidUntilUnix:          nowUnix + 1800,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    nowUnix + 1800,
		ReplayWindowID:               firstHopRandomBytes(t, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: firstHopRandomBytes(t, 48),
		SupportedShapeIDsCommitment:  firstHopRandomBytes(t, 48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         firstHopRandomBytes(t, 48),
		AbusePolicyCommitment:        firstHopRandomBytes(t, 48),
	}
	descriptorInput, err := trust.RelayDescriptorSignatureInput(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermClassical, err = ecdsa.SignASN1(rand.Reader, longtermClassical, descriptorInput)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermPQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(longtermPQ, descriptorInput, nil, false, descriptor.SignatureByLongtermPQ); err != nil {
		t.Fatal(err)
	}
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	familyInput, err := trust.CoverTemplateFamilySignatureInput(template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthority, familyInput)
	if err != nil {
		t.Fatal(err)
	}
	instanceInput, err := trust.CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, instanceInput)
	if err != nil {
		t.Fatal(err)
	}
	authority := firstHopECDSAPublicRecord(t, templateAuthority)
	deployment, err := trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    descriptorHash,
		Template:                 template,
		TemplateAuthorityKey:     authority,
		RequestClassID:           7,
		Suite:                    registry.SuiteHybrid768P256AESGCM,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  nowUnix,
		MaxTemplateFutureSkew:    120,
		RequirePQDescriptorProof: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return deployment, authority, epochClassical, epochPQ
}

func firstHopCertificate(t testing.TB) (tls.Certificate, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := server.TLS.Certificates[0]
	raw := append([]byte(nil), certificate.Certificate[0]...)
	server.Close()
	return certificate, raw
}

func certificateRawSPKI(t testing.TB, raw []byte) []byte {
	t.Helper()
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return certificate.RawSubjectPublicKeyInfo
}

func firstHopSessionLimits() session.Limits {
	return session.Limits{MaxQueuedPackets: 64, MaxQueuedBytes: 1 << 20, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 1024}
}

func firstHopEgressLimits() relay.SocketEgressLimits {
	return relay.SocketEgressLimits{
		MaxFlows:            16,
		MaxBufferedBytes:    1 << 20,
		TCPReadBufferBytes:  16 << 10,
		MaxUDPDatagramBytes: 65535,
		DialTimeout:         time.Second,
		WriteTimeout:        time.Second,
		IdleTimeout:         time.Minute,
		QueueRetryInterval:  time.Millisecond,
		ResolvedTTLSeconds:  60,
	}
}

func firstHopECDSAKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func firstHopECDSAPublicRecord(t testing.TB, key *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	t.Helper()
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA384DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: encoded}
}

func firstHopRandomBytes(t testing.TB, length int) []byte {
	t.Helper()
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func firstHopIPv4Address(t testing.TB, address net.Addr) [4]byte {
	t.Helper()
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("fixture address is not IPv4: %s", address)
	}
	return [4]byte(ip)
}

func firstHopPort(t testing.TB, address net.Addr) uint16 {
	t.Helper()
	_, text, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", text)
	if err != nil || port <= 0 || port > 65535 {
		t.Fatalf("fixture port is invalid: %s", address)
	}
	return uint16(port)
}
