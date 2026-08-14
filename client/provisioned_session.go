package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/carrier"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
)

const (
	maximumProvisionedIssuerResponse = 1 << 20
	defaultProvisionedHandshakeWait  = 30 * time.Second
	defaultProvisionedIssuerWait     = 2 * time.Minute
	defaultProvisionedIssuerLifetime = 5 * time.Minute
	defaultProvisionedCompleteWait   = 30 * time.Second
)

// IssuerWork is one bounded opaque request that must be sent to the configured issuer.
type IssuerWork struct {
	IssuerURL         string
	IssuerCarrierPath string
	RequestBody       []byte
}

// Zero erases the caller-owned issuer request once it has been submitted or abandoned.
func (w *IssuerWork) Zero() {
	if w == nil {
		return
	}
	zeroProvisionedBytes(w.RequestBody)
	*w = IssuerWork{}
}

// ProvisionedSessionOptions controls the bounded lifecycle of a provisioned client.
type ProvisionedSessionOptions struct {
	HandshakeTimeout  time.Duration
	IssuerTimeout     time.Duration
	IssuerLifetime    time.Duration
	CompletionTimeout time.Duration

	now    func() time.Time
	random io.Reader
	start  provisionedSessionStarter
}

type provisionedSessionHandshake interface {
	Complete(context.Context, protocol.AdmissionProof, protocol.ReplayProof) (*handshake.EstablishedSession, error)
	Close() error
}

type provisionedSessionStarter func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error)

// ProvisionedSession owns a deferred handshake from prelude verification until shutdown.
type ProvisionedSession struct {
	mu sync.Mutex

	ctx            context.Context
	cancel         context.CancelFunc
	handshake      provisionedSessionHandshake
	request        handshake.ClientProofRequest
	established    *handshake.EstablishedSession
	issuerTimer    *time.Timer
	issuerMetadata protocol.IssuerMetadata
	options        ProvisionedSessionOptions

	completing bool
	closed     bool
}

// BeginProvisionedSession opens the verified relay carrier and returns the issuer work needed to finish authentication.
func BeginProvisionedSession(ctx context.Context, provisioning NativeProvisioning, options ProvisionedSessionOptions) (*ProvisionedSession, IssuerWork, error) {
	return newProvisionedSession(ctx, provisioning, options)
}

func newProvisionedSession(ctx context.Context, provisioning NativeProvisioning, options ProvisionedSessionOptions) (*ProvisionedSession, IssuerWork, error) {
	if ctx == nil {
		return nil, IssuerWork{}, fmt.Errorf("client: nil provisioned session context")
	}
	if err := ctx.Err(); err != nil {
		return nil, IssuerWork{}, err
	}
	options = normalizeProvisionedSessionOptions(options)
	now := options.now().UTC()
	if now.IsZero() || now.Unix() < 0 {
		return nil, IssuerWork{}, fmt.Errorf("client: provisioned session requires a valid time")
	}
	issuerMetadata, err := provisioning.verifiedIssuerMetadataAt(now)
	if err != nil {
		return nil, IssuerWork{}, err
	}

	sessionContext, cancel := context.WithCancel(ctx)
	handshakeTimer := time.AfterFunc(options.HandshakeTimeout, cancel)
	provisioningCopy := cloneProvisioningForSession(provisioning)
	deferred, request, err := options.start(sessionContext, provisioningCopy, now)
	zeroProvisioningForSession(&provisioningCopy)
	if !handshakeTimer.Stop() {
		cancel()
		if deferred != nil {
			_ = deferred.Close()
		}
		zeroProvisionedProofRequest(&request)
		return nil, IssuerWork{}, fmt.Errorf("client: provisioned session handshake timed out")
	}
	if err != nil {
		cancel()
		if deferred != nil {
			err = errors.Join(err, deferred.Close())
		}
		zeroProvisionedProofRequest(&request)
		return nil, IssuerWork{}, err
	}
	if deferred == nil {
		cancel()
		zeroProvisionedProofRequest(&request)
		return nil, IssuerWork{}, fmt.Errorf("client: provisioned session starter returned no handshake")
	}

	request = cloneProvisionedProofRequest(request)
	work, err := buildProvisionedIssuerWork(provisioning.IssuerURL, provisioning.IssuerCarrierPath, request, now, options.IssuerLifetime, options.random)
	if err != nil {
		cancel()
		_ = deferred.Close()
		zeroProvisionedProofRequest(&request)
		return nil, IssuerWork{}, err
	}
	session := &ProvisionedSession{
		ctx:            sessionContext,
		cancel:         cancel,
		handshake:      deferred,
		request:        request,
		issuerMetadata: issuerMetadata,
		options:        options,
	}
	session.mu.Lock()
	session.issuerTimer = time.AfterFunc(options.IssuerTimeout, func() {
		_ = session.Close()
	})
	session.mu.Unlock()
	return session, work, nil
}

// Complete verifies the issuer response and transfers an established carrier session to the caller.
func (s *ProvisionedSession) Complete(ctx context.Context, issuerResponse []byte) (*handshake.EstablishedSession, error) {
	if s == nil {
		return nil, fmt.Errorf("client: nil provisioned session")
	}
	if ctx == nil {
		return nil, fmt.Errorf("client: nil provisioned completion context")
	}
	if err := ctx.Err(); err != nil {
		_ = s.Close()
		return nil, err
	}
	if len(issuerResponse) == 0 || len(issuerResponse) > maximumProvisionedIssuerResponse {
		_ = s.Close()
		return nil, fmt.Errorf("client: provisioned issuer response size is invalid")
	}

	s.mu.Lock()
	if s.closed || s.completing || s.handshake == nil || s.established != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("client: provisioned session is not awaiting issuer completion")
	}
	s.completing = true
	deferred := s.handshake
	request := cloneProvisionedProofRequest(s.request)
	sessionContext := s.ctx
	issuerMetadata := s.issuerMetadata
	options := s.options
	s.mu.Unlock()

	now := options.now().UTC()
	var nowUnix uint64
	if !now.IsZero() && now.Unix() >= 0 {
		nowUnix = uint64(now.Unix())
	}
	proof, replay, err := provisionedProofsForIssuerResponse(request, issuerResponse, issuerMetadata, nowUnix, options.random)
	zeroProvisionedProofRequest(&request)
	var established *handshake.EstablishedSession
	if err == nil {
		if sessionContext == nil {
			err = fmt.Errorf("client: provisioned session context is unavailable")
		} else if sessionErr := sessionContext.Err(); sessionErr != nil {
			err = sessionErr
		} else {
			completeContext, cancel := context.WithTimeout(sessionContext, options.CompletionTimeout)
			established, err = deferred.Complete(completeContext, proof, replay)
			cancel()
		}
	}
	zeroProvisionedAdmissionProof(&proof)
	zeroProvisionedReplayProof(&replay)
	if err == nil && (established == nil || established.Application == nil || established.ReadCarrier == nil || established.WriteCarrier == nil) {
		if established != nil {
			_ = established.Close()
		}
		established = nil
		err = fmt.Errorf("client: provisioned session completed without carrier streams")
	}

	s.mu.Lock()
	s.completing = false
	if err == nil && !s.closed {
		s.established = established
		s.handshake = nil
		zeroProvisionedProofRequest(&s.request)
		if s.issuerTimer != nil {
			s.issuerTimer.Stop()
			s.issuerTimer = nil
		}
		s.mu.Unlock()
		return established, nil
	}
	closed := s.closed
	s.mu.Unlock()

	if established != nil {
		_ = established.Close()
	}
	if !closed {
		_ = s.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("client: complete provisioned session: %w", err)
	}
	return nil, fmt.Errorf("client: provisioned session is closed")
}

// Established returns the currently owned established session, if authentication succeeded.
func (s *ProvisionedSession) Established() *handshake.EstablishedSession {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.established
}

// Close cancels the pending handshake or established carrier and releases retained secret material.
func (s *ProvisionedSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.issuerTimer != nil {
		s.issuerTimer.Stop()
		s.issuerTimer = nil
	}
	cancel := s.cancel
	deferred := s.handshake
	established := s.established
	s.handshake = nil
	s.established = nil
	s.issuerMetadata = protocol.IssuerMetadata{}
	zeroProvisionedProofRequest(&s.request)
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var closeErr error
	if deferred != nil {
		closeErr = deferred.Close()
	}
	if established != nil {
		closeErr = combineProvisionedCloseErrors(closeErr, established.Close())
	}
	return closeErr
}

func normalizeProvisionedSessionOptions(options ProvisionedSessionOptions) ProvisionedSessionOptions {
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = defaultProvisionedHandshakeWait
	}
	if options.IssuerTimeout <= 0 {
		options.IssuerTimeout = defaultProvisionedIssuerWait
	}
	if options.IssuerLifetime <= 0 {
		options.IssuerLifetime = defaultProvisionedIssuerLifetime
	}
	if options.CompletionTimeout <= 0 {
		options.CompletionTimeout = defaultProvisionedCompleteWait
	}
	if options.now == nil {
		options.now = time.Now
	}
	if options.random == nil {
		options.random = rand.Reader
	}
	if options.start == nil {
		options.start = startProvisionedSession
	}
	return options
}

func startProvisionedSession(ctx context.Context, provisioning NativeProvisioning, now time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
	config, err := provisioning.ClientDriverConfig(now, provisionedPendingProofProvider{})
	if err != nil {
		return nil, handshake.ClientProofRequest{}, fmt.Errorf("client: provisioned client configuration: %w", err)
	}
	driver, err := handshake.NewClientDriver(config)
	if err != nil {
		return nil, handshake.ClientProofRequest{}, fmt.Errorf("client: create provisioned client driver: %w", err)
	}
	opener, err := provisioning.NewHTTP2ClientCarrierOpener(now)
	if err != nil {
		return nil, handshake.ClientProofRequest{}, fmt.Errorf("client: provisioned carrier opener: %w", err)
	}
	return driver.Begin(ctx, opener)
}

type provisionedPendingProofProvider struct{}

func (provisionedPendingProofProvider) BuildProofs(context.Context, handshake.ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: provisioned proof provider must be deferred")
}

func buildProvisionedIssuerWork(issuerURL, issuerCarrierPath string, request handshake.ClientProofRequest, now time.Time, lifetime time.Duration, random io.Reader) (IssuerWork, error) {
	if issuerURL == "" || issuerCarrierPath == "" || len(request.AdmissionContextHash) != 48 || request.ReplayEpochValidUntil == 0 {
		return IssuerWork{}, fmt.Errorf("client: provisioned issuer work inputs are invalid")
	}
	nowUnix := uint64(now.Unix())
	if request.ReplayEpochValidUntil <= nowUnix+1 {
		return IssuerWork{}, fmt.Errorf("client: provisioned replay epoch expires too soon")
	}
	expiry := uint64(now.Add(lifetime).Unix())
	if expiry >= request.ReplayEpochValidUntil {
		expiry = request.ReplayEpochValidUntil - 1
	}
	if expiry <= nowUnix {
		return IssuerWork{}, fmt.Errorf("client: provisioned issuer proof would be expired")
	}
	tokenNonce := make([]byte, 32)
	defer zeroProvisionedBytes(tokenNonce)
	if _, err := io.ReadFull(random, tokenNonce); err != nil {
		return IssuerWork{}, fmt.Errorf("client: generate provisioned issuer token nonce: %w", err)
	}
	payload, err := carrier.EncodeIssueRequest(tokenNonce, request.AdmissionContextHash, expiry)
	if err != nil {
		return IssuerWork{}, fmt.Errorf("client: encode provisioned issuer request: %w", err)
	}
	defer zeroProvisionedBytes(payload)
	body := carrier.Encode(carrier.BlindRSAIssueRequest, payload)
	if len(body) == 0 || len(body) > maximumProvisionedIssuerResponse {
		zeroProvisionedBytes(body)
		return IssuerWork{}, fmt.Errorf("client: provisioned issuer request size is invalid")
	}
	return IssuerWork{
		IssuerURL:         issuerURL,
		IssuerCarrierPath: issuerCarrierPath,
		RequestBody:       body,
	}, nil
}

func provisionedProofsForIssuerResponse(request handshake.ClientProofRequest, issuerResponse []byte, issuerMetadata protocol.IssuerMetadata, nowUnix uint64, random io.Reader) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	if nowUnix == 0 {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: provisioned issuer response requires a valid time")
	}
	carrierType, payload, err := carrier.Decode(issuerResponse)
	if err != nil || carrierType != carrier.BlindRSAIssueResponse || len(payload) == 0 {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: invalid provisioned issuer response")
	}
	proof, err := issuerd.DecodeAdmissionProofBytes(payload)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: decode provisioned admission proof: %w", err)
	}
	if proof.ExpiryUnix <= nowUnix {
		zeroProvisionedAdmissionProof(&proof)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: provisioned admission proof is expired")
	}
	if !bytes.Equal(proof.RedemptionContextHash, request.AdmissionContextHash) {
		zeroProvisionedAdmissionProof(&proof)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: provisioned admission proof context mismatch")
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, issuerMetadata, nowUnix); err != nil {
		zeroProvisionedAdmissionProof(&proof)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: verify provisioned admission proof: %w", err)
	}
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		zeroProvisionedAdmissionProof(&proof)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: hash provisioned admission proof: %w", err)
	}
	defer zeroProvisionedBytes(redemption)
	replay := protocol.ReplayProof{
		ProofVersion:        proof.ProofVersion,
		ReplayEpochID:       request.ReplayEpochID,
		TokenRedemptionHash: append([]byte(nil), redemption...),
		ClientReplayNonce:   make([]byte, 32),
		ReplayWindowID:      append([]byte(nil), request.ReplayWindowID...),
	}
	if _, err := io.ReadFull(random, replay.ClientReplayNonce); err != nil {
		zeroProvisionedAdmissionProof(&proof)
		zeroProvisionedReplayProof(&replay)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: generate provisioned replay nonce: %w", err)
	}
	replay.ReplayContextHash, err = admission.ReplayContextHash(redemption, replay, request.RouteInstanceID, request.HopIndex, request.HandshakeBindingContext, request.AdmissionContextHash)
	if err != nil {
		zeroProvisionedAdmissionProof(&proof)
		zeroProvisionedReplayProof(&replay)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("client: bind provisioned replay proof: %w", err)
	}
	return proof, replay, nil
}

func cloneProvisioningForSession(in NativeProvisioning) NativeProvisioning {
	in.IssuerMetadata = append([]byte(nil), in.IssuerMetadata...)
	in.SignedSeed = append([]byte(nil), in.SignedSeed...)
	in.Descriptor = append([]byte(nil), in.Descriptor...)
	in.TrustedDescriptorHash = append([]byte(nil), in.TrustedDescriptorHash...)
	in.Template = append([]byte(nil), in.Template...)
	in.TemplateAuthorityKey = append([]byte(nil), in.TemplateAuthorityKey...)
	in.AccessHint = append([]byte(nil), in.AccessHint...)
	in.PolicyOffer = append([]byte(nil), in.PolicyOffer...)
	in.TransportHints = append([]byte(nil), in.TransportHints...)
	in.RelayRequestHeaders = append([]byte(nil), in.RelayRequestHeaders...)
	in.RelayResponseHeaders = append([]byte(nil), in.RelayResponseHeaders...)
	in.RelayTrustRoots = append([]byte(nil), in.RelayTrustRoots...)
	return in
}

func zeroProvisioningForSession(value *NativeProvisioning) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.IssuerMetadata,
		value.SignedSeed,
		value.Descriptor,
		value.TrustedDescriptorHash,
		value.Template,
		value.TemplateAuthorityKey,
		value.AccessHint,
		value.PolicyOffer,
		value.TransportHints,
		value.RelayRequestHeaders,
		value.RelayResponseHeaders,
		value.RelayTrustRoots,
	} {
		zeroProvisionedBytes(field)
	}
	*value = NativeProvisioning{}
}

func cloneProvisionedProofRequest(in handshake.ClientProofRequest) handshake.ClientProofRequest {
	in.AdmissionContextHash = append([]byte(nil), in.AdmissionContextHash...)
	in.HandshakeBindingContext = append([]byte(nil), in.HandshakeBindingContext...)
	in.ReplayWindowID = append([]byte(nil), in.ReplayWindowID...)
	return in
}

func zeroProvisionedProofRequest(value *handshake.ClientProofRequest) {
	if value == nil {
		return
	}
	zeroProvisionedBytes(value.AdmissionContextHash)
	zeroProvisionedBytes(value.HandshakeBindingContext)
	zeroProvisionedBytes(value.ReplayWindowID)
	*value = handshake.ClientProofRequest{}
}

func zeroProvisionedAdmissionProof(value *protocol.AdmissionProof) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.IssuerID,
		value.TokenKeyID,
		value.RelayBucketID,
		value.TokenScopeID,
		value.TokenNonce,
		value.RedemptionContextHash,
		value.TokenPublicMetadata,
		value.TokenAuthenticator,
		value.BindingProof,
	} {
		zeroProvisionedBytes(field)
	}
	for index := range value.Extensions {
		zeroProvisionedBytes(value.Extensions[index].Body)
	}
	*value = protocol.AdmissionProof{}
}

func zeroProvisionedReplayProof(value *protocol.ReplayProof) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.TokenRedemptionHash,
		value.ClientReplayNonce,
		value.ReplayContextHash,
		value.ReplayWindowID,
	} {
		zeroProvisionedBytes(field)
	}
	for index := range value.Extensions {
		zeroProvisionedBytes(value.Extensions[index].Body)
	}
	*value = protocol.ReplayProof{}
}

func zeroProvisionedBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func combineProvisionedCloseErrors(first, second error) error {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return fmt.Errorf("%w; %w", first, second)
}
