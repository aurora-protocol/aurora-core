package handshake

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type RelayHandshake struct {
	mu sync.Mutex

	driver                *RelayDriver
	suite                 uint64
	handshakeBinding      []byte
	hintIssuerID          []byte
	relayBucketID         []byte
	preludeTranscriptHash []byte
	secrets               HandshakeSecrets
	routeInstanceID       uint64
	terminal              bool
}

func (d *RelayDriver) Begin(ctx context.Context, binding FirstHopBinding, input protocol.CoverPrelude0, nowUnix uint64) (_ *RelayHandshake, _ protocol.CoverPrelude1, err error) {
	if d == nil {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: nil relay driver")
	}
	if ctx == nil {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: nil relay context")
	}
	if err := ctx.Err(); err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	if nowUnix == 0 || nowUnix > math.MaxInt64 {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: invalid relay time")
	}
	if err := validateDriverDeployment(d.deployment, d.deployment.Suite(), time.Unix(int64(nowUnix), 0)); err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}

	prelude0, err := cloneCoverPrelude0(input)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: clone CoverPrelude0: %w", err)
	}
	defer func() {
		if err != nil {
			zeroCoverPrelude0(&prelude0)
		}
	}()
	binding = cloneFirstHopBinding(binding)
	defer func() {
		if err != nil {
			zeroFirstHopBinding(&binding)
		}
	}()
	if err := validateRelayPrelude0(d, binding, prelude0); err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	if err := contextError(ctx); err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}

	credential, err := d.hintResolver.ResolveAccessHint(
		ctx,
		append([]byte(nil), prelude0.HintIssuerID...),
		append([]byte(nil), prelude0.RelayBucketID...),
		prelude0.HintEpochID,
		append([]byte(nil), prelude0.HintSelector...),
	)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: resolve access hint: %w", err)
	}
	credential = cloneAccessHint(credential)
	defer zeroAccessHintCredential(&credential)
	if err := validateResolvedHintCredential(prelude0, credential, nowUnix); err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	if err := contextError(ctx); err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	if err := admission.VerifyAndSpendAccessHintAt(d.hintSpentCache, credential, binding.HandshakeBindingContext, prelude0.ClientNonce, prelude0.AccessHint, nowUnix); err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}

	serverECDH, err := auroracrypto.GenerateECDHForSuite(d.deployment.Suite())
	if err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	defer serverECDH.Destroy()
	sharedClassical, err := serverECDH.SharedSecret(prelude0.ClientClassicalEphPub)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: derive relay classical shared secret: %w", err)
	}
	defer zeroBindingBytes(sharedClassical)
	sharedPQ, ciphertext, err := auroracrypto.EncapsulateMLKEMForSuite(d.deployment.Suite(), prelude0.ClientMLKEMEncapsulationKey)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: encapsulate relay PQ shared secret: %w", err)
	}
	defer zeroBindingBytes(sharedPQ)
	serverNonce := make([]byte, 32)
	defer zeroBindingBytes(serverNonce)
	entropy := contextEntropyReader{ctx: ctx, source: d.entropy}
	if _, err := entropy.Read(serverNonce); err != nil {
		return nil, protocol.CoverPrelude1{}, fmt.Errorf("handshake: read server nonce: %w", err)
	}

	descriptor := d.deployment.Descriptor()
	template := d.deployment.Template()
	prelude1 := protocol.CoverPrelude1{
		MsgType:                       registry.MsgCoverPrelude1,
		Version:                       registry.Version20,
		SelectedSuite:                 d.deployment.Suite(),
		RelayDescriptorHash:           d.deployment.DescriptorHash(),
		CoverTemplateHash:             d.deployment.TemplateHash(),
		RelayEpochID:                  descriptor.EpochID,
		ServerNonce:                   append([]byte(nil), serverNonce...),
		ServerClassicalEphPub:         serverECDH.PublicKeyBytes(),
		ServerMLKEMCiphertextToClient: append([]byte(nil), ciphertext...),
		SelectedCoverProfileID:        append([]byte(nil), template.TemplateID...),
		SelectedBootstrapEnvelopeID:   append([]byte(nil), template.CapsuleEnvelope.EnvelopeID...),
	}
	prelude1, preludeTranscriptHash, err := d.signAndPadRelayPrelude1(ctx, entropy, binding.CoverStreamBinding, prelude0, prelude1, template)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	defer func() {
		if err != nil {
			zeroCoverPrelude1(&prelude1)
			zeroBindingBytes(preludeTranscriptHash)
		}
	}()
	secrets, err := DeriveHandshakeSecrets(d.deployment.Suite(), sharedPQ, sharedClassical, binding.HandshakeBindingContext, preludeTranscriptHash)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	secretsTransferred := false
	defer func() {
		if !secretsTransferred {
			zeroHandshakeSecrets(&secrets)
		}
	}()
	routeInstanceID, err := auroracrypto.FirstHopRouteInstanceID(d.deployment.Suite(), preludeTranscriptHash, d.deployment.DescriptorHash(), binding.HandshakeBindingContext, prelude0.ClientNonce)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}
	returnedPrelude1, err := cloneCoverPrelude1(prelude1)
	if err != nil {
		return nil, protocol.CoverPrelude1{}, err
	}

	handshake := &RelayHandshake{
		driver:                d,
		suite:                 d.deployment.Suite(),
		handshakeBinding:      append([]byte(nil), binding.HandshakeBindingContext...),
		hintIssuerID:          append([]byte(nil), prelude0.HintIssuerID...),
		relayBucketID:         append([]byte(nil), prelude0.RelayBucketID...),
		preludeTranscriptHash: append([]byte(nil), preludeTranscriptHash...),
		secrets:               secrets,
		routeInstanceID:       routeInstanceID,
	}
	secretsTransferred = true
	zeroFirstHopBinding(&binding)
	zeroCoverPrelude0(&prelude0)
	zeroCoverPrelude1(&prelude1)
	zeroBindingBytes(preludeTranscriptHash)
	return handshake, returnedPrelude1, nil
}

func (h *RelayHandshake) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.terminal {
		return nil
	}
	h.terminal = true
	h.destroyLocked()
	return nil
}

func (h *RelayHandshake) Finish(ctx context.Context, capsule1Record []byte, nowUnix uint64) (_ []byte, _ *session.Application, _ protocol.PolicyAccept, err error) {
	if h == nil {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: nil relay handshake")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.terminal || h.driver == nil {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: relay handshake is terminal")
	}
	h.terminal = true
	defer h.destroyLocked()
	if ctx == nil {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: nil relay context")
	}
	if err := contextError(ctx); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	if nowUnix == 0 || nowUnix > math.MaxInt64 {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: invalid relay time")
	}
	driver := h.driver
	if err := validateDriverDeployment(driver.deployment, h.suite, time.Unix(int64(nowUnix), 0)); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	template := driver.deployment.Template()
	if err := validateBootstrapEnvelope("CoverCapsule1", capsule1Record, template.CapsuleEnvelope.MinCapsuleBodySize, template.CapsuleEnvelope.MaxCapsuleBodySize); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	control := ControlCapsuleContext{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   h.suite,
		RouteInstanceID:                 h.routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         h.handshakeBinding,
		PreludeTranscriptHashForThisHop: h.preludeTranscriptHash,
		ClientHSKey:                     h.secrets.ClientHSKey,
		ClientHSIV:                      h.secrets.ClientHSIV,
		ServerHSKey:                     h.secrets.ServerHSKey,
		ServerHSIV:                      h.secrets.ServerHSIV,
	}
	capsule1, err := OpenCoverCapsule1(control, capsule1Record)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroCoverCapsule1(&capsule1)
	if err := capsule1.ValidateStructural(nowUnix, false); err != nil {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: invalid CoverCapsule1: %w", err)
	}
	expectedClientFinished, err := ComputeClientFinished(h.suite, h.secrets.ClientFinishedKey, h.preludeTranscriptHash, capsule1)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroBindingBytes(expectedClientFinished)
	if subtle.ConstantTimeCompare(expectedClientFinished, capsule1.ClientFinished) != 1 {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: client finished mismatch")
	}

	admissionContextHash, err := admission.AdmissionContextHash(admission.ContextInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   h.suite,
		RelayDescriptorHash:             driver.deployment.DescriptorHash(),
		CoverTemplateHash:               driver.deployment.TemplateHash(),
		RouteInstanceID:                 h.routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         h.handshakeBinding,
		PreludeTranscriptHashForThisHop: h.preludeTranscriptHash,
		PolicyOffer:                     capsule1.PolicyOffer,
		ClientTransportHints:            capsule1.ClientTransportHints,
	})
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroBindingBytes(admissionContextHash)
	descriptor := driver.deployment.Descriptor()
	if err := validateRelayCapsuleProofs(h, descriptor, admissionContextHash, capsule1.AdmissionProof, capsule1.ReplayProof); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	if err := contextError(ctx); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	proofForVerifier, err := cloneAdmissionProof(capsule1.AdmissionProof)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroAdmissionProof(&proofForVerifier)
	if err := driver.admissionVerifier.VerifyAdmission(ctx, proofForVerifier, nowUnix); err != nil {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: admission verification failed: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	if _, _, err := admission.VerifyAndSpendReplay(admission.ReplayVerificationInput{
		AdmissionProof:          capsule1.AdmissionProof,
		ReplayProof:             capsule1.ReplayProof,
		RouteInstanceID:         h.routeInstanceID,
		HopIndex:                0,
		HandshakeBindingContext: h.handshakeBinding,
		AdmissionContextHash:    admissionContextHash,
		TokenSpentCache:         driver.tokenSpentCache,
		BootstrapDedupCache:     driver.bootstrapCache,
		NowUnix:                 nowUnix,
		AllowLabProofs:          false,
	}); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	if err := contextError(ctx); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	offerForSelector, err := clonePolicyOffer(capsule1.PolicyOffer)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroPolicyOffer(&offerForSelector)
	hintsForSelector, err := cloneTransportHints(capsule1.ClientTransportHints)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroTransportHints(&hintsForSelector)
	accept, err := driver.policySelector.SelectPolicy(ctx, offerForSelector, hintsForSelector)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, fmt.Errorf("handshake: policy selection failed: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	accept, err = clonePolicyAccept(accept)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroPolicyAccept(&accept)
	if err := validateClientPolicyAccept(nowUnix, driver.deployment, capsule1.PolicyOffer, accept); err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	serverFinished, capsule1Hash, policyAcceptHash, err := ComputeServerFinished(h.suite, h.secrets.ServerFinishedKey, h.preludeTranscriptHash, capsule1, accept)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroBindingBytes(serverFinished)
	defer zeroBindingBytes(capsule1Hash)
	defer zeroBindingBytes(policyAcceptHash)
	capsule2 := protocol.CoverCapsule2Plain{
		MsgType:         registry.MsgCoverCapsule2,
		RouteInstanceID: h.routeInstanceID,
		PolicyAccept:    accept,
		ServerFinished:  append([]byte(nil), serverFinished...),
	}
	defer zeroCoverCapsule2(&capsule2)
	entropy := contextEntropyReader{ctx: ctx, source: driver.entropy}
	finalizeCapsule2 := func(value protocol.CoverCapsule2Plain) (protocol.CoverCapsule2Plain, []byte, error) {
		sealed, err := SealCoverCapsule2(control, value)
		return value, sealed, err
	}
	_, capsule2Record, err := padCoverCapsule2(entropy, capsule2, template.CapsuleEnvelope.MinCapsuleBodySize, template.CapsuleEnvelope.MaxCapsuleBodySize, finalizeCapsule2)
	if err != nil {
		return nil, nil, protocol.PolicyAccept{}, err
	}
	applicationSecrets, err := DeriveApplicationSecrets(h.suite, h.secrets.HandshakeSecret, h.preludeTranscriptHash, capsule1Hash, policyAcceptHash, serverFinished)
	if err != nil {
		zeroBindingBytes(capsule2Record)
		return nil, nil, protocol.PolicyAccept{}, err
	}
	defer zeroApplicationSecrets(&applicationSecrets)
	if err := contextError(ctx); err != nil {
		zeroBindingBytes(capsule2Record)
		return nil, nil, protocol.PolicyAccept{}, err
	}
	application, err := driver.newApplication(session.Config{
		Suite:           h.suite,
		RouteInstanceID: h.routeInstanceID,
		HopLayer:        0,
		Write: session.DirectionConfig{
			Direction: 1,
			Secret:    applicationSecrets.ServerAppSecret0,
			Key:       applicationSecrets.ServerAppKey0,
			IV:        applicationSecrets.ServerAppIV0,
		},
		Read: session.DirectionConfig{
			Direction: 0,
			Secret:    applicationSecrets.ClientAppSecret0,
			Key:       applicationSecrets.ClientAppKey0,
			IV:        applicationSecrets.ClientAppIV0,
		},
		Limits:  driver.sessionLimits,
		Rekey:   driver.rekey,
		Entropy: driver.entropy,
	})
	if err != nil {
		zeroBindingBytes(capsule2Record)
		return nil, nil, protocol.PolicyAccept{}, err
	}
	if err := contextError(ctx); err != nil {
		zeroBindingBytes(capsule2Record)
		_ = application.Close()
		return nil, nil, protocol.PolicyAccept{}, err
	}
	returnedAccept, err := clonePolicyAccept(accept)
	if err != nil {
		zeroBindingBytes(capsule2Record)
		_ = application.Close()
		return nil, nil, protocol.PolicyAccept{}, err
	}
	return capsule2Record, application, returnedAccept, nil
}

func (h *RelayHandshake) destroyLocked() {
	zeroBindingBytes(h.handshakeBinding)
	zeroBindingBytes(h.hintIssuerID)
	zeroBindingBytes(h.relayBucketID)
	zeroBindingBytes(h.preludeTranscriptHash)
	zeroHandshakeSecrets(&h.secrets)
	h.driver = nil
	h.routeInstanceID = 0
}

func validateRelayPrelude0(d *RelayDriver, binding FirstHopBinding, prelude protocol.CoverPrelude0) error {
	if err := prelude.ValidateStructural(); err != nil {
		return err
	}
	if prelude.MsgType != registry.MsgCoverPrelude0 || prelude.Version != registry.Version20 {
		return fmt.Errorf("handshake: invalid CoverPrelude0 header")
	}
	encoded, err := protocol.Encode(prelude)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(encoded)
	template := d.deployment.Template()
	if err := validateBootstrapEnvelope("CoverPrelude0", encoded, template.PreludeEnvelope.MinRequestBodySize, template.PreludeEnvelope.MaxRequestBodySize); err != nil {
		return err
	}
	if len(prelude.SuiteOffers) == 0 || hasDuplicateDriverIDs(prelude.SuiteOffers) || !containsDriverID(prelude.SuiteOffers, d.deployment.Suite()) {
		return fmt.Errorf("handshake: no unambiguous shared production suite")
	}
	for _, suite := range prelude.SuiteOffers {
		if !isDriverProductionSuite(suite) {
			return fmt.Errorf("handshake: Prelude0 contains non-production suite")
		}
	}
	if subtle.ConstantTimeCompare(prelude.RelayDescriptorHash, d.deployment.DescriptorHash()) != 1 || subtle.ConstantTimeCompare(prelude.CoverTemplateHash, d.deployment.TemplateHash()) != 1 {
		return fmt.Errorf("handshake: Prelude0 deployment hash mismatch")
	}
	if prelude.RequestClassID != d.deployment.RequestClass().ClassID {
		return fmt.Errorf("handshake: Prelude0 request class mismatch")
	}
	if err := validateClientFirstHopBinding(d.deployment, prelude.ClientCoverRandom, binding); err != nil {
		return err
	}
	if err := validatePrelude0ClientHybridSharesForSuite(d.deployment.Suite(), prelude); err != nil {
		return fmt.Errorf("handshake: malformed client hybrid share: %w", err)
	}
	return nil
}

func validateResolvedHintCredential(prelude protocol.CoverPrelude0, credential admission.AccessHintCredential, nowUnix uint64) error {
	if !bytes.Equal(credential.HintIssuerID, prelude.HintIssuerID) ||
		!bytes.Equal(credential.RelayBucketID, prelude.RelayBucketID) ||
		credential.HintEpochID != prelude.HintEpochID ||
		!bytes.Equal(credential.HintSelector, prelude.HintSelector) {
		return fmt.Errorf("handshake: resolved access hint tuple mismatch")
	}
	if credential.ExpiryUnix == 0 || nowUnix >= credential.ExpiryUnix {
		return fmt.Errorf("handshake: resolved access hint expired")
	}
	if _, err := admission.ComputeSpentHintKey(credential); err != nil {
		return fmt.Errorf("handshake: invalid resolved access hint: %w", err)
	}
	return nil
}

func validateRelayCapsuleProofs(handshake *RelayHandshake, descriptor protocol.RelayDescriptor, admissionContextHash []byte, proof protocol.AdmissionProof, replay protocol.ReplayProof) error {
	if proof.ExpiryUnix > descriptor.ReplayEpochValidUntilUnix {
		return fmt.Errorf("handshake: admission proof outlives replay epoch")
	}
	if subtle.ConstantTimeCompare(proof.IssuerID, handshake.hintIssuerID) != 1 || subtle.ConstantTimeCompare(proof.RelayBucketID, handshake.relayBucketID) != 1 {
		return fmt.Errorf("handshake: admission proof issuer or relay bucket mismatch")
	}
	if subtle.ConstantTimeCompare(proof.RedemptionContextHash, admissionContextHash) != 1 {
		return fmt.Errorf("handshake: admission redemption context mismatch")
	}
	if replay.ReplayEpochID != descriptor.ReplayEpochID || subtle.ConstantTimeCompare(replay.ReplayWindowID, descriptor.ReplayWindowID) != 1 {
		return fmt.Errorf("handshake: replay epoch or window mismatch")
	}
	redemptionHash, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(redemptionHash)
	if subtle.ConstantTimeCompare(redemptionHash, replay.TokenRedemptionHash) != 1 {
		return fmt.Errorf("handshake: replay token redemption hash mismatch")
	}
	replayContextHash, err := admission.ReplayContextHash(redemptionHash, replay, handshake.routeInstanceID, 0, handshake.handshakeBinding, admissionContextHash)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(replayContextHash)
	if subtle.ConstantTimeCompare(replayContextHash, replay.ReplayContextHash) != 1 {
		return fmt.Errorf("handshake: replay context mismatch")
	}
	return nil
}

func zeroPolicyOffer(value *protocol.PolicyOffer) {
	if value == nil {
		return
	}
	zeroExtensions(value.Extensions)
}

func zeroPolicyAccept(value *protocol.PolicyAccept) {
	if value == nil {
		return
	}
	if assignment := value.VirtualAddressAssignment; assignment != nil {
		zeroBindingBytes(assignment.LeaseID)
		zeroBindingBytes(assignment.ClientAddress)
		zeroBindingBytes(assignment.DNSServerHint)
	}
	zeroExtensions(value.Extensions)
}

func zeroTransportHints(value *protocol.ClientTransportHints) {
	if value == nil {
		return
	}
	zeroBindingBytes(value.NetworkCohortHint)
	zeroBindingBytes(value.Padding)
	zeroExtensions(value.Extensions)
}

func (d *RelayDriver) signAndPadRelayPrelude1(ctx context.Context, entropy contextEntropyReader, coverStreamBinding []byte, prelude0 protocol.CoverPrelude0, input protocol.CoverPrelude1, template protocol.CoverTemplate) (protocol.CoverPrelude1, []byte, error) {
	classicalSize, err := signatureUpperBound(d.classicalSigner.PublicKey())
	if err != nil {
		return protocol.CoverPrelude1{}, nil, err
	}
	pqSize, err := signatureUpperBound(d.pqSigner.PublicKey())
	if err != nil {
		return protocol.CoverPrelude1{}, nil, err
	}
	placeholderFinalizer := func(value protocol.CoverPrelude1) (protocol.CoverPrelude1, []byte, error) {
		value.ServerPreludeSignatureClassical = make([]byte, classicalSize)
		value.ServerPreludeSignaturePQ = make([]byte, pqSize)
		encoded, err := protocol.Encode(value)
		return value, encoded, err
	}
	padded, placeholderRecord, err := padCoverPrelude1(entropy, input, template.PreludeEnvelope.MinResponseBodySize, template.PreludeEnvelope.MaxResponseBodySize, placeholderFinalizer)
	zeroBindingBytes(placeholderRecord)
	if err != nil {
		return protocol.CoverPrelude1{}, nil, err
	}
	zeroBindingBytes(padded.ServerPreludeSignatureClassical)
	zeroBindingBytes(padded.ServerPreludeSignaturePQ)
	padded.ServerPreludeSignatureClassical = nil
	padded.ServerPreludeSignaturePQ = nil
	transcript, err := PreludeTranscriptHash(d.deployment.Suite(), coverStreamBinding, prelude0, padded)
	if err != nil {
		zeroCoverPrelude1(&padded)
		return protocol.CoverPrelude1{}, nil, err
	}
	if err := contextError(ctx); err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		return protocol.CoverPrelude1{}, nil, err
	}
	classicalSignature, err := d.classicalSigner.SignTranscript(ctx, append([]byte(nil), transcript...))
	if err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		return protocol.CoverPrelude1{}, nil, fmt.Errorf("handshake: sign classical Prelude1 transcript: %w", err)
	}
	if err := verifyPublicKeySignature(d.classicalSigner.PublicKey(), transcript, classicalSignature); err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		zeroBindingBytes(classicalSignature)
		return protocol.CoverPrelude1{}, nil, fmt.Errorf("handshake: classical signer produced invalid signature: %w", err)
	}
	if err := contextError(ctx); err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		zeroBindingBytes(classicalSignature)
		return protocol.CoverPrelude1{}, nil, err
	}
	pqSignature, err := d.pqSigner.SignTranscript(ctx, append([]byte(nil), transcript...))
	if err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		zeroBindingBytes(classicalSignature)
		return protocol.CoverPrelude1{}, nil, fmt.Errorf("handshake: sign PQ Prelude1 transcript: %w", err)
	}
	if err := verifyPublicKeySignature(d.pqSigner.PublicKey(), transcript, pqSignature); err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		zeroBindingBytes(classicalSignature)
		zeroBindingBytes(pqSignature)
		return protocol.CoverPrelude1{}, nil, fmt.Errorf("handshake: PQ signer produced invalid signature: %w", err)
	}
	padded.ServerPreludeSignatureClassical = classicalSignature
	padded.ServerPreludeSignaturePQ = pqSignature
	encoded, err := protocol.Encode(padded)
	if err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		return protocol.CoverPrelude1{}, nil, err
	}
	defer zeroBindingBytes(encoded)
	if err := validateBootstrapEnvelope("CoverPrelude1", encoded, template.PreludeEnvelope.MinResponseBodySize, template.PreludeEnvelope.MaxResponseBodySize); err != nil {
		zeroCoverPrelude1(&padded)
		zeroBindingBytes(transcript)
		return protocol.CoverPrelude1{}, nil, err
	}
	return padded, transcript, nil
}

func signatureUpperBound(key protocol.PublicKeyRecord) (int, error) {
	switch key.SignatureScheme {
	case registry.SigECDSAP256SHA256DER, registry.SigECDSAP256SHA384DER:
		return 72, nil
	case registry.SigECDSAP384SHA384DER:
		return 104, nil
	case registry.SigMLDSA65:
		return mldsa65.SignatureSize, nil
	case registry.SigMLDSA87:
		return mldsa87.SignatureSize, nil
	case registry.SigEd25519Lab:
		return 64, nil
	default:
		return 0, fmt.Errorf("handshake: unsupported Prelude1 signature scheme 0x%x", key.SignatureScheme)
	}
}

func zeroAccessHintCredential(value *admission.AccessHintCredential) {
	if value == nil {
		return
	}
	zeroBindingBytes(value.HintIssuerID)
	zeroBindingBytes(value.RelayBucketID)
	zeroBindingBytes(value.HintSelector)
	zeroBindingBytes(value.HintSecret)
}

func zeroCoverPrelude1(value *protocol.CoverPrelude1) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.RelayDescriptorHash, value.CoverTemplateHash, value.ServerNonce,
		value.ServerClassicalEphPub, value.ServerMLKEMCiphertextToClient,
		value.SelectedCoverProfileID, value.SelectedBootstrapEnvelopeID,
		value.ServerPreludeSignatureClassical, value.ServerPreludeSignaturePQ,
		value.ResponsePadding,
	} {
		zeroBindingBytes(field)
	}
	zeroExtensions(value.Extensions)
}
