package handshake

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/wire"
)

func (d *ClientDriver) Connect(ctx context.Context, opener ClientCarrierOpener) (_ *EstablishedSession, err error) {
	if d == nil {
		return nil, fmt.Errorf("handshake: nil client driver")
	}
	if ctx == nil {
		return nil, fmt.Errorf("handshake: nil client context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isNilDependency(opener) {
		return nil, fmt.Errorf("handshake: missing client carrier opener")
	}
	now := time.Now()
	if err := validateDriverDeployment(d.deployment, d.suite, now); err != nil {
		return nil, err
	}
	if d.accessHint.ExpiryUnix == 0 || uint64(now.Unix()) >= d.accessHint.ExpiryUnix {
		return nil, fmt.Errorf("handshake: access hint credential expired")
	}
	if err := d.reserveAccessHintUse(); err != nil {
		return nil, err
	}
	hintUseCommitted := false
	defer func() {
		if !hintUseCommitted {
			d.releaseAccessHintUse()
		}
	}()

	clientState := NewClientSession()
	if err := clientState.MarkDescriptorLoaded(); err != nil {
		return nil, err
	}
	entropy := contextEntropyReader{ctx: ctx, source: d.entropy}
	clientCoverRandom := make([]byte, 32)
	defer zeroBindingBytes(clientCoverRandom)
	if _, err := io.ReadFull(entropy, clientCoverRandom); err != nil {
		return nil, fmt.Errorf("handshake: read client cover random: %w", err)
	}

	carrier, openErr := opener.Open(ctx, append([]byte(nil), clientCoverRandom...))
	if openErr != nil {
		if !isNilDependency(carrier) {
			openErr = errors.Join(openErr, carrier.Close())
		}
		return nil, openErr
	}
	if isNilDependency(carrier) {
		return nil, fmt.Errorf("handshake: carrier opener returned nil carrier")
	}
	completed := false
	defer func() {
		if !completed {
			err = errors.Join(err, carrier.Close())
		}
	}()

	binding := cloneFirstHopBinding(carrier.Binding())
	defer zeroFirstHopBinding(&binding)
	if err := validateClientFirstHopBinding(d.deployment, clientCoverRandom, binding); err != nil {
		return nil, err
	}
	if err := clientState.MarkCoverOpened(); err != nil {
		return nil, err
	}

	clientNonce := make([]byte, 32)
	defer zeroBindingBytes(clientNonce)
	if _, err := io.ReadFull(entropy, clientNonce); err != nil {
		return nil, fmt.Errorf("handshake: read client nonce: %w", err)
	}
	clientECDH, err := auroracrypto.GenerateECDHForSuite(d.suite)
	if err != nil {
		return nil, err
	}
	defer clientECDH.Destroy()
	clientMLKEM, err := auroracrypto.GenerateMLKEMForSuite(d.suite)
	if err != nil {
		return nil, err
	}
	defer clientMLKEM.Destroy()

	accessHint, err := admission.ComputeAccessHint(d.accessHint, binding.HandshakeBindingContext, clientNonce)
	if err != nil {
		return nil, err
	}
	defer zeroBindingBytes(accessHint)
	template := d.deployment.Template()
	requestClass := d.deployment.RequestClass()
	prelude0 := protocol.CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{d.suite},
		ClientNonce:                 append([]byte(nil), clientNonce...),
		ClientClassicalEphPub:       clientECDH.PublicKeyBytes(),
		ClientMLKEMEncapsulationKey: clientMLKEM.EncapsulationKeyBytes(),
		RelayDescriptorHash:         d.deployment.DescriptorHash(),
		CoverTemplateHash:           d.deployment.TemplateHash(),
		RequestClassID:              requestClass.ClassID,
		HintIssuerID:                append([]byte(nil), d.accessHint.HintIssuerID...),
		RelayBucketID:               append([]byte(nil), d.accessHint.RelayBucketID...),
		HintEpochID:                 d.accessHint.HintEpochID,
		HintSelector:                append([]byte(nil), d.accessHint.HintSelector...),
		AccessHint:                  append([]byte(nil), accessHint...),
		ClientCoverRandom:           append([]byte(nil), clientCoverRandom...),
	}
	paddedPrelude0, prelude0Record, err := padCoverPrelude0(entropy, prelude0, template.PreludeEnvelope.MinRequestBodySize, template.PreludeEnvelope.MaxRequestBodySize)
	zeroCoverPrelude0(&prelude0)
	if err != nil {
		return nil, err
	}
	prelude0 = paddedPrelude0
	defer zeroCoverPrelude0(&prelude0)
	defer zeroBindingBytes(prelude0Record)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	hintUseCommitted = true
	if err := carrier.WriteRecord(prelude0Record); err != nil {
		return nil, fmt.Errorf("handshake: write CoverPrelude0: %w", err)
	}
	if err := clientState.MarkCoverPrelude0Sent(); err != nil {
		return nil, err
	}

	prelude1Record, err := readClientRecord(ctx, carrier)
	if err != nil {
		return nil, fmt.Errorf("handshake: read CoverPrelude1: %w", err)
	}
	defer zeroBindingBytes(prelude1Record)
	if err := validateBootstrapEnvelope("CoverPrelude1", prelude1Record, template.PreludeEnvelope.MinResponseBodySize, template.PreludeEnvelope.MaxResponseBodySize); err != nil {
		return nil, err
	}
	prelude1, err := decodeClientPrelude1(prelude1Record)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(prelude1.SelectedBootstrapEnvelopeID, template.CapsuleEnvelope.EnvelopeID) {
		return nil, fmt.Errorf("handshake: selected bootstrap envelope mismatch")
	}
	descriptor := d.deployment.Descriptor()
	preludeTranscriptHash, err := clientState.VerifyCoverPrelude1(CoverPreludeVerificationInput{
		Suite:              d.suite,
		CoverStreamBinding: binding.CoverStreamBinding,
		Prelude0:           prelude0,
		Prelude1:           prelude1,
		Descriptor:         descriptor,
		RequirePQ:          d.requirePQ,
	})
	if err != nil {
		return nil, err
	}
	defer zeroBindingBytes(preludeTranscriptHash)
	if !bytes.Equal(prelude1.SelectedCoverProfileID, template.TemplateID) {
		return nil, fmt.Errorf("handshake: selected cover profile mismatch")
	}

	sharedClassical, err := clientECDH.SharedSecret(prelude1.ServerClassicalEphPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: derive classical shared secret: %w", err)
	}
	defer zeroBindingBytes(sharedClassical)
	sharedPQ, err := clientMLKEM.Decapsulate(prelude1.ServerMLKEMCiphertextToClient)
	if err != nil {
		return nil, fmt.Errorf("handshake: derive PQ shared secret: %w", err)
	}
	defer zeroBindingBytes(sharedPQ)
	handshakeSecrets, err := DeriveHandshakeSecrets(d.suite, sharedPQ, sharedClassical, binding.HandshakeBindingContext, preludeTranscriptHash)
	if err != nil {
		return nil, err
	}
	defer zeroHandshakeSecrets(&handshakeSecrets)
	routeInstanceID, err := auroracrypto.FirstHopRouteInstanceID(d.suite, preludeTranscriptHash, d.deployment.DescriptorHash(), binding.HandshakeBindingContext, clientNonce)
	if err != nil {
		return nil, err
	}
	admissionContextHash, err := admission.AdmissionContextHash(admission.ContextInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   d.suite,
		RelayDescriptorHash:             d.deployment.DescriptorHash(),
		CoverTemplateHash:               d.deployment.TemplateHash(),
		RouteInstanceID:                 routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         binding.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: preludeTranscriptHash,
		PolicyOffer:                     d.policyOffer,
		ClientTransportHints:            d.transportHints,
	})
	if err != nil {
		return nil, err
	}
	defer zeroBindingBytes(admissionContextHash)

	proofRequest := ClientProofRequest{
		AdmissionContextHash:    append([]byte(nil), admissionContextHash...),
		HandshakeBindingContext: append([]byte(nil), binding.HandshakeBindingContext...),
		RouteInstanceID:         routeInstanceID,
		HopIndex:                0,
		ReplayEpochID:           descriptor.ReplayEpochID,
		ReplayEpochValidUntil:   descriptor.ReplayEpochValidUntilUnix,
		ReplayWindowID:          append([]byte(nil), descriptor.ReplayWindowID...),
	}
	defer zeroClientProofRequest(&proofRequest)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	rawAdmissionProof, rawReplayProof, err := d.proofProvider.BuildProofs(ctx, cloneClientProofRequestValue(proofRequest))
	if err != nil {
		return nil, fmt.Errorf("handshake: build client proofs: %w", err)
	}
	defer zeroAdmissionProof(&rawAdmissionProof)
	defer zeroReplayProof(&rawReplayProof)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	admissionProof, err := cloneAdmissionProof(rawAdmissionProof)
	if err != nil {
		return nil, fmt.Errorf("handshake: clone admission proof: %w", err)
	}
	defer zeroAdmissionProof(&admissionProof)
	replayProof, err := cloneReplayProof(rawReplayProof)
	if err != nil {
		return nil, fmt.Errorf("handshake: clone replay proof: %w", err)
	}
	defer zeroReplayProof(&replayProof)
	zeroAdmissionProof(&rawAdmissionProof)
	zeroReplayProof(&rawReplayProof)
	if err := validateClientProofs(uint64(time.Now().Unix()), d.accessHint, descriptor, routeInstanceID, binding.HandshakeBindingContext, admissionContextHash, admissionProof, replayProof); err != nil {
		return nil, err
	}

	capsule1 := protocol.CoverCapsule1Plain{
		MsgType:              registry.MsgCoverCapsule1,
		RouteInstanceID:      routeInstanceID,
		AdmissionProof:       admissionProof,
		ReplayProof:          replayProof,
		PolicyOffer:          d.policyOffer,
		ClientTransportHints: d.transportHints,
	}
	capsule1, err = clientState.BuildCoverCapsule1(capsule1)
	if err != nil {
		return nil, err
	}
	control := ControlCapsuleContext{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   d.suite,
		RouteInstanceID:                 routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         binding.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: preludeTranscriptHash,
		ClientHSKey:                     handshakeSecrets.ClientHSKey,
		ClientHSIV:                      handshakeSecrets.ClientHSIV,
		ServerHSKey:                     handshakeSecrets.ServerHSKey,
		ServerHSIV:                      handshakeSecrets.ServerHSIV,
	}
	finalizeCapsule1 := func(value protocol.CoverCapsule1Plain) (protocol.CoverCapsule1Plain, []byte, error) {
		value.ClientFinished = nil
		finished, err := ComputeClientFinished(d.suite, handshakeSecrets.ClientFinishedKey, preludeTranscriptHash, value)
		if err != nil {
			return protocol.CoverCapsule1Plain{}, nil, err
		}
		value.ClientFinished = finished
		sealed, err := SealCoverCapsule1(control, value)
		return value, sealed, err
	}
	capsule1, capsule1Record, err := padCoverCapsule1(entropy, capsule1, template.CapsuleEnvelope.MinCapsuleBodySize, template.CapsuleEnvelope.MaxCapsuleBodySize, finalizeCapsule1)
	if err != nil {
		return nil, err
	}
	defer zeroCoverCapsule1(&capsule1)
	defer zeroBindingBytes(capsule1Record)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := carrier.WriteRecord(capsule1Record); err != nil {
		return nil, fmt.Errorf("handshake: write CoverCapsule1: %w", err)
	}

	capsule2Record, err := readClientRecord(ctx, carrier)
	if err != nil {
		return nil, fmt.Errorf("handshake: read CoverCapsule2: %w", err)
	}
	defer zeroBindingBytes(capsule2Record)
	if err := validateBootstrapEnvelope("CoverCapsule2", capsule2Record, template.CapsuleEnvelope.MinCapsuleBodySize, template.CapsuleEnvelope.MaxCapsuleBodySize); err != nil {
		return nil, err
	}
	capsule2, err := OpenCoverCapsule2(control, capsule2Record)
	if err != nil {
		return nil, err
	}
	defer zeroCoverCapsule2(&capsule2)
	if err := validateClientPolicyAccept(uint64(time.Now().Unix()), d.deployment, d.policyOffer, capsule2.PolicyAccept); err != nil {
		return nil, err
	}
	expectedServerFinished, capsule1Hash, policyAcceptHash, err := ComputeServerFinished(d.suite, handshakeSecrets.ServerFinishedKey, preludeTranscriptHash, capsule1, capsule2.PolicyAccept)
	if err != nil {
		return nil, err
	}
	defer zeroBindingBytes(expectedServerFinished)
	defer zeroBindingBytes(capsule1Hash)
	defer zeroBindingBytes(policyAcceptHash)
	if err := clientState.VerifyCoverCapsule2(capsule2, expectedServerFinished); err != nil {
		return nil, err
	}

	applicationSecrets, err := DeriveApplicationSecrets(d.suite, handshakeSecrets.HandshakeSecret, preludeTranscriptHash, capsule1Hash, policyAcceptHash, expectedServerFinished)
	if err != nil {
		return nil, err
	}
	defer zeroApplicationSecrets(&applicationSecrets)
	application, err := session.NewApplication(session.Config{
		Suite:           d.suite,
		RouteInstanceID: routeInstanceID,
		HopLayer:        0,
		Write: session.DirectionConfig{
			Direction: 0,
			Secret:    applicationSecrets.ClientAppSecret0,
			Key:       applicationSecrets.ClientAppKey0,
			IV:        applicationSecrets.ClientAppIV0,
		},
		Read: session.DirectionConfig{
			Direction: 1,
			Secret:    applicationSecrets.ServerAppSecret0,
			Key:       applicationSecrets.ServerAppKey0,
			IV:        applicationSecrets.ServerAppIV0,
		},
		Limits:  d.sessionLimits,
		Rekey:   d.rekey,
		Entropy: d.entropy,
	})
	if err != nil {
		return nil, err
	}
	applicationOwned := true
	defer func() {
		if applicationOwned {
			err = errors.Join(err, application.Close())
		}
	}()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	readCarrier, writeCarrier, streamErr := carrier.ApplicationStreams()
	streamsOwned := true
	defer func() {
		if streamsOwned {
			if !isNilDependency(readCarrier) {
				err = errors.Join(err, readCarrier.Close())
			}
			if !isNilDependency(writeCarrier) {
				err = errors.Join(err, writeCarrier.Close())
			}
		}
	}()
	if streamErr != nil {
		return nil, fmt.Errorf("handshake: acquire application streams: %w", streamErr)
	}
	if isNilDependency(readCarrier) || isNilDependency(writeCarrier) {
		return nil, fmt.Errorf("handshake: carrier returned nil application stream")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	policy, err := clonePolicyAccept(capsule2.PolicyAccept)
	if err != nil {
		return nil, err
	}

	completed = true
	applicationOwned = false
	streamsOwned = false
	return &EstablishedSession{
		Application:     application,
		ReadCarrier:     readCarrier,
		WriteCarrier:    writeCarrier,
		Policy:          policy,
		RouteInstanceID: routeInstanceID,
		closeCarrier:    carrier.Close,
	}, nil
}

func (d *ClientDriver) reserveAccessHintUse() error {
	d.hintUseMu.Lock()
	defer d.hintUseMu.Unlock()
	if d.hintUses >= d.accessHint.MaxUses {
		return fmt.Errorf("handshake: access hint credential usage exhausted")
	}
	d.hintUses++
	return nil
}

func (d *ClientDriver) releaseAccessHintUse() {
	d.hintUseMu.Lock()
	if d.hintUses > 0 {
		d.hintUses--
	}
	d.hintUseMu.Unlock()
}

type contextEntropyReader struct {
	ctx    context.Context
	source session.EntropySource
}

func (r contextEntropyReader) Read(p []byte) (int, error) {
	if err := contextError(r.ctx); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.source != nil {
		if err := r.source.ReadContext(r.ctx, p); err != nil {
			zeroBindingBytes(p)
			return 0, err
		}
	} else if _, err := rand.Read(p); err != nil {
		zeroBindingBytes(p)
		return 0, err
	}
	if err := contextError(r.ctx); err != nil {
		zeroBindingBytes(p)
		return 0, err
	}
	return len(p), nil
}

func readClientRecord(ctx context.Context, carrier BootstrapCarrier) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	record, err := carrier.ReadRecord()
	if err != nil {
		zeroBindingBytes(record)
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		zeroBindingBytes(record)
		return nil, err
	}
	return append([]byte(nil), record...), nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("handshake: nil client context")
	}
	return ctx.Err()
}

func validateBootstrapEnvelope(label string, record []byte, minimum, maximum uint64) error {
	size := uint64(len(record))
	if minimum > maximum || maximum > maxBootstrapRecordBodyBytes {
		return fmt.Errorf("handshake: invalid %s envelope", label)
	}
	if size < minimum || size > maximum {
		return fmt.Errorf("handshake: %s body size %d outside envelope [%d,%d]", label, size, minimum, maximum)
	}
	return nil
}

func decodeClientPrelude1(encoded []byte) (protocol.CoverPrelude1, error) {
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverPrelude1(r)
	if r.Err() != nil {
		return protocol.CoverPrelude1{}, fmt.Errorf("handshake: malformed CoverPrelude1: %w", r.Err())
	}
	if !r.EOF() {
		return protocol.CoverPrelude1{}, fmt.Errorf("handshake: trailing CoverPrelude1 bytes")
	}
	return out, nil
}

func validateClientFirstHopBinding(deployment interface {
	Template() protocol.CoverTemplate
	RequestClass() protocol.RequestClass
	Method() uint64
}, clientCoverRandom []byte, binding FirstHopBinding) error {
	for label, value := range map[string][]byte{
		"outer exporter":            binding.OuterExporterValue,
		"TLS exporter channel ID":   binding.TLSExporterChannelID,
		"connection ID hash":        binding.ConnectionIDHash,
		"cover stream binding":      binding.CoverStreamBinding,
		"handshake binding context": binding.HandshakeBindingContext,
	} {
		if len(value) != 48 {
			return fmt.Errorf("handshake: %s length %d, want 48", label, len(value))
		}
	}
	wantConnection := auroracrypto.PreHash([]byte("h2"), binding.TLSExporterChannelID, make([]byte, 48))
	defer zeroBindingBytes(wantConnection)
	if subtle.ConstantTimeCompare(wantConnection, binding.ConnectionIDHash) != 1 {
		return fmt.Errorf("handshake: first-hop connection binding mismatch")
	}
	template := deployment.Template()
	requestClass := deployment.RequestClass()
	wantStream, err := CoverStreamBinding(CoverStreamBindingInput{
		OuterExporterValue:       binding.OuterExporterValue,
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         binding.ConnectionIDHash,
		StreamIDOrRequestID:      http2StreamID,
		MethodFamilyID:           deployment.Method(),
		NormalizedAuthorityHash:  template.PublicNameHash,
		NormalizedPathTemplateID: requestClass.PathTemplateID,
		RequestClassID:           requestClass.ClassID,
		ClientCoverRandom:        clientCoverRandom,
	})
	if err != nil {
		return err
	}
	defer zeroBindingBytes(wantStream)
	if subtle.ConstantTimeCompare(wantStream, binding.CoverStreamBinding) != 1 {
		return fmt.Errorf("handshake: first-hop stream binding mismatch")
	}
	wantContext, err := FirstHopBindingContext(binding.OuterExporterValue, binding.CoverStreamBinding)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(wantContext)
	if subtle.ConstantTimeCompare(wantContext, binding.HandshakeBindingContext) != 1 {
		return fmt.Errorf("handshake: first-hop handshake binding mismatch")
	}
	return nil
}

func validateClientProofs(now uint64, credential admission.AccessHintCredential, descriptor protocol.RelayDescriptor, routeInstanceID uint64, handshakeBindingContext, admissionContextHash []byte, proof protocol.AdmissionProof, replay protocol.ReplayProof) error {
	if err := proof.ValidateStructural(now, false); err != nil {
		return fmt.Errorf("handshake: invalid admission proof: %w", err)
	}
	if proof.ExpiryUnix > descriptor.ReplayEpochValidUntilUnix {
		return fmt.Errorf("handshake: admission proof outlives replay epoch")
	}
	if subtle.ConstantTimeCompare(proof.RedemptionContextHash, admissionContextHash) != 1 {
		return fmt.Errorf("handshake: admission redemption context mismatch")
	}
	if subtle.ConstantTimeCompare(proof.IssuerID, credential.HintIssuerID) != 1 || subtle.ConstantTimeCompare(proof.RelayBucketID, credential.RelayBucketID) != 1 {
		return fmt.Errorf("handshake: admission proof issuer or relay bucket mismatch")
	}
	if err := replay.ValidateStructural(); err != nil {
		return fmt.Errorf("handshake: invalid replay proof: %w", err)
	}
	if replay.ReplayEpochID != descriptor.ReplayEpochID || subtle.ConstantTimeCompare(replay.ReplayWindowID, descriptor.ReplayWindowID) != 1 {
		return fmt.Errorf("handshake: replay epoch or window mismatch")
	}
	wantRedemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(wantRedemption)
	if subtle.ConstantTimeCompare(wantRedemption, replay.TokenRedemptionHash) != 1 {
		return fmt.Errorf("handshake: replay token redemption hash mismatch")
	}
	wantReplayContext, err := admission.ReplayContextHash(wantRedemption, replay, routeInstanceID, 0, handshakeBindingContext, admissionContextHash)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(wantReplayContext)
	if subtle.ConstantTimeCompare(wantReplayContext, replay.ReplayContextHash) != 1 {
		return fmt.Errorf("handshake: replay context mismatch")
	}
	return nil
}

func validateClientPolicyAccept(now uint64, deployment interface {
	Suite() uint64
	Method() uint64
}, offer protocol.PolicyOffer, accept protocol.PolicyAccept) error {
	if err := accept.ValidateForOffer(offer); err != nil {
		return fmt.Errorf("handshake: invalid policy accept: %w", err)
	}
	if accept.SelectedVersion != registry.Version20 || accept.SelectedSuite != deployment.Suite() || accept.SelectedMethod != deployment.Method() {
		return fmt.Errorf("handshake: policy accept changed authenticated version, suite, or method")
	}
	if accept.SelectedPolicy == registry.PolicyLab {
		return fmt.Errorf("handshake: lab policy is forbidden in production")
	}
	if accept.SelectedRouteModeID != offer.RequestedRouteModeID || accept.SelectedShape != offer.RequestedShapeID {
		return fmt.Errorf("handshake: policy accept changed requested route or shape")
	}
	if hasDuplicateDriverIDs(accept.FallbackMethods) {
		return fmt.Errorf("handshake: policy accept contains duplicate fallback methods")
	}
	for _, method := range accept.FallbackMethods {
		if !containsDriverID(offer.OfferedMethods, method) || !isDriverProductionMethod(method) {
			return fmt.Errorf("handshake: policy accept contains an unoffered fallback method")
		}
	}
	if assignment := accept.VirtualAddressAssignment; assignment != nil {
		if len(assignment.LeaseID) != 16 {
			return fmt.Errorf("handshake: virtual address lease ID length %d, want 16", len(assignment.LeaseID))
		}
		if assignment.AddressFamily == 0 || len(assignment.ClientAddress) == 0 || len(assignment.ClientAddress) > 16 {
			return fmt.Errorf("handshake: invalid virtual client address")
		}
		if int(assignment.PrefixLength) > len(assignment.ClientAddress)*8 {
			return fmt.Errorf("handshake: virtual address prefix exceeds address width")
		}
		if assignment.DNSServerHint != nil && (len(assignment.DNSServerHint) == 0 || len(assignment.DNSServerHint) > 16) {
			return fmt.Errorf("handshake: invalid virtual DNS server hint")
		}
		if assignment.LeaseExpiryUnix <= now {
			return fmt.Errorf("handshake: virtual address lease expired")
		}
	}
	return nil
}

func cloneFirstHopBinding(in FirstHopBinding) FirstHopBinding {
	in.OuterExporterValue = append([]byte(nil), in.OuterExporterValue...)
	in.TLSExporterChannelID = append([]byte(nil), in.TLSExporterChannelID...)
	in.ConnectionIDHash = append([]byte(nil), in.ConnectionIDHash...)
	in.CoverStreamBinding = append([]byte(nil), in.CoverStreamBinding...)
	in.HandshakeBindingContext = append([]byte(nil), in.HandshakeBindingContext...)
	return in
}

func cloneClientProofRequestValue(in ClientProofRequest) ClientProofRequest {
	in.AdmissionContextHash = append([]byte(nil), in.AdmissionContextHash...)
	in.HandshakeBindingContext = append([]byte(nil), in.HandshakeBindingContext...)
	in.ReplayWindowID = append([]byte(nil), in.ReplayWindowID...)
	return in
}

func cloneAdmissionProof(in protocol.AdmissionProof) (protocol.AdmissionProof, error) {
	encoded, err := protocol.Encode(in)
	if err != nil {
		return protocol.AdmissionProof{}, err
	}
	defer zeroBindingBytes(encoded)
	r := wire.NewReader(encoded)
	out := protocol.DecodeAdmissionProof(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.AdmissionProof{}, fmt.Errorf("handshake: cannot clone admission proof")
	}
	return out, nil
}

func cloneReplayProof(in protocol.ReplayProof) (protocol.ReplayProof, error) {
	encoded, err := protocol.Encode(in)
	if err != nil {
		return protocol.ReplayProof{}, err
	}
	defer zeroBindingBytes(encoded)
	r := wire.NewReader(encoded)
	out := protocol.DecodeReplayProof(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.ReplayProof{}, fmt.Errorf("handshake: cannot clone replay proof")
	}
	return out, nil
}

func clonePolicyAccept(in protocol.PolicyAccept) (protocol.PolicyAccept, error) {
	encoded, err := protocol.Encode(in)
	if err != nil {
		return protocol.PolicyAccept{}, err
	}
	defer zeroBindingBytes(encoded)
	r := wire.NewReader(encoded)
	out := protocol.DecodePolicyAccept(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.PolicyAccept{}, fmt.Errorf("handshake: cannot clone policy accept")
	}
	return out, nil
}

func zeroFirstHopBinding(binding *FirstHopBinding) {
	if binding == nil {
		return
	}
	zeroBindingBytes(binding.OuterExporterValue)
	zeroBindingBytes(binding.TLSExporterChannelID)
	zeroBindingBytes(binding.ConnectionIDHash)
	zeroBindingBytes(binding.CoverStreamBinding)
	zeroBindingBytes(binding.HandshakeBindingContext)
}

func zeroClientProofRequest(request *ClientProofRequest) {
	if request == nil {
		return
	}
	zeroBindingBytes(request.AdmissionContextHash)
	zeroBindingBytes(request.HandshakeBindingContext)
	zeroBindingBytes(request.ReplayWindowID)
}

func zeroCoverPrelude0(value *protocol.CoverPrelude0) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.ClientNonce, value.ClientClassicalEphPub, value.ClientMLKEMEncapsulationKey,
		value.RelayDescriptorHash, value.CoverTemplateHash, value.HintIssuerID,
		value.RelayBucketID, value.HintSelector, value.AccessHint, value.ClientCoverRandom, value.Padding,
	} {
		zeroBindingBytes(field)
	}
	zeroExtensions(value.Extensions)
}

func zeroAdmissionProof(value *protocol.AdmissionProof) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.IssuerID, value.TokenKeyID, value.RelayBucketID, value.TokenScopeID,
		value.TokenNonce, value.RedemptionContextHash, value.TokenPublicMetadata,
		value.TokenAuthenticator, value.BindingProof,
	} {
		zeroBindingBytes(field)
	}
	zeroExtensions(value.Extensions)
}

func zeroReplayProof(value *protocol.ReplayProof) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.TokenRedemptionHash, value.ClientReplayNonce, value.ReplayContextHash, value.ReplayWindowID,
	} {
		zeroBindingBytes(field)
	}
	zeroExtensions(value.Extensions)
}

func zeroCoverCapsule1(value *protocol.CoverCapsule1Plain) {
	if value == nil {
		return
	}
	zeroAdmissionProof(&value.AdmissionProof)
	zeroReplayProof(&value.ReplayProof)
	zeroBindingBytes(value.ClientTransportHints.NetworkCohortHint)
	zeroBindingBytes(value.ClientTransportHints.Padding)
	zeroBindingBytes(value.ClientFinished)
	zeroBindingBytes(value.Padding)
	zeroExtensions(value.PolicyOffer.Extensions)
	zeroExtensions(value.ClientTransportHints.Extensions)
	zeroExtensions(value.Extensions)
}

func zeroCoverCapsule2(value *protocol.CoverCapsule2Plain) {
	if value == nil {
		return
	}
	zeroBindingBytes(value.ServerFinished)
	zeroBindingBytes(value.Padding)
	if assignment := value.PolicyAccept.VirtualAddressAssignment; assignment != nil {
		zeroBindingBytes(assignment.LeaseID)
		zeroBindingBytes(assignment.ClientAddress)
		zeroBindingBytes(assignment.DNSServerHint)
	}
	zeroExtensions(value.PolicyAccept.Extensions)
	zeroExtensions(value.Extensions)
}

func zeroExtensions(values []protocol.Extension) {
	for i := range values {
		zeroBindingBytes(values[i].Body)
	}
}

func zeroHandshakeSecrets(value *HandshakeSecrets) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.EarlySecret, value.DerivedSecret, value.HandshakeSecret,
		value.ClientHandshakeSecret, value.ServerHandshakeSecret,
		value.ClientFinishedKey, value.ServerFinishedKey,
		value.ClientHSKey, value.ClientHSIV, value.ServerHSKey, value.ServerHSIV,
	} {
		zeroBindingBytes(field)
	}
}

func zeroApplicationSecrets(value *ApplicationSecrets) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{
		value.ApplicationTranscriptHash, value.ApplicationSecret,
		value.ClientAppSecret0, value.ServerAppSecret0,
		value.ClientAppKey0, value.ClientAppIV0, value.ServerAppKey0, value.ServerAppIV0,
	} {
		zeroBindingBytes(field)
	}
}
