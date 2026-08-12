package handshake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const maximumStaticAccessHintCredentials = 4096

// BlindRSAAdmissionVerifier verifies admission proofs with one owned Blind RSA verification key.
type BlindRSAAdmissionVerifier struct {
	verificationKeyDER []byte
}

// NewBlindRSAAdmissionVerifier validates and owns a Blind RSA verification key.
func NewBlindRSAAdmissionVerifier(verificationKeyDER []byte) (*BlindRSAAdmissionVerifier, error) {
	if err := admission.ValidateBlindRSA2048VerificationKey(verificationKeyDER); err != nil {
		return nil, fmt.Errorf("handshake: invalid Blind RSA verification key: %w", err)
	}
	return &BlindRSAAdmissionVerifier{verificationKeyDER: append([]byte(nil), verificationKeyDER...)}, nil
}

// VerifyAdmission verifies one proof after respecting the request context.
func (v *BlindRSAAdmissionVerifier) VerifyAdmission(ctx context.Context, proof protocol.AdmissionProof, _ uint64) error {
	if ctx == nil {
		return fmt.Errorf("handshake: nil Blind RSA verification context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil {
		return fmt.Errorf("handshake: Blind RSA admission verifier is missing")
	}
	return admission.VerifyBlindRSA2048(proof, v.verificationKeyDER)
}

// StaticAccessHintResolver resolves one of a fixed, owned credential set.
type StaticAccessHintResolver struct {
	credentials map[staticAccessHintKey]admission.AccessHintCredential
}

type staticAccessHintKey struct {
	issuerID      string
	relayBucketID string
	epochID       uint64
	selector      string
}

// NewStaticAccessHintResolver validates and owns a bounded credential set.
func NewStaticAccessHintResolver(credentials []admission.AccessHintCredential) (*StaticAccessHintResolver, error) {
	if len(credentials) == 0 || len(credentials) > maximumStaticAccessHintCredentials {
		return nil, fmt.Errorf("handshake: static access hint credential count is invalid")
	}
	owned := make(map[staticAccessHintKey]admission.AccessHintCredential, len(credentials))
	for _, credential := range credentials {
		if _, err := admission.ComputeSpentHintKey(credential); err != nil {
			return nil, fmt.Errorf("handshake: invalid static access hint credential: %w", err)
		}
		key := newStaticAccessHintKey(credential.HintIssuerID, credential.RelayBucketID, credential.HintEpochID, credential.HintSelector)
		if _, exists := owned[key]; exists {
			return nil, fmt.Errorf("handshake: duplicate static access hint credential")
		}
		owned[key] = cloneAccessHint(credential)
	}
	return &StaticAccessHintResolver{credentials: owned}, nil
}

// ResolveAccessHint returns an owned credential matching the exact prelude selector.
func (r *StaticAccessHintResolver) ResolveAccessHint(ctx context.Context, issuerID, relayBucketID []byte, epochID uint64, selector []byte) (admission.AccessHintCredential, error) {
	if ctx == nil {
		return admission.AccessHintCredential{}, fmt.Errorf("handshake: nil static access hint context")
	}
	if err := ctx.Err(); err != nil {
		return admission.AccessHintCredential{}, err
	}
	if r == nil {
		return admission.AccessHintCredential{}, fmt.Errorf("handshake: static access hint resolver is missing")
	}
	credential, ok := r.credentials[newStaticAccessHintKey(issuerID, relayBucketID, epochID, selector)]
	if !ok {
		return admission.AccessHintCredential{}, fmt.Errorf("handshake: static access hint credential is unavailable")
	}
	return cloneAccessHint(credential), nil
}

func newStaticAccessHintKey(issuerID, relayBucketID []byte, epochID uint64, selector []byte) staticAccessHintKey {
	return staticAccessHintKey{
		issuerID:      string(issuerID),
		relayBucketID: string(relayBucketID),
		epochID:       epochID,
		selector:      string(selector),
	}
}

// FixedProxyPolicySelector selects a configured HTTP/2 proxy-flow policy only when offered by the client.
type FixedProxyPolicySelector struct {
	suite  uint64
	policy uint64
	route  uint64
	shape  uint64
}

// NewFixedProxyPolicySelector validates a production policy selection.
func NewFixedProxyPolicySelector(suite, policy, route, shape uint64) (*FixedProxyPolicySelector, error) {
	selector := &FixedProxyPolicySelector{suite: suite, policy: policy, route: route, shape: shape}
	if err := selector.accept().ValidateStructural(); err != nil {
		return nil, fmt.Errorf("handshake: invalid fixed proxy policy: %w", err)
	}
	if policy == registry.PolicyLab {
		return nil, fmt.Errorf("handshake: lab policy is forbidden for a fixed proxy selector")
	}
	return selector, nil
}

// SelectPolicy validates the offer and returns the configured selection only when it remains admissible.
func (s *FixedProxyPolicySelector) SelectPolicy(ctx context.Context, offer protocol.PolicyOffer, hints protocol.ClientTransportHints) (protocol.PolicyAccept, error) {
	if ctx == nil {
		return protocol.PolicyAccept{}, fmt.Errorf("handshake: nil fixed proxy policy context")
	}
	if err := ctx.Err(); err != nil {
		return protocol.PolicyAccept{}, err
	}
	if s == nil {
		return protocol.PolicyAccept{}, fmt.Errorf("handshake: fixed proxy policy selector is missing")
	}
	if err := offer.ValidateStructural(); err != nil {
		return protocol.PolicyAccept{}, err
	}
	if err := hints.ValidatePrototype(); err != nil {
		return protocol.PolicyAccept{}, err
	}
	selected := s.accept()
	if err := selected.ValidateForOffer(offer); err != nil {
		return protocol.PolicyAccept{}, err
	}
	return selected, nil
}

func (s *FixedProxyPolicySelector) accept() protocol.PolicyAccept {
	if s == nil {
		return protocol.PolicyAccept{}
	}
	return protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             s.suite,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            s.policy,
		SelectedRouteModeID:       s.route,
		SelectedShape:             s.shape,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
	}
}

type ecdsaP256TranscriptSigner struct {
	private *ecdsa.PrivateKey
	public  protocol.PublicKeyRecord
}

// NewECDSAP256TranscriptSigner constructs a transcript signer from a P-256 private key.
func NewECDSAP256TranscriptSigner(private *ecdsa.PrivateKey) (TranscriptSigner, error) {
	if private == nil || private.D == nil || private.PublicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("handshake: P-256 transcript private key is invalid")
	}
	rawPrivate, err := private.Bytes()
	if err != nil {
		return nil, fmt.Errorf("handshake: encode P-256 transcript private key: %w", err)
	}
	defer zeroBindingBytes(rawPrivate)
	ownedPrivate, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), rawPrivate)
	if err != nil {
		return nil, fmt.Errorf("handshake: parse P-256 transcript private key: %w", err)
	}
	encoded, err := ownedPrivate.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("handshake: encode P-256 transcript public key: %w", err)
	}
	return &ecdsaP256TranscriptSigner{
		private: ownedPrivate,
		public: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       encoded,
		},
	}, nil
}

func (s *ecdsaP256TranscriptSigner) PublicKey() protocol.PublicKeyRecord {
	if s == nil {
		return protocol.PublicKeyRecord{}
	}
	return protocol.PublicKeyRecord{
		SignatureScheme: s.public.SignatureScheme,
		KeyEncoding:     s.public.KeyEncoding,
		PublicKey:       append([]byte(nil), s.public.PublicKey...),
	}
}

func (s *ecdsaP256TranscriptSigner) SignTranscript(ctx context.Context, transcript []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("handshake: nil P-256 transcript context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.private == nil {
		return nil, fmt.Errorf("handshake: P-256 transcript signer is missing")
	}
	return ecdsa.SignASN1(rand.Reader, s.private, transcript)
}

type mldsa65TranscriptSigner struct {
	private *mldsa65.PrivateKey
	public  protocol.PublicKeyRecord
}

// NewMLDSA65TranscriptSigner constructs a transcript signer from an ML-DSA-65 private key.
func NewMLDSA65TranscriptSigner(private *mldsa65.PrivateKey) (TranscriptSigner, error) {
	if private == nil {
		return nil, fmt.Errorf("handshake: ML-DSA-65 transcript private key is invalid")
	}
	rawPrivate, err := private.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("handshake: encode ML-DSA-65 transcript private key: %w", err)
	}
	defer zeroBindingBytes(rawPrivate)
	ownedPrivate := new(mldsa65.PrivateKey)
	if err := ownedPrivate.UnmarshalBinary(rawPrivate); err != nil {
		return nil, fmt.Errorf("handshake: parse ML-DSA-65 transcript private key: %w", err)
	}
	public, ok := ownedPrivate.Public().(*mldsa65.PublicKey)
	if !ok || public == nil {
		return nil, fmt.Errorf("handshake: ML-DSA-65 transcript public key is invalid")
	}
	return &mldsa65TranscriptSigner{
		private: ownedPrivate,
		public: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       append([]byte(nil), public.Bytes()...),
		},
	}, nil
}

func (s *mldsa65TranscriptSigner) PublicKey() protocol.PublicKeyRecord {
	if s == nil {
		return protocol.PublicKeyRecord{}
	}
	return protocol.PublicKeyRecord{
		SignatureScheme: s.public.SignatureScheme,
		KeyEncoding:     s.public.KeyEncoding,
		PublicKey:       append([]byte(nil), s.public.PublicKey...),
	}
}

func (s *mldsa65TranscriptSigner) SignTranscript(ctx context.Context, transcript []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("handshake: nil ML-DSA-65 transcript context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.private == nil {
		return nil, fmt.Errorf("handshake: ML-DSA-65 transcript signer is missing")
	}
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.private, transcript, nil, false, signature); err != nil {
		return nil, err
	}
	return signature, nil
}
