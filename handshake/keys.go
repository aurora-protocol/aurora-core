package handshake

import (
	"bytes"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

type HandshakeSecrets struct {
	EarlySecret           []byte
	DerivedSecret         []byte
	HandshakeSecret       []byte
	ClientHandshakeSecret []byte
	ServerHandshakeSecret []byte
	ClientFinishedKey     []byte
	ServerFinishedKey     []byte
	ClientHSKey           []byte
	ClientHSIV            []byte
	ServerHSKey           []byte
	ServerHSIV            []byte
}

type CoverStreamBindingInput struct {
	OuterExporterValue       []byte
	HTTPVersion              []byte
	ConnectionIDHash         []byte
	StreamIDOrRequestID      uint64
	MethodFamilyID           uint64
	NormalizedAuthorityHash  []byte
	NormalizedPathTemplateID []byte
	RequestClassID           uint64
	ClientCoverRandom        []byte
}

func CoverStreamBinding(in CoverStreamBindingInput) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 cover stream binding"))
	e.WriteOpaqueFixed(in.OuterExporterValue, 48)
	e.WriteOpaque8(in.HTTPVersion)
	e.WritePreHash(in.ConnectionIDHash)
	e.WriteVarint(in.StreamIDOrRequestID)
	e.WriteVarint(in.MethodFamilyID)
	e.WritePreHash(in.NormalizedAuthorityHash)
	e.WriteOpaqueFixed(in.NormalizedPathTemplateID, 16)
	e.WriteVarint(in.RequestClassID)
	e.WriteOpaqueFixed(in.ClientCoverRandom, 32)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func FirstHopBindingContext(outerExporterValue, coverStreamBinding []byte) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 first-hop binding context"))
	e.WriteOpaqueFixed(outerExporterValue, 48)
	e.WritePreHash(coverStreamBinding)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return auroracrypto.PreHash(preimage), nil
}

func PreludeTranscriptHash(suite uint64, coverStreamBinding []byte, p0 protocol.CoverPrelude0, p1 protocol.CoverPrelude1) ([]byte, error) {
	encoded0, err := protocol.Encode(p0)
	if err != nil {
		return nil, err
	}
	encoded1, err := protocol.Encode(p1.Unsigned())
	if err != nil {
		return nil, err
	}
	return auroracrypto.SuiteHash(suite,
		[]byte("aurora v2.0 prelude transcript"),
		coverStreamBinding,
		encoded0,
		encoded1,
	)
}

type CoverPreludeVerificationInput struct {
	Suite              uint64
	CoverStreamBinding []byte
	Prelude0           protocol.CoverPrelude0
	Prelude1           protocol.CoverPrelude1
	Descriptor         protocol.RelayDescriptor
	RequirePQ          bool
}

func VerifyCoverPrelude1Signatures(in CoverPreludeVerificationInput) ([]byte, error) {
	if in.Prelude0.MsgType != registry.MsgCoverPrelude0 || in.Prelude0.Version != registry.Version20 {
		return nil, fmt.Errorf("handshake: invalid CoverPrelude0 header")
	}
	if in.Prelude1.MsgType != registry.MsgCoverPrelude1 || in.Prelude1.Version != registry.Version20 {
		return nil, fmt.Errorf("handshake: invalid CoverPrelude1 header")
	}
	if in.Prelude1.SelectedSuite != in.Suite {
		return nil, fmt.Errorf("handshake: selected suite mismatch")
	}
	if !suiteOffered(in.Prelude0.SuiteOffers, in.Suite) {
		return nil, fmt.Errorf("handshake: selected suite was not offered")
	}
	if !suiteOffered(in.Descriptor.SupportedSuiteIDs, in.Suite) {
		return nil, fmt.Errorf("handshake: selected suite is not supported by descriptor")
	}
	if err := ValidatePreludeHybridShares(in.Suite, in.Prelude0, in.Prelude1); err != nil {
		return nil, err
	}
	if in.Prelude1.RelayEpochID != in.Descriptor.EpochID {
		return nil, fmt.Errorf("handshake: relay epoch mismatch")
	}
	descriptorHash, err := trust.RelayDescriptorHash(in.Descriptor)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(in.Prelude0.RelayDescriptorHash, descriptorHash) || !bytes.Equal(in.Prelude1.RelayDescriptorHash, descriptorHash) {
		return nil, fmt.Errorf("handshake: prelude descriptor hash mismatch")
	}
	if !bytes.Equal(in.Prelude0.CoverTemplateHash, in.Prelude1.CoverTemplateHash) {
		return nil, fmt.Errorf("handshake: cover template hash mismatch")
	}
	transcript, err := PreludeTranscriptHash(in.Suite, in.CoverStreamBinding, in.Prelude0, in.Prelude1)
	if err != nil {
		return nil, err
	}
	if len(in.Prelude1.ServerPreludeSignatureClassical) == 0 {
		return nil, fmt.Errorf("handshake: missing classical prelude signature")
	}
	if err := verifyPublicKeySignature(in.Descriptor.EpochAuthClassicalKey, transcript, in.Prelude1.ServerPreludeSignatureClassical); err != nil {
		return nil, err
	}
	if in.RequirePQ || len(in.Prelude1.ServerPreludeSignaturePQ) > 0 {
		if len(in.Prelude1.ServerPreludeSignaturePQ) == 0 {
			return nil, fmt.Errorf("handshake: missing PQ prelude signature")
		}
		if err := verifyPublicKeySignature(in.Descriptor.EpochAuthPQKey, transcript, in.Prelude1.ServerPreludeSignaturePQ); err != nil {
			return nil, err
		}
	}
	return transcript, nil
}

func verifyPublicKeySignature(key protocol.PublicKeyRecord, digest, signature []byte) error {
	return auroracrypto.VerifySignature(key.SignatureScheme, key.KeyEncoding, key.PublicKey, digest, signature)
}

func suiteOffered(offers []uint64, selected uint64) bool {
	for _, offer := range offers {
		if offer == selected {
			return true
		}
	}
	return false
}

func DeriveHandshakeSecrets(suite uint64, ssPQ, ssClassical, handshakeBindingContext, preludeTranscriptHash []byte) (HandshakeSecrets, error) {
	hashLen, err := auroracrypto.SuiteHashLength(suite)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	zeros := make([]byte, hashLen)
	early, err := auroracrypto.HKDFExtractForSuite(suite, zeros, zeros)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	derived, err := auroracrypto.HKDFExpandLabelForSuite(suite, early, "derived", nil, hashLen)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	ikm := append(append(append([]byte(nil), ssPQ...), ssClassical...), handshakeBindingContext...)
	handshakeSecret, err := auroracrypto.HKDFExtractForSuite(suite, ikm, derived)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	clientHS, err := auroracrypto.HKDFExpandLabelForSuite(suite, handshakeSecret, "client hs", preludeTranscriptHash, hashLen)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	serverHS, err := auroracrypto.HKDFExpandLabelForSuite(suite, handshakeSecret, "server hs", preludeTranscriptHash, hashLen)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	clientFinished, err := auroracrypto.HKDFExpandLabelForSuite(suite, clientHS, "finished", nil, hashLen)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	serverFinished, err := auroracrypto.HKDFExpandLabelForSuite(suite, serverHS, "finished", nil, hashLen)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	keyLen, err := auroracrypto.AEADKeyLength(suite)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	clientKey, err := auroracrypto.HKDFExpandLabelForSuite(suite, clientHS, "key", nil, keyLen)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	clientIV, err := auroracrypto.HKDFExpandLabelForSuite(suite, clientHS, "iv", nil, 12)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	serverKey, err := auroracrypto.HKDFExpandLabelForSuite(suite, serverHS, "key", nil, keyLen)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	serverIV, err := auroracrypto.HKDFExpandLabelForSuite(suite, serverHS, "iv", nil, 12)
	if err != nil {
		return HandshakeSecrets{}, err
	}
	return HandshakeSecrets{
		EarlySecret:           early,
		DerivedSecret:         derived,
		HandshakeSecret:       handshakeSecret,
		ClientHandshakeSecret: clientHS,
		ServerHandshakeSecret: serverHS,
		ClientFinishedKey:     clientFinished,
		ServerFinishedKey:     serverFinished,
		ClientHSKey:           clientKey,
		ClientHSIV:            clientIV,
		ServerHSKey:           serverKey,
		ServerHSIV:            serverIV,
	}, nil
}

func ComputeClientFinished(suite uint64, clientFinishedKey, preludeTranscriptHash []byte, capsule1 protocol.CoverCapsule1Plain) ([]byte, error) {
	encodedUnsigned, err := protocol.Encode(capsule1.UnsignedClientFinished())
	if err != nil {
		return nil, err
	}
	return computeClientFinished(suite, clientFinishedKey, preludeTranscriptHash, encodedUnsigned)
}

func ComputeRouteClientFinished(suite uint64, clientFinishedKey, hopPreludeTranscriptHash []byte, capsule1 protocol.RouteCapsule1Plain) ([]byte, error) {
	encodedUnsigned, err := protocol.Encode(capsule1.UnsignedClientFinished())
	if err != nil {
		return nil, err
	}
	return computeClientFinished(suite, clientFinishedKey, hopPreludeTranscriptHash, encodedUnsigned)
}

func computeClientFinished(suite uint64, clientFinishedKey, transcriptHashForHop, encodedUnsignedCapsule1 []byte) ([]byte, error) {
	capsuleHash, err := auroracrypto.SuiteHash(suite, encodedUnsignedCapsule1)
	if err != nil {
		return nil, err
	}
	input, err := auroracrypto.SuiteHash(suite,
		[]byte("aurora v2.0 client finished"),
		transcriptHashForHop,
		capsuleHash,
	)
	if err != nil {
		return nil, err
	}
	return auroracrypto.HMACForSuite(suite, clientFinishedKey, input)
}

func ComputeServerFinished(suite uint64, serverFinishedKey, preludeTranscriptHash []byte, capsule1 protocol.CoverCapsule1Plain, accept protocol.PolicyAccept) ([]byte, []byte, []byte, error) {
	encodedCapsule1, err := protocol.Encode(capsule1)
	if err != nil {
		return nil, nil, nil, err
	}
	return computeServerFinished(suite, serverFinishedKey, preludeTranscriptHash, encodedCapsule1, accept)
}

func ComputeRouteServerFinished(suite uint64, serverFinishedKey, hopPreludeTranscriptHash []byte, capsule1 protocol.RouteCapsule1Plain, accept protocol.PolicyAccept) ([]byte, []byte, []byte, error) {
	encodedCapsule1, err := protocol.Encode(capsule1)
	if err != nil {
		return nil, nil, nil, err
	}
	return computeServerFinished(suite, serverFinishedKey, hopPreludeTranscriptHash, encodedCapsule1, accept)
}

func computeServerFinished(suite uint64, serverFinishedKey, transcriptHashForHop, encodedCapsule1 []byte, accept protocol.PolicyAccept) ([]byte, []byte, []byte, error) {
	capsule1Hash, err := auroracrypto.SuiteHash(suite, encodedCapsule1)
	if err != nil {
		return nil, nil, nil, err
	}
	encodedAccept, err := protocol.Encode(accept)
	if err != nil {
		return nil, nil, nil, err
	}
	policyAcceptHash, err := auroracrypto.SuiteHash(suite, encodedAccept)
	if err != nil {
		return nil, nil, nil, err
	}
	input, err := auroracrypto.SuiteHash(suite,
		[]byte("aurora v2.0 server finished"),
		transcriptHashForHop,
		capsule1Hash,
		policyAcceptHash,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	finished, err := auroracrypto.HMACForSuite(suite, serverFinishedKey, input)
	if err != nil {
		return nil, nil, nil, err
	}
	return finished, capsule1Hash, policyAcceptHash, nil
}

type ApplicationSecrets struct {
	ApplicationTranscriptHash []byte
	ApplicationSecret         []byte
	ClientAppSecret0          []byte
	ServerAppSecret0          []byte
	ClientAppKey0             []byte
	ClientAppIV0              []byte
	ServerAppKey0             []byte
	ServerAppIV0              []byte
}

func DeriveApplicationSecrets(suite uint64, handshakeSecret, preludeTranscriptHash, capsule1PlainHash, policyAcceptHash, serverFinished []byte) (ApplicationSecrets, error) {
	hashLen, err := auroracrypto.SuiteHashLength(suite)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	applicationTranscript, err := auroracrypto.SuiteHash(suite,
		[]byte("aurora v2.0 application transcript"),
		preludeTranscriptHash,
		capsule1PlainHash,
		policyAcceptHash,
		serverFinished,
	)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	derivedHandshake, err := auroracrypto.HKDFExpandLabelForSuite(suite, handshakeSecret, "derived", nil, hashLen)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	applicationSecret, err := auroracrypto.HKDFExtractForSuite(suite, make([]byte, hashLen), derivedHandshake)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	clientApp, err := auroracrypto.HKDFExpandLabelForSuite(suite, applicationSecret, "client app", applicationTranscript, hashLen)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	serverApp, err := auroracrypto.HKDFExpandLabelForSuite(suite, applicationSecret, "server app", applicationTranscript, hashLen)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	keyLen, err := auroracrypto.AEADKeyLength(suite)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	clientKey, clientIV, err := trafficKeyIV(suite, clientApp, keyLen)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	serverKey, serverIV, err := trafficKeyIV(suite, serverApp, keyLen)
	if err != nil {
		return ApplicationSecrets{}, err
	}
	return ApplicationSecrets{
		ApplicationTranscriptHash: applicationTranscript,
		ApplicationSecret:         applicationSecret,
		ClientAppSecret0:          clientApp,
		ServerAppSecret0:          serverApp,
		ClientAppKey0:             clientKey,
		ClientAppIV0:              clientIV,
		ServerAppKey0:             serverKey,
		ServerAppIV0:              serverIV,
	}, nil
}

func trafficKeyIV(suite uint64, secret []byte, keyLen int) ([]byte, []byte, error) {
	key, err := auroracrypto.HKDFExpandLabelForSuite(suite, secret, "key", nil, keyLen)
	if err != nil {
		return nil, nil, err
	}
	iv, err := auroracrypto.HKDFExpandLabelForSuite(suite, secret, "iv", nil, 12)
	if err != nil {
		return nil, nil, err
	}
	if len(key) != keyLen || len(iv) != 12 {
		return nil, nil, fmt.Errorf("handshake: invalid traffic key/iv lengths")
	}
	return key, iv, nil
}
