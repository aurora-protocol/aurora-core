package vectors

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/route"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type FirstHopRealCryptoBundle struct {
	ClientClassicalEphPub           string
	ServerClassicalEphPub           string
	ClassicalSharedSecret           string
	ClientMLKEMEncapsulationKey     string
	ServerMLKEMCiphertextToClient   string
	MLKEMSharedSecret               string
	ServerPQPublicKey               string
	ServerPreludeSignatureClassical string
	ServerPreludeSignaturePQ        string
	CoverPrelude0                   string
	CoverPrelude1                   string
	PreludeTranscriptHash           string
}

type RoutePreludeRealCryptoBundle struct {
	RoutePreludeEnvelope                 string
	RoutePrelude0Plaintext               string
	RoutePrelude1                        string
	RouteHopBinding                      string
	RoutePreludeTranscriptHash           string
	RouteClientClassicalEphPub           string
	RouteServerClassicalEphPub           string
	RouteClassicalSharedSecret           string
	RouteClientMLKEMEncapsulationKey     string
	RouteServerMLKEMCiphertext           string
	RouteMLKEMSharedSecret               string
	RouteServerPQPublicKey               string
	RouteServerPreludeSignatureClassical string
	RouteServerPreludeSignaturePQ        string
}

type TrustMetadataRealCryptoBundle struct {
	DirectoryAuthorityClassicalKey        string
	DirectoryAuthorityPQKey               string
	DirectoryConsensus                    string
	DirectoryConsensusHash                string
	DirectoryConsensusSignatureInputClass string
	DirectoryConsensusSignatureInputPQ    string
	DirectoryConsensusSignatureClassical  string
	DirectoryConsensusSignaturePQ         string
	RelayDescriptor                       string
	RelayDescriptorHash                   string
	RelayDescriptorSignatureInput         string
	RelayDescriptorSignatureClassical     string
	RelayDescriptorSignaturePQ            string
	CoverTemplate                         string
	CoverTemplateHash                     string
	CoverTemplateFamilySignatureInput     string
	CoverTemplateInstanceSignatureInput   string
	CoverTemplateFamilySignature          string
	CoverTemplateInstanceSignature        string
}

func GenerateTrustMetadataRealCryptoBundle() (TrustMetadataRealCryptoBundle, error) {
	const nowUnix = 1700000100

	directoryClassicalSigner, err := ecdsaPrivateKeyFromScalar(repeated(0xd1, 32))
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	directoryClassicalKey := ecdsaPublicKeyRecord(directoryClassicalSigner)
	directoryClassicalKeyID, err := authorityKeyID(directoryClassicalKey)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	directoryClassicalAuthority := protocol.AuthorityKeyRecord{
		AuthorityID:    repeated(0xd0, 16),
		AuthorityKeyID: directoryClassicalKeyID,
		AuthorityRole:  1,
		PublicKey:      directoryClassicalKey,
		ValidFromUnix:  1700000000,
		ValidUntilUnix: 1700003600,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus,
	}

	var directoryPQSeed [mldsa65.SeedSize]byte
	copy(directoryPQSeed[:], repeated(0xd2, len(directoryPQSeed)))
	directoryPQPublic, directoryPQPrivate := mldsa65.NewKeyFromSeed(&directoryPQSeed)
	directoryPQKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       directoryPQPublic.Bytes(),
	}
	directoryPQKeyID, err := authorityKeyID(directoryPQKey)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	directoryPQAuthority := protocol.AuthorityKeyRecord{
		AuthorityID:    repeated(0xd3, 16),
		AuthorityKeyID: directoryPQKeyID,
		AuthorityRole:  1,
		PublicKey:      directoryPQKey,
		ValidFromUnix:  1700000000,
		ValidUntilUnix: 1700003600,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus,
	}

	relayLongtermClassicalSigner, err := ecdsaPrivateKeyFromScalar(repeated(0xd4, 32))
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	relayLongtermClassicalKey := ecdsaPublicKeyRecord(relayLongtermClassicalSigner)
	var relayLongtermPQSeed [mldsa65.SeedSize]byte
	copy(relayLongtermPQSeed[:], repeated(0xd5, len(relayLongtermPQSeed)))
	relayLongtermPQPublic, relayLongtermPQPrivate := mldsa65.NewKeyFromSeed(&relayLongtermPQSeed)
	relayLongtermPQKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       relayLongtermPQPublic.Bytes(),
	}
	relayEpochClassicalSigner, err := ecdsaPrivateKeyFromScalar(repeated(0xd6, 32))
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	relayEpochClassicalKey := ecdsaPublicKeyRecord(relayEpochClassicalSigner)
	var relayEpochPQSeed [mldsa65.SeedSize]byte
	copy(relayEpochPQSeed[:], repeated(0xd7, len(relayEpochPQSeed)))
	relayEpochPQPublic, _ := mldsa65.NewKeyFromSeed(&relayEpochPQSeed)
	relayEpochPQKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       relayEpochPQPublic.Bytes(),
	}

	coverTemplate := sampleCoverTemplate()
	coverTemplate.TemplateFamilySignature = nil
	coverTemplate.TemplateInstanceSignature = nil
	coverTemplate.CoverOriginCommitment, err = trust.CoverOriginCommitment(coverTemplate)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	coverTemplateHash, err := trust.CoverTemplateHash(coverTemplate)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}

	relayDescriptor := sampleRelayDescriptor()
	relayDescriptor.RelayLongtermClassicalKey = relayLongtermClassicalKey
	relayDescriptor.RelayLongtermPQKey = relayLongtermPQKey
	relayDescriptor.EpochAuthClassicalKey = relayEpochClassicalKey
	relayDescriptor.EpochAuthPQKey = relayEpochPQKey
	relayDescriptor.SupportedSuiteIDs = []uint64{registry.SuiteHybrid768P256AESGCM}
	relayDescriptor.CoverTemplateInstanceHashes = [][]byte{coverTemplateHash}
	relayDescriptor.SignatureByLongtermClassical = nil
	relayDescriptor.SignatureByLongtermPQ = nil
	relayDescriptorHash, err := trust.RelayDescriptorHash(relayDescriptor)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	relayDescriptorInput, err := trust.RelayDescriptorSignatureInput(relayDescriptor)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	relayDescriptor.SignatureByLongtermClassical, err = relayLongtermClassicalSigner.Sign(nil, relayDescriptorInput, crypto.SHA384)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	relayDescriptor.SignatureByLongtermPQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(relayLongtermPQPrivate, relayDescriptorInput, nil, false, relayDescriptor.SignatureByLongtermPQ); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	if err := auroracrypto.VerifySignature(relayDescriptor.RelayLongtermClassicalKey.SignatureScheme, relayDescriptor.RelayLongtermClassicalKey.KeyEncoding, relayDescriptor.RelayLongtermClassicalKey.PublicKey, relayDescriptorInput, relayDescriptor.SignatureByLongtermClassical); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	if err := auroracrypto.VerifySignature(relayDescriptor.RelayLongtermPQKey.SignatureScheme, relayDescriptor.RelayLongtermPQKey.KeyEncoding, relayDescriptor.RelayLongtermPQKey.PublicKey, relayDescriptorInput, relayDescriptor.SignatureByLongtermPQ); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}

	coverFamilyInput, err := trust.CoverTemplateFamilySignatureInput(coverTemplate)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	coverInstanceInput, err := trust.CoverTemplateInstanceSignatureInput(relayDescriptorHash, coverTemplate)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	coverTemplate.TemplateFamilySignature, err = directoryClassicalSigner.Sign(nil, coverFamilyInput, crypto.SHA384)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	coverTemplate.TemplateInstanceSignature, err = relayLongtermClassicalSigner.Sign(nil, coverInstanceInput, crypto.SHA384)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	if err := auroracrypto.VerifySignature(directoryClassicalKey.SignatureScheme, directoryClassicalKey.KeyEncoding, directoryClassicalKey.PublicKey, coverFamilyInput, coverTemplate.TemplateFamilySignature); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	if err := auroracrypto.VerifySignature(relayLongtermClassicalKey.SignatureScheme, relayLongtermClassicalKey.KeyEncoding, relayLongtermClassicalKey.PublicKey, coverInstanceInput, coverTemplate.TemplateInstanceSignature); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}

	classicalEntry := protocol.SignatureEntry{
		AuthorityID:     directoryClassicalAuthority.AuthorityID,
		AuthorityKeyID:  directoryClassicalAuthority.AuthorityKeyID,
		SignatureScheme: directoryClassicalAuthority.PublicKey.SignatureScheme,
		KeyEncoding:     directoryClassicalAuthority.PublicKey.KeyEncoding,
	}
	pqEntry := protocol.SignatureEntry{
		AuthorityID:     directoryPQAuthority.AuthorityID,
		AuthorityKeyID:  directoryPQAuthority.AuthorityKeyID,
		SignatureScheme: directoryPQAuthority.PublicKey.SignatureScheme,
		KeyEncoding:     directoryPQAuthority.PublicKey.KeyEncoding,
	}
	directoryConsensus := sampleDirectoryConsensus()
	directoryConsensus.RelayDescriptorRoot = relayDescriptorHash
	directoryConsensus.CoverTemplateFamilyRoot = coverTemplateHash
	directoryConsensus.AuthoritySignatures = []protocol.SignatureEntry{classicalEntry, pqEntry}
	directoryClassicalInput, err := trust.DirectoryConsensusSignatureInput(directoryConsensus, classicalEntry)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	directoryPQInput, err := trust.DirectoryConsensusSignatureInput(directoryConsensus, pqEntry)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	directoryConsensus.AuthoritySignatures[0].Signature, err = directoryClassicalSigner.Sign(nil, directoryClassicalInput, crypto.SHA384)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	directoryConsensus.AuthoritySignatures[1].Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(directoryPQPrivate, directoryPQInput, nil, false, directoryConsensus.AuthoritySignatures[1].Signature); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	if err := trust.VerifyDirectoryConsensusSignatures(directoryConsensus, []protocol.AuthorityKeyRecord{directoryClassicalAuthority, directoryPQAuthority}, nowUnix, 2); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	if err := trust.VerifyStrictDirectoryConsensusSignatures(directoryConsensus, []protocol.AuthorityKeyRecord{directoryClassicalAuthority, directoryPQAuthority}, nowUnix, 1); err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	directoryConsensusHash, err := trust.DirectoryConsensusHash(directoryConsensus)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}

	encodedClassicalAuthority, err := wire.Encode(directoryClassicalAuthority)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	encodedPQAuthority, err := wire.Encode(directoryPQAuthority)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	encodedConsensus, err := wire.Encode(directoryConsensus)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	encodedRelayDescriptor, err := wire.Encode(relayDescriptor)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	encodedCoverTemplate, err := wire.Encode(coverTemplate)
	if err != nil {
		return TrustMetadataRealCryptoBundle{}, err
	}
	return TrustMetadataRealCryptoBundle{
		DirectoryAuthorityClassicalKey:        hex.EncodeToString(encodedClassicalAuthority),
		DirectoryAuthorityPQKey:               hex.EncodeToString(encodedPQAuthority),
		DirectoryConsensus:                    hex.EncodeToString(encodedConsensus),
		DirectoryConsensusHash:                hex.EncodeToString(directoryConsensusHash),
		DirectoryConsensusSignatureInputClass: hex.EncodeToString(directoryClassicalInput),
		DirectoryConsensusSignatureInputPQ:    hex.EncodeToString(directoryPQInput),
		DirectoryConsensusSignatureClassical:  hex.EncodeToString(directoryConsensus.AuthoritySignatures[0].Signature),
		DirectoryConsensusSignaturePQ:         hex.EncodeToString(directoryConsensus.AuthoritySignatures[1].Signature),
		RelayDescriptor:                       hex.EncodeToString(encodedRelayDescriptor),
		RelayDescriptorHash:                   hex.EncodeToString(relayDescriptorHash),
		RelayDescriptorSignatureInput:         hex.EncodeToString(relayDescriptorInput),
		RelayDescriptorSignatureClassical:     hex.EncodeToString(relayDescriptor.SignatureByLongtermClassical),
		RelayDescriptorSignaturePQ:            hex.EncodeToString(relayDescriptor.SignatureByLongtermPQ),
		CoverTemplate:                         hex.EncodeToString(encodedCoverTemplate),
		CoverTemplateHash:                     hex.EncodeToString(coverTemplateHash),
		CoverTemplateFamilySignatureInput:     hex.EncodeToString(coverFamilyInput),
		CoverTemplateInstanceSignatureInput:   hex.EncodeToString(coverInstanceInput),
		CoverTemplateFamilySignature:          hex.EncodeToString(coverTemplate.TemplateFamilySignature),
		CoverTemplateInstanceSignature:        hex.EncodeToString(coverTemplate.TemplateInstanceSignature),
	}, nil
}

func GenerateFirstHopRealCryptoBundle() (FirstHopRealCryptoBundle, error) {
	const suite = registry.SuiteHybrid768P256AESGCM

	clientECDH, err := auroracrypto.NewECDHPrivateKeyForSuite(suite, repeated(0x31, 32))
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	serverECDH, err := auroracrypto.NewECDHPrivateKeyForSuite(suite, repeated(0x41, 32))
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	clientClassicalSecret, err := clientECDH.SharedSecret(serverECDH.PublicKeyBytes())
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	serverClassicalSecret, err := serverECDH.SharedSecret(clientECDH.PublicKeyBytes())
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	if !bytes.Equal(clientClassicalSecret, serverClassicalSecret) {
		return FirstHopRealCryptoBundle{}, fmt.Errorf("vectors: deterministic ECDH shared secret mismatch")
	}

	clientMLKEMPublic, clientMLKEMPrivate := mlkem768.NewKeyFromSeed(repeated(0x51, mlkem768.KeySeedSize))
	clientMLKEMPublicBytes, err := clientMLKEMPublic.MarshalBinary()
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	mlkemCiphertext := make([]byte, mlkem768.CiphertextSize)
	mlkemShared := make([]byte, mlkem768.SharedKeySize)
	clientMLKEMPublic.EncapsulateTo(mlkemCiphertext, mlkemShared, repeated(0x52, mlkem768.EncapsulationSeedSize))
	decapsulated := make([]byte, mlkem768.SharedKeySize)
	clientMLKEMPrivate.DecapsulateTo(decapsulated, mlkemCiphertext)
	if !bytes.Equal(mlkemShared, decapsulated) {
		return FirstHopRealCryptoBundle{}, fmt.Errorf("vectors: deterministic ML-KEM shared secret mismatch")
	}

	classicalSigner, err := ecdsaPrivateKeyFromScalar(repeated(0x61, 32))
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	classicalPublic := elliptic.Marshal(elliptic.P256(), classicalSigner.PublicKey.X, classicalSigner.PublicKey.Y)
	var pqSeed [mldsa65.SeedSize]byte
	copy(pqSeed[:], repeated(0x71, len(pqSeed)))
	pqPublic, pqPrivate := mldsa65.NewKeyFromSeed(&pqSeed)

	descriptor := sampleRelayDescriptor()
	descriptor.SupportedSuiteIDs = []uint64{suite}
	descriptor.RelayLongtermClassicalKey = protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       append([]byte(nil), classicalPublic...),
	}
	descriptor.EpochAuthClassicalKey = descriptor.RelayLongtermClassicalKey
	descriptor.RelayLongtermPQKey = protocol.PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       pqPublic.Bytes(),
	}
	descriptor.EpochAuthPQKey = descriptor.RelayLongtermPQKey
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	coverTemplateHash, err := trust.CoverTemplateHash(sampleCoverTemplate())
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	p0 := protocol.CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{suite},
		ClientNonce:                 repeated(0x81, 32),
		ClientClassicalEphPub:       clientECDH.PublicKeyBytes(),
		ClientMLKEMEncapsulationKey: clientMLKEMPublicBytes,
		RelayDescriptorHash:         descriptorHash,
		CoverTemplateHash:           coverTemplateHash,
		RequestClassID:              1,
		HintIssuerID:                repeated(0x82, 16),
		RelayBucketID:               repeated(0x83, 16),
		HintEpochID:                 1700000100,
		HintSelector:                repeated(0x84, 16),
		AccessHint:                  repeated(0x85, 16),
		ClientCoverRandom:           repeated(0x86, 32),
		Padding:                     repeated(0x87, 32),
	}
	p1 := protocol.CoverPrelude1{
		MsgType:                       registry.MsgCoverPrelude1,
		Version:                       registry.Version20,
		SelectedSuite:                 suite,
		RelayDescriptorHash:           descriptorHash,
		CoverTemplateHash:             coverTemplateHash,
		RelayEpochID:                  descriptor.EpochID,
		ServerNonce:                   repeated(0x91, 32),
		ServerClassicalEphPub:         serverECDH.PublicKeyBytes(),
		ServerMLKEMCiphertextToClient: mlkemCiphertext,
		SelectedCoverProfileID:        repeated(0x92, 16),
		SelectedBootstrapEnvelopeID:   repeated(0x93, 16),
		ResponsePadding:               repeated(0x94, 32),
	}
	coverStreamBinding := repeated(0xa1, 48)
	transcript, err := handshake.PreludeTranscriptHash(suite, coverStreamBinding, p0, p1)
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	p1.ServerPreludeSignatureClassical, err = classicalSigner.Sign(nil, transcript, crypto.SHA384)
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	p1.ServerPreludeSignaturePQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(pqPrivate, transcript, nil, false, p1.ServerPreludeSignaturePQ); err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	if _, err := handshake.VerifyCoverPrelude1Signatures(handshake.CoverPreludeVerificationInput{
		Suite:              suite,
		CoverStreamBinding: coverStreamBinding,
		Prelude0:           p0,
		Prelude1:           p1,
		Descriptor:         descriptor,
		RequirePQ:          true,
	}); err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	encodedP0, err := wire.Encode(p0)
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	encodedP1, err := wire.Encode(p1)
	if err != nil {
		return FirstHopRealCryptoBundle{}, err
	}
	return FirstHopRealCryptoBundle{
		ClientClassicalEphPub:           hex.EncodeToString(clientECDH.PublicKeyBytes()),
		ServerClassicalEphPub:           hex.EncodeToString(serverECDH.PublicKeyBytes()),
		ClassicalSharedSecret:           hex.EncodeToString(clientClassicalSecret),
		ClientMLKEMEncapsulationKey:     hex.EncodeToString(clientMLKEMPublicBytes),
		ServerMLKEMCiphertextToClient:   hex.EncodeToString(mlkemCiphertext),
		MLKEMSharedSecret:               hex.EncodeToString(mlkemShared),
		ServerPQPublicKey:               hex.EncodeToString(pqPublic.Bytes()),
		ServerPreludeSignatureClassical: hex.EncodeToString(p1.ServerPreludeSignatureClassical),
		ServerPreludeSignaturePQ:        hex.EncodeToString(p1.ServerPreludeSignaturePQ),
		CoverPrelude0:                   hex.EncodeToString(encodedP0),
		CoverPrelude1:                   hex.EncodeToString(encodedP1),
		PreludeTranscriptHash:           hex.EncodeToString(transcript),
	}, nil
}

func GenerateRoutePreludeRealCryptoBundle() (RoutePreludeRealCryptoBundle, error) {
	const suite = registry.SuiteHybrid768P256AESGCM

	clientECDH, err := auroracrypto.NewECDHPrivateKeyForSuite(suite, repeated(0xb1, 32))
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	serverECDH, err := auroracrypto.NewECDHPrivateKeyForSuite(suite, repeated(0xb2, 32))
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	clientClassicalSecret, err := clientECDH.SharedSecret(serverECDH.PublicKeyBytes())
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	serverClassicalSecret, err := serverECDH.SharedSecret(clientECDH.PublicKeyBytes())
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	if !bytes.Equal(clientClassicalSecret, serverClassicalSecret) {
		return RoutePreludeRealCryptoBundle{}, fmt.Errorf("vectors: deterministic route ECDH shared secret mismatch")
	}

	clientMLKEMPublic, clientMLKEMPrivate := mlkem768.NewKeyFromSeed(repeated(0xb3, mlkem768.KeySeedSize))
	clientMLKEMPublicBytes, err := clientMLKEMPublic.MarshalBinary()
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	mlkemCiphertext := make([]byte, mlkem768.CiphertextSize)
	mlkemShared := make([]byte, mlkem768.SharedKeySize)
	clientMLKEMPublic.EncapsulateTo(mlkemCiphertext, mlkemShared, repeated(0xb4, mlkem768.EncapsulationSeedSize))
	decapsulated := make([]byte, mlkem768.SharedKeySize)
	clientMLKEMPrivate.DecapsulateTo(decapsulated, mlkemCiphertext)
	if !bytes.Equal(mlkemShared, decapsulated) {
		return RoutePreludeRealCryptoBundle{}, fmt.Errorf("vectors: deterministic route ML-KEM shared secret mismatch")
	}

	classicalSigner, err := ecdsaPrivateKeyFromScalar(repeated(0xb5, 32))
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	classicalPublic := elliptic.Marshal(elliptic.P256(), classicalSigner.PublicKey.X, classicalSigner.PublicKey.Y)
	var pqSeed [mldsa65.SeedSize]byte
	copy(pqSeed[:], repeated(0xb6, len(pqSeed)))
	pqPublic, pqPrivate := mldsa65.NewKeyFromSeed(&pqSeed)

	descriptor := sampleRelayDescriptor()
	descriptor.SupportedSuiteIDs = []uint64{suite}
	descriptor.RelayLongtermClassicalKey = protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       append([]byte(nil), classicalPublic...),
	}
	descriptor.EpochAuthClassicalKey = descriptor.RelayLongtermClassicalKey
	descriptor.RelayLongtermPQKey = protocol.PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       pqPublic.Bytes(),
	}
	descriptor.EpochAuthPQKey = descriptor.RelayLongtermPQKey
	nextDescriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	previousDescriptorHash, err := trust.RelayDescriptorHash(sampleRelayDescriptor())
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	previousHopFullTranscript, err := route.PreviousHopFullTranscriptHash(suite, repeated(0xb7, 48))
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	env := route.EnvelopeInput{
		RouteInstanceID:                2,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: previousDescriptorHash,
		NextRelayDescriptorHash:        nextDescriptorHash,
		HintIssuerID:                   repeated(0xc0, 16),
		RelayBucketID:                  repeated(0xc1, 16),
		HintEpochID:                    1700000200,
		HintSelector:                   repeated(0xc2, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      repeated(0xc3, 16),
		HintSecret:                     repeated(0xc4, 32),
	}
	wrapContext, err := auroracrypto.RoutePreludeWrapContext(routeWrapInput(env))
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	private := route.PrivatePrelude{
		RoutePreludeWrapContext:       wrapContext,
		PreviousHopFullTranscriptHash: previousHopFullTranscript,
		ClientNonceForThisHop:         repeated(0xc5, 32),
		OfferedSuites:                 []uint64{suite},
		ClientClassicalEphPub:         clientECDH.PublicKeyBytes(),
		ClientMLKEMEncapsulationKey:   clientMLKEMPublicBytes,
		AccessHint:                    repeated(0xc6, 16),
		RequestedRouteModeID:          registry.RouteSplit2,
		CoverShapeHintID:              registry.ShapeNormal,
		Padding:                       repeated(0xc7, 32),
	}
	envelope, err := route.SealPrivatePrelude(env, private)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	openedPrivate, err := route.OpenPrivatePrelude(env, envelope)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	routeHopBinding, err := route.RouteHopBinding(route.HopBindingInput{
		RouteInstanceID:                openedPrivate.RouteInstanceID,
		HopIndex:                       openedPrivate.HopIndex,
		PreviousHopFullTranscriptHash:  openedPrivate.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: openedPrivate.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        openedPrivate.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        openedPrivate.RoutePreludeWrapContext,
		ClientNonceForThisHop:          openedPrivate.ClientNonceForThisHop,
	})
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	p1 := protocol.RoutePrelude1{
		MsgType:                        registry.MsgRoutePrelude1,
		Version:                        registry.Version20,
		RouteInstanceID:                env.RouteInstanceID,
		HopIndex:                       env.HopIndex,
		PreviousHopRelayDescriptorHash: previousDescriptorHash,
		NextRelayDescriptorHash:        nextDescriptorHash,
		NextRelayEpochID:               descriptor.EpochID,
		SelectedSuite:                  suite,
		ServerNonce:                    repeated(0xc8, 32),
		ServerClassicalEphPub:          serverECDH.PublicKeyBytes(),
		ServerMLKEMCiphertextToClient:  mlkemCiphertext,
		SelectedShapeID:                registry.ShapeNormal,
		Padding:                        repeated(0xc9, 32),
	}
	transcript, err := route.HopPreludeTranscriptHash(suite, routeHopBinding, openedPrivate, p1)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	p1.ServerPreludeSignatureClassical, err = classicalSigner.Sign(nil, transcript, crypto.SHA384)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	p1.ServerPreludeSignaturePQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(pqPrivate, transcript, nil, false, p1.ServerPreludeSignaturePQ); err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	if _, err := route.VerifyRoutePrelude1Signatures(route.RoutePreludeVerificationInput{
		Suite:           suite,
		RouteHopBinding: routeHopBinding,
		Prelude0:        openedPrivate,
		Prelude1:        p1,
		Descriptor:      descriptor,
		RequirePQ:       true,
		NowUnix:         descriptor.EpochValidFromUnix,
	}); err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	encodedEnvelope, err := wire.Encode(envelope)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	encodedPrivate, err := wire.Encode(openedPrivate)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	encodedP1, err := wire.Encode(p1)
	if err != nil {
		return RoutePreludeRealCryptoBundle{}, err
	}
	return RoutePreludeRealCryptoBundle{
		RoutePreludeEnvelope:                 hex.EncodeToString(encodedEnvelope),
		RoutePrelude0Plaintext:               hex.EncodeToString(encodedPrivate),
		RoutePrelude1:                        hex.EncodeToString(encodedP1),
		RouteHopBinding:                      hex.EncodeToString(routeHopBinding),
		RoutePreludeTranscriptHash:           hex.EncodeToString(transcript),
		RouteClientClassicalEphPub:           hex.EncodeToString(clientECDH.PublicKeyBytes()),
		RouteServerClassicalEphPub:           hex.EncodeToString(serverECDH.PublicKeyBytes()),
		RouteClassicalSharedSecret:           hex.EncodeToString(clientClassicalSecret),
		RouteClientMLKEMEncapsulationKey:     hex.EncodeToString(clientMLKEMPublicBytes),
		RouteServerMLKEMCiphertext:           hex.EncodeToString(mlkemCiphertext),
		RouteMLKEMSharedSecret:               hex.EncodeToString(mlkemShared),
		RouteServerPQPublicKey:               hex.EncodeToString(pqPublic.Bytes()),
		RouteServerPreludeSignatureClassical: hex.EncodeToString(p1.ServerPreludeSignatureClassical),
		RouteServerPreludeSignaturePQ:        hex.EncodeToString(p1.ServerPreludeSignaturePQ),
	}, nil
}

func routeWrapInput(env route.EnvelopeInput) auroracrypto.RouteWrapInput {
	return auroracrypto.RouteWrapInput{
		RouteInstanceID:                env.RouteInstanceID,
		HopIndex:                       env.HopIndex,
		PreviousHopRelayDescriptorHash: env.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        env.NextRelayDescriptorHash,
		HintIssuerID:                   env.HintIssuerID,
		RelayBucketID:                  env.RelayBucketID,
		HintEpochID:                    env.HintEpochID,
		HintSelector:                   env.HintSelector,
		WrapSuiteID:                    env.WrapSuiteID,
		WrapNonce:                      env.WrapNonce,
		HintSecret:                     env.HintSecret,
	}
}

func ecdsaPrivateKeyFromScalar(scalar []byte) (*ecdsa.PrivateKey, error) {
	d := new(big.Int).SetBytes(scalar)
	if d.Sign() == 0 || d.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, fmt.Errorf("vectors: invalid deterministic ECDSA scalar")
	}
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	if x == nil || y == nil {
		return nil, fmt.Errorf("vectors: invalid deterministic ECDSA public point")
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}, nil
}

func ecdsaPublicKeyRecord(privateKey *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y),
	}
}

func authorityKeyID(record protocol.PublicKeyRecord) ([]byte, error) {
	encoded, err := wire.Encode(record)
	if err != nil {
		return nil, err
	}
	return auroracrypto.Truncate128(auroracrypto.PreHashLabel("aurora v2.0 authority key id", encoded)), nil
}
