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
