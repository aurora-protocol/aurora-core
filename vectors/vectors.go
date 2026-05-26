package vectors

import (
	"encoding/hex"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/route"
	"github.com/aurora-protocol/aurora-core/wire"
)

type StructuralBundle struct {
	ControlAAD                    string
	RouteWrapCiphertextTag        string
	PreviousHopFullTranscriptHash string
	AuthorityKeyID                string
	PublicKeyRecord               string
	AuthorityKeyRecord            string
	FlowOpen                      string
	UDPTargetConfirm              string
	FlowClose                     string
}

func GenerateStructuralBundle() (StructuralBundle, error) {
	controlAAD, err := auroracrypto.ControlAAD(auroracrypto.ControlAADInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		MsgType:                         registry.MsgCoverCapsule1,
		RouteInstanceID:                 1,
		HandshakeBindingContext:         repeated(0xaa, 48),
		PreludeTranscriptHashForThisHop: repeated(0xbb, 48),
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	_, _, _, _, sealed, err := auroracrypto.SealRoutePrelude(auroracrypto.RouteWrapInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: repeated(0x41, 48),
		NextRelayDescriptorHash:        repeated(0x42, 48),
		HintIssuerID:                   repeated(0x34, 16),
		RelayBucketID:                  repeated(0x35, 16),
		HintEpochID:                    7,
		HintSelector:                   repeated(0x31, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      repeated(0x32, 16),
		HintSecret:                     repeated(0x33, 32),
	}, repeated(0x44, 16))
	if err != nil {
		return StructuralBundle{}, err
	}
	previousHopFullTranscript, err := route.PreviousHopFullTranscriptHash(registry.SuiteHybrid768AESGCM, repeated(0x66, 48))
	if err != nil {
		return StructuralBundle{}, err
	}
	pk := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       repeated(0x04, 65),
	}
	encodedPK, err := wire.Encode(pk)
	if err != nil {
		return StructuralBundle{}, err
	}
	keyID := auroracrypto.Truncate128(auroracrypto.PreHashLabel("aurora v2.0 authority key id", encodedPK))
	akr := protocol.AuthorityKeyRecord{
		AuthorityID:    repeated(0x11, 16),
		AuthorityKeyID: keyID,
		AuthorityRole:  1,
		PublicKey:      pk,
		ValidFromUnix:  1700000000,
		ValidUntilUnix: 1800000000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageAllKnownAuthority,
	}
	encodedAKR, err := wire.Encode(akr)
	if err != nil {
		return StructuralBundle{}, err
	}
	flowOpen, err := wire.Encode(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           7,
		FlowKind:         0x02,
		TargetKind:       0x01,
		TargetHost:       []byte{93, 184, 216, 34},
		TargetPort:       443,
		UDPFQDNMode:      0x01,
		NameBindingID:    repeated(0x51, 16),
		DNSAnswerSetHash: repeated(0x52, 48),
		LocalBindingMode: 0x02,
		PriorityClass:    0x03,
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	udpConfirm, err := wire.Encode(protocol.UDPTargetConfirm{
		FlowID:           7,
		TargetKind:       0x01,
		SelectedIP:       []byte{93, 184, 216, 34},
		SelectedPort:     443,
		DNSAnswerSetHash: repeated(0x52, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	flowClose, err := wire.Encode(protocol.FlowClose{
		FlowID:                   7,
		CloseCode:                protocol.CloseNormal,
		FinalSequenceHintPresent: true,
		FinalSequenceHint:        99,
		Reason:                   []byte("done"),
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	return StructuralBundle{
		ControlAAD:                    hex.EncodeToString(controlAAD),
		RouteWrapCiphertextTag:        hex.EncodeToString(sealed),
		PreviousHopFullTranscriptHash: hex.EncodeToString(previousHopFullTranscript),
		AuthorityKeyID:                hex.EncodeToString(keyID),
		PublicKeyRecord:               hex.EncodeToString(encodedPK),
		AuthorityKeyRecord:            hex.EncodeToString(encodedAKR),
		FlowOpen:                      hex.EncodeToString(flowOpen),
		UDPTargetConfirm:              hex.EncodeToString(udpConfirm),
		FlowClose:                     hex.EncodeToString(flowClose),
	}, nil
}

func repeated(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
