package handshake

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestPadCoverPrelude0UsesOwnedRandomPaddingWithinEnvelope(t *testing.T) {
	input := paddingPrelude0()
	wantInput := input
	wantInput.Padding = append([]byte(nil), input.Padding...)
	random := &countingPaddingReader{value: 0xa1}

	padded, encoded, err := padCoverPrelude0(random, input, 1536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	assertPaddedBody(t, encoded, 1536, 4096, padded.Padding, random)
	if bytes.Contains(padded.Padding, []byte("caller-padding")) {
		t.Fatal("preexisting Prelude0 padding was retained")
	}
	if !reflect.DeepEqual(input, wantInput) {
		t.Fatal("Prelude0 input was mutated")
	}
}

func TestPadCoverPrelude1FinalizesSignaturesBeforeLengthCheck(t *testing.T) {
	input := paddingPrelude1()
	wantInput := clonePaddingPrelude1(input)
	random := &countingPaddingReader{value: 0xa2}
	finalize := func(value protocol.CoverPrelude1) (protocol.CoverPrelude1, []byte, error) {
		value.ServerPreludeSignatureClassical = bytes.Repeat([]byte{0xc1}, 70+len(value.ResponsePadding)%3)
		value.ServerPreludeSignaturePQ = bytes.Repeat([]byte{0xc2}, 3309)
		encoded, err := protocol.Encode(value)
		return value, encoded, err
	}

	padded, encoded, err := padCoverPrelude1(random, input, 6144, 8192, finalize)
	if err != nil {
		t.Fatal(err)
	}
	assertPaddedBody(t, encoded, 6144, 8192, padded.ResponsePadding, random)
	if len(padded.ServerPreludeSignatureClassical) < 70 || len(padded.ServerPreludeSignaturePQ) != 3309 {
		t.Fatal("Prelude1 final signatures were not retained")
	}
	if !reflect.DeepEqual(input, wantInput) {
		t.Fatal("Prelude1 input was mutated")
	}
}

func TestPadCoverCapsulesChecksFinalAEADBody(t *testing.T) {
	t.Run("capsule1", func(t *testing.T) {
		input := paddingCapsule1()
		wantInput := clonePaddingCapsule1(input)
		random := &countingPaddingReader{value: 0xa3}
		finalize := func(value protocol.CoverCapsule1Plain) (protocol.CoverCapsule1Plain, []byte, error) {
			value.ClientFinished = bytes.Repeat([]byte{0xf1}, 48)
			encoded, err := protocol.Encode(value)
			if err != nil {
				return protocol.CoverCapsule1Plain{}, nil, err
			}
			return value, append(encoded, make([]byte, 16)...), nil
		}
		padded, sealed, err := padCoverCapsule1(random, input, 1024, 8192, finalize)
		if err != nil {
			t.Fatal(err)
		}
		assertPaddedBody(t, sealed, 1024, 8192, padded.Padding, random)
		if !reflect.DeepEqual(input, wantInput) {
			t.Fatal("Capsule1 input was mutated")
		}
	})

	t.Run("capsule2", func(t *testing.T) {
		input := paddingCapsule2()
		wantInput := clonePaddingCapsule2(input)
		random := &countingPaddingReader{value: 0xa4}
		finalize := func(value protocol.CoverCapsule2Plain) (protocol.CoverCapsule2Plain, []byte, error) {
			encoded, err := protocol.Encode(value)
			if err != nil {
				return protocol.CoverCapsule2Plain{}, nil, err
			}
			return value, append(encoded, make([]byte, 16)...), nil
		}
		padded, sealed, err := padCoverCapsule2(random, input, 1024, 8192, finalize)
		if err != nil {
			t.Fatal(err)
		}
		assertPaddedBody(t, sealed, 1024, 8192, padded.Padding, random)
		if !reflect.DeepEqual(input, wantInput) {
			t.Fatal("Capsule2 input was mutated")
		}
	})
}

func TestPaddingHelpersRejectInvalidEnvelopeWithoutPartialOutput(t *testing.T) {
	tests := []struct {
		name string
		min  uint64
		max  uint64
		rng  io.Reader
	}{
		{name: "inverted", min: 2000, max: 1999, rng: &countingPaddingReader{value: 1}},
		{name: "record limit", min: 1, max: maxBootstrapRecordBodyBytes + 1, rng: &countingPaddingReader{value: 1}},
		{name: "canonical body too large", min: 1, max: 64, rng: &countingPaddingReader{value: 1}},
		{name: "entropy failure", min: 1536, max: 4096, rng: errorPaddingReader{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			padded, encoded, err := padCoverPrelude0(test.rng, paddingPrelude0(), test.min, test.max)
			if err == nil {
				t.Fatal("invalid padding request accepted")
			}
			if !reflect.DeepEqual(padded, protocol.CoverPrelude0{}) || encoded != nil {
				t.Fatal("padding failure returned partial output")
			}
		})
	}
}

func TestPaddingHelpersRejectFinalizerFailureWithoutPartialOutput(t *testing.T) {
	finalize := func(protocol.CoverPrelude1) (protocol.CoverPrelude1, []byte, error) {
		return protocol.CoverPrelude1{}, nil, errors.New("signing failed")
	}
	padded, encoded, err := padCoverPrelude1(&countingPaddingReader{value: 1}, paddingPrelude1(), 6144, 8192, finalize)
	if err == nil {
		t.Fatal("Prelude1 finalizer failure accepted")
	}
	if !reflect.DeepEqual(padded, protocol.CoverPrelude1{}) || encoded != nil {
		t.Fatal("Prelude1 finalizer failure returned partial output")
	}
}

type countingPaddingReader struct {
	value byte
	read  int
}

func (r *countingPaddingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.value
	}
	r.read += len(p)
	return len(p), nil
}

type errorPaddingReader struct{}

func (errorPaddingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func assertPaddedBody(t *testing.T, body []byte, min, max uint64, padding []byte, random *countingPaddingReader) {
	t.Helper()
	if uint64(len(body)) < min || uint64(len(body)) > max {
		t.Fatalf("padded body length %d outside [%d,%d]", len(body), min, max)
	}
	if len(padding) == 0 || random.read != len(padding) {
		t.Fatalf("padding reader consumed %d bytes for %d padding bytes", random.read, len(padding))
	}
	if !bytes.Equal(padding, bytes.Repeat([]byte{random.value}, len(padding))) {
		t.Fatal("padding did not come from configured reader")
	}
}

func paddingPrelude0() protocol.CoverPrelude0 {
	return protocol.CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{registry.SuiteHybrid768P256AESGCM},
		ClientNonce:                 hx(1, 32),
		ClientClassicalEphPub:       hx(2, 65),
		ClientMLKEMEncapsulationKey: hx(3, 1184),
		RelayDescriptorHash:         hx(4, 48),
		CoverTemplateHash:           hx(5, 48),
		RequestClassID:              7,
		HintIssuerID:                hx(6, 16),
		RelayBucketID:               hx(7, 16),
		HintEpochID:                 8,
		HintSelector:                hx(9, 16),
		AccessHint:                  hx(10, 16),
		ClientCoverRandom:           hx(11, 32),
		Padding:                     []byte("caller-padding"),
	}
}

func paddingPrelude1() protocol.CoverPrelude1 {
	return protocol.CoverPrelude1{
		MsgType:                       registry.MsgCoverPrelude1,
		Version:                       registry.Version20,
		SelectedSuite:                 registry.SuiteHybrid768P256AESGCM,
		RelayDescriptorHash:           hx(12, 48),
		CoverTemplateHash:             hx(13, 48),
		RelayEpochID:                  14,
		ServerNonce:                   hx(15, 32),
		ServerClassicalEphPub:         hx(16, 65),
		ServerMLKEMCiphertextToClient: hx(17, 1088),
		SelectedCoverProfileID:        hx(18, 16),
		SelectedBootstrapEnvelopeID:   hx(19, 16),
		ResponsePadding:               []byte("caller-padding"),
	}
}

func paddingCapsule1() protocol.CoverCapsule1Plain {
	return protocol.CoverCapsule1Plain{
		MsgType:         registry.MsgCoverCapsule1,
		RouteInstanceID: 20,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              hx(20, 16),
			TokenKeyID:            hx(21, 32),
			RelayBucketID:         hx(22, 16),
			TokenScopeID:          hx(23, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            hx(24, 32),
			RedemptionContextHash: hx(25, 48),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       26,
			TokenRedemptionHash: hx(27, 48),
			ClientReplayNonce:   hx(28, 32),
			ReplayContextHash:   hx(29, 48),
			ReplayWindowID:      hx(30, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768P256AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyFastWeb,
			RequestedPolicyID:       registry.PolicyBalancedWeb,
			RequestedRouteModeID:    registry.RouteFast1,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
		ClientFinished: hx(21, 48),
		Padding:        []byte("caller-padding"),
	}
}

func paddingCapsule2() protocol.CoverCapsule2Plain {
	return protocol.CoverCapsule2Plain{
		MsgType:         registry.MsgCoverCapsule2,
		RouteInstanceID: 22,
		ServerFinished:  hx(23, 48),
		Padding:         []byte("caller-padding"),
	}
}

func clonePaddingPrelude1(in protocol.CoverPrelude1) protocol.CoverPrelude1 {
	in.ResponsePadding = append([]byte(nil), in.ResponsePadding...)
	return in
}

func clonePaddingCapsule1(in protocol.CoverCapsule1Plain) protocol.CoverCapsule1Plain {
	in.ClientFinished = append([]byte(nil), in.ClientFinished...)
	in.Padding = append([]byte(nil), in.Padding...)
	return in
}

func clonePaddingCapsule2(in protocol.CoverCapsule2Plain) protocol.CoverCapsule2Plain {
	in.ServerFinished = append([]byte(nil), in.ServerFinished...)
	in.Padding = append([]byte(nil), in.Padding...)
	return in
}
