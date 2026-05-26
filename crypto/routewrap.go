package auroracrypto

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type RouteWrapInput struct {
	RouteInstanceID                uint64
	HopIndex                       uint8
	PreviousHopRelayDescriptorHash []byte
	NextRelayDescriptorHash        []byte
	HintIssuerID                   []byte
	RelayBucketID                  []byte
	HintEpochID                    uint64
	HintSelector                   []byte
	WrapSuiteID                    uint64
	WrapNonce                      []byte
	HintSecret                     []byte
}

func RoutePreludeWrapContext(in RouteWrapInput) ([]byte, error) {
	if in.WrapSuiteID != registry.WrapSuiteRouteV1 {
		return nil, fmt.Errorf("crypto: unsupported route wrap suite 0x%x", in.WrapSuiteID)
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 route prelude wrap context"))
	e.WriteVarint(in.RouteInstanceID)
	e.WriteUint8(in.HopIndex)
	e.WritePreHash(in.PreviousHopRelayDescriptorHash)
	e.WritePreHash(in.NextRelayDescriptorHash)
	e.WriteOpaqueFixed(in.HintIssuerID, 16)
	e.WriteOpaqueFixed(in.RelayBucketID, 16)
	e.WriteUint64(in.HintEpochID)
	e.WriteOpaqueFixed(in.HintSelector, 16)
	e.WriteVarint(in.WrapSuiteID)
	e.WriteOpaqueFixed(in.WrapNonce, 16)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return PreHash(preimage), nil
}

func RoutePreludeWrapKeyIV(in RouteWrapInput) (context, key, iv []byte, err error) {
	context, err = RoutePreludeWrapContext(in)
	if err != nil {
		return nil, nil, nil, err
	}
	secret, err := HKDFExtractSHA384(in.HintSecret, []byte("aurora v2.0 route prelude wrap"))
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = HKDFExpandLabelSHA384(secret, "key", context, 32)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err = HKDFExpandLabelSHA384(secret, "iv", context, 12)
	if err != nil {
		return nil, nil, nil, err
	}
	return context, key, iv, nil
}

func RouteWrapAAD(wrapSuiteID uint64, context []byte) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 route prelude envelope aad"))
	e.WriteVarint(wrapSuiteID)
	e.WritePreHash(context)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return PreHash(preimage), nil
}

func SealRoutePrelude(in RouteWrapInput, plaintext []byte) (context, key, iv, aad, sealed []byte, err error) {
	context, key, iv, err = RoutePreludeWrapKeyIV(in)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	aad, err = RouteWrapAAD(in.WrapSuiteID, context)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	nonce, err := XORNonce96(iv, 0)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	sealed, err = AES256GCMSeal(key, nonce, aad, plaintext)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return context, key, iv, aad, sealed, nil
}

func OpenRoutePrelude(in RouteWrapInput, sealed []byte) ([]byte, error) {
	context, key, iv, err := RoutePreludeWrapKeyIV(in)
	if err != nil {
		return nil, err
	}
	aad, err := RouteWrapAAD(in.WrapSuiteID, context)
	if err != nil {
		return nil, err
	}
	nonce, err := XORNonce96(iv, 0)
	if err != nil {
		return nil, err
	}
	return AES256GCMOpen(key, nonce, aad, sealed)
}
