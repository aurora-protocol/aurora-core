package transport

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
)

type CarrierPayloadKind uint8

const (
	CarrierPayloadStream CarrierPayloadKind = iota + 1
	CarrierPayloadMessage
	CarrierPayloadDatagram
)

type CarrierPayload struct {
	Kind CarrierPayloadKind
	Data []byte
}

type CarrierSession struct {
	methodID        uint64
	streamFallback  bool
	nativeDatagrams bool
	initial         []CarrierPayload
}

func NewCarrierSession(built BuiltCarrierRequest) (CarrierSession, error) {
	if built.MethodID == 0 {
		return CarrierSession{}, fmt.Errorf("transport: carrier session missing method id")
	}
	if built.StreamFallback && built.NativeDatagrams {
		return CarrierSession{}, fmt.Errorf("transport: carrier session has ambiguous datagram mode")
	}
	if !built.StreamFallback && !built.NativeDatagrams {
		return CarrierSession{}, fmt.Errorf("transport: carrier session missing datagram mode")
	}
	if err := validateCarrierSessionMode(built.MethodID, built.StreamFallback, built.NativeDatagrams); err != nil {
		return CarrierSession{}, err
	}
	session := CarrierSession{
		methodID:        built.MethodID,
		streamFallback:  built.StreamFallback,
		nativeDatagrams: built.NativeDatagrams,
	}
	session.initial = appendPayloads(session.initial, CarrierPayloadStream, built.InitialStreams)
	session.initial = appendPayloads(session.initial, CarrierPayloadMessage, built.InitialMessages)
	session.initial = appendPayloads(session.initial, CarrierPayloadDatagram, built.InitialDatagrams)
	return session, nil
}

func validateCarrierSessionMode(methodID uint64, streamFallback, nativeDatagrams bool) error {
	switch methodID {
	case registry.MethodWebH2Stream, registry.MethodWebH1WS, registry.MethodShadowOrigin, registry.MethodWebH3Stream:
		if !streamFallback || nativeDatagrams {
			return fmt.Errorf("transport: method 0x%x requires stream fallback datagram mode", methodID)
		}
	case registry.MethodWebH3ExtDgram, registry.MethodMasqueConnectIP, registry.MethodMasqueConnectUDP, registry.MethodDirectQUICLab:
		if streamFallback || !nativeDatagrams {
			return fmt.Errorf("transport: method 0x%x requires native datagram mode", methodID)
		}
	default:
		return fmt.Errorf("transport: carrier session unsupported method 0x%x", methodID)
	}
	return nil
}

func (s CarrierSession) InitialPayloads() []CarrierPayload {
	return cloneCarrierPayloads(s.initial)
}

func (s CarrierSession) SendStream(data []byte) (CarrierPayload, error) {
	if len(data) == 0 {
		return CarrierPayload{}, fmt.Errorf("transport: empty carrier stream payload")
	}
	kind := CarrierPayloadStream
	if s.methodID == registry.MethodWebH1WS {
		kind = CarrierPayloadMessage
	}
	return CarrierPayload{Kind: kind, Data: append([]byte(nil), data...)}, nil
}

func (s CarrierSession) SendDatagram(data []byte) (CarrierPayload, error) {
	if len(data) == 0 {
		return CarrierPayload{}, fmt.Errorf("transport: empty carrier datagram payload")
	}
	if s.nativeDatagrams {
		return CarrierPayload{Kind: CarrierPayloadDatagram, Data: append([]byte(nil), data...)}, nil
	}
	if s.streamFallback {
		return s.SendStream(data)
	}
	return CarrierPayload{}, fmt.Errorf("transport: carrier session has no datagram path")
}

func appendPayloads(out []CarrierPayload, kind CarrierPayloadKind, payloads [][]byte) []CarrierPayload {
	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		out = append(out, CarrierPayload{Kind: kind, Data: append([]byte(nil), payload...)})
	}
	return out
}

func cloneCarrierPayloads(in []CarrierPayload) []CarrierPayload {
	out := make([]CarrierPayload, len(in))
	for i, payload := range in {
		out[i] = CarrierPayload{
			Kind: payload.Kind,
			Data: append([]byte(nil), payload.Data...),
		}
	}
	return out
}
