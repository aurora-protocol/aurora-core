package handshake

import (
	"crypto/tls"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	outerExporterLabel   = "EXPORTER-aurora-v2.0-outer"
	channelExporterLabel = "EXPORTER-aurora-v2.0-channel-id"
	http2StreamID        = 1
)

type HTTP2BindingMetadata struct {
	NormalizedAuthorityHash []byte
	PathTemplateID          []byte
	RequestClassID          uint64
	MethodFamilyID          uint64
}

type FirstHopBinding struct {
	OuterExporterValue      []byte
	TLSExporterChannelID    []byte
	ConnectionIDHash        []byte
	CoverStreamBinding      []byte
	HandshakeBindingContext []byte
}

func DeriveHTTP2FirstHopBinding(state tls.ConnectionState, metadata HTTP2BindingMetadata, clientCoverRandom []byte) (FirstHopBinding, error) {
	if !state.HandshakeComplete {
		return FirstHopBinding{}, fmt.Errorf("handshake: TLS handshake is incomplete")
	}
	if state.Version != tls.VersionTLS13 {
		return FirstHopBinding{}, fmt.Errorf("handshake: first-hop HTTP/2 binding requires TLS 1.3")
	}
	if state.NegotiatedProtocol != "h2" {
		return FirstHopBinding{}, fmt.Errorf("handshake: first-hop binding requires HTTP/2 ALPN")
	}
	if state.DidResume {
		return FirstHopBinding{}, fmt.Errorf("handshake: resumed TLS is forbidden for first-hop binding")
	}
	if len(metadata.NormalizedAuthorityHash) != 48 {
		return FirstHopBinding{}, fmt.Errorf("handshake: normalized authority hash length %d, want 48", len(metadata.NormalizedAuthorityHash))
	}
	if len(metadata.PathTemplateID) != 16 {
		return FirstHopBinding{}, fmt.Errorf("handshake: path template ID length %d, want 16", len(metadata.PathTemplateID))
	}
	if metadata.RequestClassID == 0 || metadata.RequestClassID > wire.MaxVarint {
		return FirstHopBinding{}, fmt.Errorf("handshake: invalid request class ID")
	}
	if metadata.MethodFamilyID != registry.MethodWebH2Stream {
		return FirstHopBinding{}, fmt.Errorf("handshake: binding metadata is not the HTTP/2 method family")
	}
	if len(clientCoverRandom) != 32 {
		return FirstHopBinding{}, fmt.Errorf("handshake: client cover random length %d, want 32", len(clientCoverRandom))
	}

	outerExporter, err := exportBindingKeyingMaterial(&state, outerExporterLabel)
	if err != nil {
		return FirstHopBinding{}, fmt.Errorf("handshake: outer TLS exporter unavailable: %w", err)
	}
	channelExporter, err := exportBindingKeyingMaterial(&state, channelExporterLabel)
	if err != nil {
		zeroBindingBytes(outerExporter)
		return FirstHopBinding{}, fmt.Errorf("handshake: channel TLS exporter unavailable: %w", err)
	}
	connectionIDHash := auroracrypto.PreHash([]byte("h2"), channelExporter, make([]byte, 48))
	streamBinding, err := CoverStreamBinding(CoverStreamBindingInput{
		OuterExporterValue:       outerExporter,
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         connectionIDHash,
		StreamIDOrRequestID:      http2StreamID,
		MethodFamilyID:           metadata.MethodFamilyID,
		NormalizedAuthorityHash:  metadata.NormalizedAuthorityHash,
		NormalizedPathTemplateID: metadata.PathTemplateID,
		RequestClassID:           metadata.RequestClassID,
		ClientCoverRandom:        clientCoverRandom,
	})
	if err != nil {
		zeroBindingBytes(outerExporter)
		zeroBindingBytes(channelExporter)
		zeroBindingBytes(connectionIDHash)
		return FirstHopBinding{}, err
	}
	bindingContext, err := FirstHopBindingContext(outerExporter, streamBinding)
	if err != nil {
		zeroBindingBytes(outerExporter)
		zeroBindingBytes(channelExporter)
		zeroBindingBytes(connectionIDHash)
		zeroBindingBytes(streamBinding)
		return FirstHopBinding{}, err
	}

	return FirstHopBinding{
		OuterExporterValue:      append([]byte(nil), outerExporter...),
		TLSExporterChannelID:    append([]byte(nil), channelExporter...),
		ConnectionIDHash:        append([]byte(nil), connectionIDHash...),
		CoverStreamBinding:      append([]byte(nil), streamBinding...),
		HandshakeBindingContext: append([]byte(nil), bindingContext...),
	}, nil
}

func exportBindingKeyingMaterial(state *tls.ConnectionState, label string) (material []byte, err error) {
	defer func() {
		if recover() != nil {
			zeroBindingBytes(material)
			material = nil
			err = fmt.Errorf("handshake: TLS exporter state is unavailable")
		}
	}()
	return state.ExportKeyingMaterial(label, []byte{}, 48)
}

func zeroBindingBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
