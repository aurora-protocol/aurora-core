package handshake

import (
	"bytes"
	"fmt"
	"io"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	maxBootstrapRecordBodyBytes uint64 = uint64(wire.DefaultRecordBodyBytes)
	maxPaddingAttempts                 = 4
	preludeSignatureSizeGuard          = 16
)

type prelude1Finalizer func(protocol.CoverPrelude1) (protocol.CoverPrelude1, []byte, error)
type capsule1Finalizer func(protocol.CoverCapsule1Plain) (protocol.CoverCapsule1Plain, []byte, error)
type capsule2Finalizer func(protocol.CoverCapsule2Plain) (protocol.CoverCapsule2Plain, []byte, error)

func padCoverPrelude0(random io.Reader, input protocol.CoverPrelude0, minBodySize, maxBodySize uint64) (protocol.CoverPrelude0, []byte, error) {
	cloned, err := cloneCoverPrelude0(input)
	if err != nil {
		return protocol.CoverPrelude0{}, nil, err
	}
	return padBootstrapBody(random, cloned, minBodySize, maxBodySize, false,
		func(value *protocol.CoverPrelude0, padding []byte) { value.Padding = padding },
		func(value protocol.CoverPrelude0) []byte { return value.Padding },
		func(value protocol.CoverPrelude0) (protocol.CoverPrelude0, []byte, error) {
			encoded, err := protocol.Encode(value)
			return value, encoded, err
		},
	)
}

func padCoverPrelude1(random io.Reader, input protocol.CoverPrelude1, minBodySize, maxBodySize uint64, finalize prelude1Finalizer) (protocol.CoverPrelude1, []byte, error) {
	if finalize == nil {
		return protocol.CoverPrelude1{}, nil, fmt.Errorf("handshake: missing Prelude1 finalizer")
	}
	cloned, err := cloneCoverPrelude1(input)
	if err != nil {
		return protocol.CoverPrelude1{}, nil, err
	}
	cloned.ServerPreludeSignatureClassical = nil
	cloned.ServerPreludeSignaturePQ = nil
	return padBootstrapBody(random, cloned, minBodySize, maxBodySize, true,
		func(value *protocol.CoverPrelude1, padding []byte) { value.ResponsePadding = padding },
		func(value protocol.CoverPrelude1) []byte { return value.ResponsePadding },
		finalize,
	)
}

func padCoverCapsule1(random io.Reader, input protocol.CoverCapsule1Plain, minBodySize, maxBodySize uint64, finalize capsule1Finalizer) (protocol.CoverCapsule1Plain, []byte, error) {
	if finalize == nil {
		return protocol.CoverCapsule1Plain{}, nil, fmt.Errorf("handshake: missing Capsule1 finalizer")
	}
	cloned, err := cloneCoverCapsule1(input)
	if err != nil {
		return protocol.CoverCapsule1Plain{}, nil, err
	}
	return padBootstrapBody(random, cloned, minBodySize, maxBodySize, false,
		func(value *protocol.CoverCapsule1Plain, padding []byte) { value.Padding = padding },
		func(value protocol.CoverCapsule1Plain) []byte { return value.Padding },
		finalize,
	)
}

func padCoverCapsule2(random io.Reader, input protocol.CoverCapsule2Plain, minBodySize, maxBodySize uint64, finalize capsule2Finalizer) (protocol.CoverCapsule2Plain, []byte, error) {
	if finalize == nil {
		return protocol.CoverCapsule2Plain{}, nil, fmt.Errorf("handshake: missing Capsule2 finalizer")
	}
	cloned, err := cloneCoverCapsule2(input)
	if err != nil {
		return protocol.CoverCapsule2Plain{}, nil, err
	}
	return padBootstrapBody(random, cloned, minBodySize, maxBodySize, false,
		func(value *protocol.CoverCapsule2Plain, padding []byte) { value.Padding = padding },
		func(value protocol.CoverCapsule2Plain) []byte { return value.Padding },
		finalize,
	)
}

func padBootstrapBody[T any](
	random io.Reader,
	input T,
	minBodySize, maxBodySize uint64,
	useSignatureGuard bool,
	setPadding func(*T, []byte),
	getPadding func(T) []byte,
	finalize func(T) (T, []byte, error),
) (T, []byte, error) {
	var zero T
	if minBodySize > maxBodySize {
		return zero, nil, fmt.Errorf("handshake: bootstrap envelope minimum exceeds maximum")
	}
	if maxBodySize > maxBootstrapRecordBodyBytes {
		return zero, nil, fmt.Errorf("handshake: bootstrap envelope exceeds record limit")
	}
	if isNilDependency(random) {
		return zero, nil, fmt.Errorf("handshake: missing padding entropy")
	}

	value := input
	padding := make([]byte, 0)
	setPadding(&value, padding)
	previousBodySize := -1
	for attempt := 0; attempt < maxPaddingAttempts; attempt++ {
		finalized, body, err := finalize(value)
		if err != nil {
			zeroBindingBytes(padding)
			zeroBindingBytes(body)
			return zero, nil, fmt.Errorf("handshake: finalize bootstrap body: %w", err)
		}
		bodySize := uint64(len(body))
		if previousBodySize >= 0 && len(body) <= previousBodySize {
			zeroBindingBytes(padding)
			zeroBindingBytes(body)
			return zero, nil, fmt.Errorf("handshake: bootstrap padding did not increase body size")
		}
		if bodySize > maxBodySize {
			zeroBindingBytes(padding)
			zeroBindingBytes(body)
			return zero, nil, fmt.Errorf("handshake: finalized bootstrap body exceeds envelope")
		}
		if bodySize >= minBodySize {
			if !bytes.Equal(getPadding(finalized), padding) {
				zeroBindingBytes(padding)
				zeroBindingBytes(body)
				return zero, nil, fmt.Errorf("handshake: bootstrap finalizer changed padding")
			}
			ownedBody := append([]byte(nil), body...)
			zeroBindingBytes(body)
			return finalized, ownedBody, nil
		}

		additional := minBodySize - bodySize
		if useSignatureGuard && attempt == 0 {
			headroom := maxBodySize - minBodySize
			if headroom > preludeSignatureSizeGuard {
				headroom = preludeSignatureSizeGuard
			}
			additional += headroom
		}
		if additional > 0xffff-uint64(len(padding)) {
			zeroBindingBytes(padding)
			zeroBindingBytes(body)
			return zero, nil, fmt.Errorf("handshake: required bootstrap padding exceeds opaque16")
		}
		addition := make([]byte, int(additional))
		if _, err := io.ReadFull(random, addition); err != nil {
			zeroBindingBytes(addition)
			zeroBindingBytes(padding)
			zeroBindingBytes(body)
			return zero, nil, fmt.Errorf("handshake: read bootstrap padding entropy: %w", err)
		}
		padding = append(padding, addition...)
		zeroBindingBytes(addition)
		setPadding(&value, padding)
		previousBodySize = len(body)
		zeroBindingBytes(body)
	}

	zeroBindingBytes(padding)
	return zero, nil, fmt.Errorf("handshake: bootstrap padding did not converge")
}

func cloneCoverPrelude0(input protocol.CoverPrelude0) (protocol.CoverPrelude0, error) {
	encoded, err := protocol.Encode(input)
	if err != nil {
		return protocol.CoverPrelude0{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverPrelude0(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.CoverPrelude0{}, fmt.Errorf("handshake: cannot clone CoverPrelude0")
	}
	return out, nil
}

func cloneCoverPrelude1(input protocol.CoverPrelude1) (protocol.CoverPrelude1, error) {
	encoded, err := protocol.Encode(input)
	if err != nil {
		return protocol.CoverPrelude1{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverPrelude1(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.CoverPrelude1{}, fmt.Errorf("handshake: cannot clone CoverPrelude1")
	}
	return out, nil
}

func cloneCoverCapsule1(input protocol.CoverCapsule1Plain) (protocol.CoverCapsule1Plain, error) {
	encoded, err := protocol.Encode(input)
	if err != nil {
		return protocol.CoverCapsule1Plain{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverCapsule1Plain(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.CoverCapsule1Plain{}, fmt.Errorf("handshake: cannot clone CoverCapsule1")
	}
	return out, nil
}

func cloneCoverCapsule2(input protocol.CoverCapsule2Plain) (protocol.CoverCapsule2Plain, error) {
	encoded, err := protocol.Encode(input)
	if err != nil {
		return protocol.CoverCapsule2Plain{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverCapsule2Plain(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.CoverCapsule2Plain{}, fmt.Errorf("handshake: cannot clone CoverCapsule2")
	}
	return out, nil
}
