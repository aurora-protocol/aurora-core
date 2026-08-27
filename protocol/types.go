package protocol

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/wire"
)

type Extension struct {
	ExtensionType uint64
	Critical      bool
	Body          []byte
}

const minimumEncodedExtensionBytes = 5 // varint type, bool, and opaque24 length

func (x Extension) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(x.ExtensionType)
	if x.Critical {
		e.WriteUint8(1)
	} else {
		e.WriteUint8(0)
	}
	e.WriteOpaque24(x.Body)
}

func EncodeExtensions(e *wire.Encoder, xs []Extension) {
	e.WriteVarint(uint64(len(xs)))
	for _, x := range xs {
		x.EncodeTo(e)
	}
}

func DecodeExtension(r *wire.Reader) Extension {
	return Extension{
		ExtensionType: r.ReadVarint(),
		Critical:      r.ReadBool(),
		Body:          r.ReadOpaque24(),
	}
}

func DecodeExtensions(r *wire.Reader) []Extension {
	n := r.ReadVectorCount("extension")
	if r.Err() != nil {
		return nil
	}
	if n > uint64(r.Remaining()/minimumEncodedExtensionBytes) {
		r.SetErr(fmt.Errorf("protocol: extension count %d cannot fit in %d remaining bytes", n, r.Remaining()))
		return nil
	}
	out := make([]Extension, 0, n)
	for i := uint64(0); i < n; i++ {
		out = append(out, DecodeExtension(r))
	}
	return out
}

func ValidateExtensions(xs []Extension, known map[uint64]bool) error {
	for _, x := range xs {
		if x.Critical && !known[x.ExtensionType] {
			return fmt.Errorf("protocol: unknown critical extension 0x%x", x.ExtensionType)
		}
	}
	return nil
}

func Encode(v wire.Encodable) ([]byte, error) {
	if block, ok := v.(FrameBlock); ok {
		if length, known := block.EncodedLen(); known {
			return wire.EncodeWithCapacity(block, length)
		}
	}
	return wire.Encode(v)
}
