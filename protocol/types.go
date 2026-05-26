package protocol

import "github.com/aurora-protocol/aurora-core/wire"

type Extension struct {
	ExtensionType uint64
	Critical      bool
	Body          []byte
}

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
	n := r.ReadVarint()
	if r.Err() != nil {
		return nil
	}
	out := make([]Extension, 0, n)
	for i := uint64(0); i < n; i++ {
		out = append(out, DecodeExtension(r))
	}
	return out
}

func Encode(v wire.Encodable) ([]byte, error) {
	return wire.Encode(v)
}
