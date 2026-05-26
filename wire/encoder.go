package wire

import "fmt"

type Encodable interface {
	EncodeTo(*Encoder)
}

type Encoder struct {
	buf []byte
	err error
}

func NewEncoder() *Encoder {
	return &Encoder{}
}

func Encode(v Encodable) ([]byte, error) {
	e := NewEncoder()
	v.EncodeTo(e)
	return e.Bytes()
}

func (e *Encoder) Bytes() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	out := make([]byte, len(e.buf))
	copy(out, e.buf)
	return out, nil
}

func (e *Encoder) Err() error {
	return e.err
}

func (e *Encoder) SetErr(err error) {
	if e.err == nil && err != nil {
		e.err = err
	}
}

func (e *Encoder) WriteBytes(b []byte) {
	if e.err != nil {
		return
	}
	e.buf = append(e.buf, b...)
}

func (e *Encoder) WriteUint8(v uint8) {
	e.WriteBytes([]byte{v})
}

func (e *Encoder) WriteBool(v bool) {
	if v {
		e.WriteUint8(1)
		return
	}
	e.WriteUint8(0)
}

func (e *Encoder) WriteUint16(v uint16) {
	e.WriteBytes([]byte{byte(v >> 8), byte(v)})
}

func (e *Encoder) WriteUint24(v uint32) {
	if v > 0xffffff {
		e.SetErr(fmt.Errorf("wire: uint24 out of range: %d", v))
		return
	}
	e.WriteBytes([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
}

func (e *Encoder) WriteUint32(v uint32) {
	e.WriteBytes([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (e *Encoder) WriteUint64(v uint64) {
	e.WriteBytes([]byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	})
}

func (e *Encoder) WriteVarint(v uint64) {
	b, err := EncodeVarint(v)
	if err != nil {
		e.SetErr(err)
		return
	}
	e.WriteBytes(b)
}

func (e *Encoder) WriteOpaqueFixed(b []byte, n int) {
	if len(b) != n {
		e.SetErr(fmt.Errorf("wire: fixed opaque length %d, want %d", len(b), n))
		return
	}
	e.WriteBytes(b)
}

func (e *Encoder) WriteOpaque8(b []byte) {
	if len(b) > 0xff {
		e.SetErr(fmt.Errorf("wire: opaque8 too long: %d", len(b)))
		return
	}
	e.WriteUint8(uint8(len(b)))
	e.WriteBytes(b)
}

func (e *Encoder) WriteOpaque16(b []byte) {
	if len(b) > 0xffff {
		e.SetErr(fmt.Errorf("wire: opaque16 too long: %d", len(b)))
		return
	}
	e.WriteUint16(uint16(len(b)))
	e.WriteBytes(b)
}

func (e *Encoder) WriteOpaque24(b []byte) {
	if len(b) > 0xffffff {
		e.SetErr(fmt.Errorf("wire: opaque24 too long: %d", len(b)))
		return
	}
	e.WriteUint24(uint32(len(b)))
	e.WriteBytes(b)
}

func (e *Encoder) WriteOpaque32(b []byte) {
	e.WriteUint32(uint32(len(b)))
	e.WriteBytes(b)
}

func (e *Encoder) WritePreHash(b []byte) {
	e.WriteOpaqueFixed(b, 48)
}

func (e *Encoder) WriteVarintVector(items []uint64) {
	e.WriteVarint(uint64(len(items)))
	for _, item := range items {
		e.WriteVarint(item)
	}
}

func EncodeUint64(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}
