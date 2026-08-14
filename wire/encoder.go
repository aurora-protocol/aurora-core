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
	return encode(v, -1, 0)
}

// EncodeWithCapacity uses capacity as a verified expected output length.
func EncodeWithCapacity(v Encodable, capacity int) ([]byte, error) {
	return encode(v, capacity, capacity)
}

// EncodeWithReservedCapacity retains capacity beyond the verified encoded length.
func EncodeWithReservedCapacity(v Encodable, expectedLength, capacity int) ([]byte, error) {
	if expectedLength < 0 || capacity < expectedLength {
		return Encode(v)
	}
	return encode(v, expectedLength, capacity)
}

func encode(v Encodable, expectedLength, capacity int) ([]byte, error) {
	e := NewEncoder()
	if expectedLength >= 0 {
		e.buf = make([]byte, 0, capacity)
	}
	v.EncodeTo(e)
	if e.err != nil {
		return nil, e.err
	}
	if expectedLength >= 0 && len(e.buf) == expectedLength {
		return e.buf, nil
	}
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
	if e.err != nil {
		return
	}
	e.buf = append(e.buf, v)
}

func (e *Encoder) WriteBool(v bool) {
	if v {
		e.WriteUint8(1)
		return
	}
	e.WriteUint8(0)
}

func (e *Encoder) WriteUint16(v uint16) {
	if e.err != nil {
		return
	}
	e.buf = append(e.buf, byte(v>>8), byte(v))
}

func (e *Encoder) WriteUint24(v uint32) {
	if e.err != nil {
		return
	}
	if v > 0xffffff {
		e.SetErr(fmt.Errorf("wire: uint24 out of range: %d", v))
		return
	}
	e.buf = append(e.buf, byte(v>>16), byte(v>>8), byte(v))
}

func (e *Encoder) WriteUint32(v uint32) {
	if e.err != nil {
		return
	}
	e.buf = append(e.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (e *Encoder) WriteUint64(v uint64) {
	if e.err != nil {
		return
	}
	e.buf = append(e.buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

func (e *Encoder) WriteVarint(v uint64) {
	if e.err != nil {
		return
	}
	buf, err := AppendVarint(e.buf, v)
	if err != nil {
		e.SetErr(err)
		return
	}
	e.buf = buf
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
