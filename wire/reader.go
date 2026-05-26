package wire

import "fmt"

type Reader struct {
	b   []byte
	off int
	err error
}

func NewReader(b []byte) *Reader {
	return &Reader{b: b}
}

func (r *Reader) Err() error {
	return r.err
}

func (r *Reader) Remaining() int {
	return len(r.b) - r.off
}

func (r *Reader) EOF() bool {
	return r.err == nil && r.off == len(r.b)
}

func (r *Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = fmt.Errorf("wire: short read")
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *Reader) ReadUint8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *Reader) ReadBool() bool {
	v := r.ReadUint8()
	if r.err != nil {
		return false
	}
	if v != 0 && v != 1 {
		r.err = fmt.Errorf("wire: malformed bool %d", v)
		return false
	}
	return v == 1
}

func (r *Reader) ReadUint16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

func (r *Reader) ReadUint24() uint32 {
	b := r.take(3)
	if b == nil {
		return 0
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func (r *Reader) ReadUint32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func (r *Reader) ReadUint64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func (r *Reader) ReadVarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n, err := DecodeVarint(r.b[r.off:])
	if err != nil {
		r.err = err
		return 0
	}
	r.off += n
	return v
}

func (r *Reader) ReadOpaqueFixed(n int) []byte {
	b := r.take(n)
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func (r *Reader) ReadOpaque8() []byte {
	n := int(r.ReadUint8())
	return r.ReadOpaqueFixed(n)
}

func (r *Reader) ReadOpaque16() []byte {
	n := int(r.ReadUint16())
	return r.ReadOpaqueFixed(n)
}

func (r *Reader) ReadOpaque24() []byte {
	n := int(r.ReadUint24())
	return r.ReadOpaqueFixed(n)
}

func (r *Reader) ReadPreHash() []byte {
	return r.ReadOpaqueFixed(48)
}

func (r *Reader) ReadVarintVector() []uint64 {
	n := r.ReadVarint()
	if r.err != nil {
		return nil
	}
	if n > uint64(r.Remaining()) {
		r.err = fmt.Errorf("wire: vector length %d exceeds remaining bytes", n)
		return nil
	}
	out := make([]uint64, 0, n)
	for i := uint64(0); i < n; i++ {
		out = append(out, r.ReadVarint())
	}
	return out
}
