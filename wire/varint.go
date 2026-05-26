package wire

import "fmt"

const MaxVarint = uint64(1<<62 - 1)

var ErrNonMinimalVarint = fmt.Errorf("wire: non-minimal varint")

func EncodeVarint(v uint64) ([]byte, error) {
	if v > MaxVarint {
		return nil, fmt.Errorf("wire: varint out of range: %d", v)
	}
	switch {
	case v <= 63:
		return []byte{byte(v)}, nil
	case v <= 16383:
		x := uint16(v) | 0x4000
		return []byte{byte(x >> 8), byte(x)}, nil
	case v <= 1073741823:
		x := uint32(v) | 0x80000000
		return []byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}, nil
	default:
		x := v | 0xc000000000000000
		return []byte{
			byte(x >> 56), byte(x >> 48), byte(x >> 40), byte(x >> 32),
			byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x),
		}, nil
	}
}

func VarintLen(v uint64) (int, error) {
	if v > MaxVarint {
		return 0, fmt.Errorf("wire: varint out of range: %d", v)
	}
	switch {
	case v <= 63:
		return 1, nil
	case v <= 16383:
		return 2, nil
	case v <= 1073741823:
		return 4, nil
	default:
		return 8, nil
	}
}

func DecodeVarint(b []byte) (value uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("wire: short varint")
	}
	prefix := b[0] >> 6
	switch prefix {
	case 0:
		return uint64(b[0]), 1, nil
	case 1:
		if len(b) < 2 {
			return 0, 0, fmt.Errorf("wire: short 2-byte varint")
		}
		v := uint64(b[0]&0x3f)<<8 | uint64(b[1])
		if v <= 63 {
			return 0, 0, ErrNonMinimalVarint
		}
		return v, 2, nil
	case 2:
		if len(b) < 4 {
			return 0, 0, fmt.Errorf("wire: short 4-byte varint")
		}
		v := uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		if v <= 16383 {
			return 0, 0, ErrNonMinimalVarint
		}
		return v, 4, nil
	default:
		if len(b) < 8 {
			return 0, 0, fmt.Errorf("wire: short 8-byte varint")
		}
		v := uint64(b[0]&0x3f)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
		if v <= 1073741823 {
			return 0, 0, ErrNonMinimalVarint
		}
		return v, 8, nil
	}
}
