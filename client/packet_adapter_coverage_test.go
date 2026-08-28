package client

// Adversarial coverage for the pure (no-receiver) parsers, builders, and checksums in
// client/packet_adapter.go. The existing packet_adapter_test.go suite drives a live
// PacketAdapter end-to-end (opening flows, reassembling fragments through the
// receiver methods), which is why the stateful fragment-reassembly methods are already
// ~80% covered while the package-level parsers that feed them stay largely uncovered.
// This file calls those parsers directly with crafted byte slices, perturbing exactly
// one field per case so the branch under test is the one that fires.
//
// The builders (buildPacketAdapterIPPacket / buildPacketAdapterTCPPacket /
// buildPacketAdapterUDPPacket) compute correct IPv4 header and transport checksums, so
// they double as oracle fixtures: a builder output round-trips through the matching
// parser (happy path), and a single-field mutation of a builder output (with the IPv4
// header checksum left intact or deliberately broken as the case requires) reaches the
// targeted error branch. covIPv4Packet builds an IPv4 packet from scratch with a correct
// checksum, giving full control over the fragment flags/offset/TTL without recomputation.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). Each rejection asserts exactly one error so the failure is
// attributable to the perturbed field alone. New helpers are each referenced by >=2
// tests so there is no U1000 (staticcheck U1000 flags unused package-level helpers and
// is a required CI check).
//
// Uncovered blocks (measured count 0 before this file):
//   - normalizePacketAdapterOptions (1053): the zero-value default fallbacks (1056/1063/
//     1070) and the four invalid-value rejections (1058/1065/1072/1079).
//   - parsePacketAdapterIPPacket (1085): unsupported IP version 1094.
//   - parsePacketAdapterIPv4 (1099): header malformed 1100, packet malformed 1105,
//     fragments unsupported 1109.
//   - parsePacketAdapterIPv4Fragment (1124): header malformed 1128, packet malformed
//     1133, reserved flag 1137, Don't-Fragment conflict 1142, fragment malformed 1149.
//   - parsePacketAdapterIPv6Fragment (1279): malformed 1283, chain-too-long before
//     fragment 1304, fragment-field parse error 1308, duplicate destination after
//     fragment 1314.
//   - parsePacketAdapterIPv6 (1468): malformed 1469.
//   - parsePacketAdapterIPv6Headers (1488): hop-by-hop not first 1498, duplicate
//     destination 1502, duplicate fragment 1507, unsupported extension 1512, chain too
//     long 1514, sub-parse error 1523.
//   - parsePacketAdapterIPv6FragmentHeader (1529): field parse error 1531, fragmented
//     1534.
//   - parsePacketAdapterIPv6FragmentFields (1540): malformed 1541, reserved bits 1545.
//   - parsePacketAdapterIPv6OptionsHeader (1551): malformed 1552, length overflow 1556,
//     option parse error 1559.
//   - parsePacketAdapterTransport (1582): TCP header invalid 1589, UDP segment
//     malformed 1602, UDP checksum invalid 1606, unsupported protocol 1615.
//   - buildPacketAdapterUDPPacket (1634): payload too large 1635, zero-checksum -> 0xffff
//     1644.
//   - buildPacketAdapterIPPacket (1651): invalid addresses 1652, IPv4 too large 1657,
//     IPv6 too large 1675, invalid version 1689.
//   - tcpSequenceBefore (1738): the false return (0% before).
//
// Dead-by-design (documented, not covered):
//   - parsePacketAdapterIPv4 1118, parsePacketAdapterIPv4Fragment 1163,
//     parsePacketAdapterIPv6 1482, parsePacketAdapterIPv6Fragment 1339 — the "address is
//     invalid" branches. Each builds the address with netip.AddrFrom4([4]byte(...)) /
//     netip.AddrFrom16([16]byte(...)) from a fixed-size array slice whose length is
//     already guaranteed by an earlier size check. AddrFrom4/AddrFrom16 always return a
//     valid (non-zero) Addr for any fixed-size input (verified: even all-zero bytes
//     report IsValid()==true), so the IsValid() guards can never fire.
//   - parsePacketAdapterIPv6Fragment 1347 — the chain-too-long check at the bottom of
//     the extension-header loop. The only switch cases that fall through to it are
//     hop-by-hop (which errors at 1295 when headerCount!=0) and destination (which
//     errors at 1299 once seenDestination is set). At headerCount>=2 both have already
//     errored, so the headerCount>=maximumPacketAdapterIPv6Options check is unreachable.
//
// Out of scope (already partially covered by the end-to-end suite; need live PacketAdapter
// fragment-table state, not pure parsers):
//   - ingressIPv4FragmentLocked / ingressIPv6FragmentLocked remaining error paths,
//     expireIPv4FragmentsLocked. These receiver methods are exercised by the existing
//     reassembly/overflow/limit tests; their residual count-0 branches require driving a
//   PacketAdapter through crafted fragment sequences and are left to a follow-up.
//
// No context.Context, no deprecated APIs.

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/transport"
)

// covIPv4Src/Dst and covIPv6Src/Dst feed the builders and checksum oracles. Each is
// referenced by many tests, so none are U1000.
var (
	covIPv4Src = netip.MustParseAddr("10.0.0.1")
	covIPv4Dst = netip.MustParseAddr("10.0.0.2")
	covIPv6Src = netip.MustParseAddr("fd00::1")
	covIPv6Dst = netip.MustParseAddr("fd00::2")
)

// covValidIPv4TCP returns a complete, checksum-correct IPv4+TCP packet. It is the oracle
// for the parsePacketAdapterIPv4 / parsePacketAdapterIPPacket happy paths and the base
// for single-field mutations. Referenced by >=4 tests, so not U1000.
func covValidIPv4TCP() []byte {
	pkt, err := buildPacketAdapterTCPPacket(4, covIPv4Src, covIPv4Dst, 1234, 80, 1, 0, 0x02, []byte("hi"), 1)
	if err != nil {
		panic(err)
	}
	return pkt
}

// covValidIPv6TCP returns a complete, checksum-correct IPv6+TCP packet — the oracle for
// the parsePacketAdapterIPv6 happy path. Referenced by >=2 tests, so not U1000.
func covValidIPv6TCP() []byte {
	pkt, err := buildPacketAdapterTCPPacket(6, covIPv6Src, covIPv6Dst, 1234, 80, 1, 0, 0x02, []byte("hi"), 1)
	if err != nil {
		panic(err)
	}
	return pkt
}

// covValidIPv6UDP returns a complete, checksum-correct IPv6+UDP packet — the oracle for
// the buildPacketAdapterUDPPacket zero-checksum path (payload small enough that the
// computed checksum is non-zero, exercising the normal branch) and the UDP happy path.
// Referenced by >=2 tests, so not U1000.
func covValidIPv6UDP() []byte {
	pkt, err := buildPacketAdapterUDPPacket(6, covIPv6Src, covIPv6Dst, 1234, 80, []byte("hello"), 1)
	if err != nil {
		panic(err)
	}
	return pkt
}

// covIPv4Packet builds an IPv4 packet from scratch with IHL=5, a correct header
// checksum, and full control over the protocol, TTL, fragment flags/offset, and payload.
// It gives the fragment-flag and TTL-mutation cases a valid-checksum baseline without
// recomputation. Referenced by >=4 tests, so not U1000.
func covIPv4Packet(protocol, ttl, flagsHi, flagsLo byte, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	pkt[6] = flagsHi
	pkt[7] = flagsLo
	pkt[8] = ttl
	pkt[9] = protocol
	src4 := covIPv4Src.As4()
	dst4 := covIPv4Dst.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	copy(pkt[20:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], packetAdapterChecksum(pkt[:20]))
	return pkt
}

// covTCPSegment builds a TCP segment with a correct transport checksum for the IPv4
// oracle addrs, giving full control over the source/destination ports. Referenced by
// >=2 tests, so not U1000.
func covTCPSegment(srcPort, dstPort uint16, flags uint8, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	seg[12] = 5 << 4
	seg[13] = flags
	copy(seg[20:], payload)
	binary.BigEndian.PutUint16(seg[16:18], packetAdapterTransportChecksum(4, covIPv4Src, covIPv4Dst, packetAdapterTCP, seg))
	return seg
}

// covUDPSegment builds a UDP segment whose length field matches its byte length, with
// the checksum set explicitly. It gives the UDP checksum-valid/invalid cases full control
// without recomputation. Referenced by >=4 tests, so not U1000.
func covUDPSegment(version uint8, srcPort, dstPort uint16, payload []byte, checksum uint16) []byte {
	seg := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(seg[:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
	copy(seg[8:], payload)
	binary.BigEndian.PutUint16(seg[6:8], checksum)
	return seg
}

// covValidUDPChecksum returns the correct transport checksum for a UDP segment over the
// cov addrs, mapping a zero result to 0xffff (the UDP "no zero checksum" rule). Used by
// the UDP happy and checksum-corrupt cases. Referenced by >=2 tests, so not U1000.
func covValidUDPChecksum(version uint8, seg []byte) uint16 {
	var src, dst netip.Addr
	if version == 4 {
		src, dst = covIPv4Src, covIPv4Dst
	} else {
		src, dst = covIPv6Src, covIPv6Dst
	}
	csum := packetAdapterTransportChecksum(version, src, dst, packetAdapterUDP, seg)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

// covIPv6Packet builds an IPv6 base header (hop limit 64) followed by the given
// extension-header bytes and payload, with payload length = len(extensions)+len(payload).
// It is the oracle for the parsePacketAdapterIPv6 / parsePacketAdapterIPv6Fragment happy
// and error paths. Referenced by >=4 tests, so not U1000.
func covIPv6Packet(baseNextHeader byte, extensions, payload []byte) []byte {
	pkt := make([]byte, 40+len(extensions)+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(extensions)+len(payload)))
	pkt[6] = baseNextHeader
	pkt[7] = 64
	src16 := covIPv6Src.As16()
	dst16 := covIPv6Dst.As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])
	copy(pkt[40:], extensions)
	copy(pkt[40+len(extensions):], payload)
	return pkt
}

// covIPv6ExtOptions builds an IPv6 hop-by-hop/destination options extension header of
// length (lengthUnits+1)*8 with the given next-header and options bytes. An empty
// options slice yields valid Pad1 padding. Referenced by >=2 tests, so not U1000.
func covIPv6ExtOptions(nextHeader, lengthUnits byte, options []byte) []byte {
	length := (int(lengthUnits) + 1) * 8
	hdr := make([]byte, length)
	hdr[0] = nextHeader
	hdr[1] = lengthUnits
	copy(hdr[2:], options)
	return hdr
}

// covIPv6Base returns a 40-byte IPv6 base header with hop limit 64 and the given
// next-header, carrying the covIPv6 source/destination. It is the fixed prefix for the
// direct calls to the IPv6 extension-header parsers (parsePacketAdapterIPv6FragmentHeader,
// parsePacketAdapterIPv6FragmentFields, parsePacketAdapterIPv6OptionsHeader), which index
// from a >=40 offset. Referenced by >=2 tests, so not U1000.
func covIPv6Base(nextHeader byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	b[6] = nextHeader
	b[7] = 64
	src16 := covIPv6Src.As16()
	dst16 := covIPv6Dst.As16()
	copy(b[8:24], src16[:])
	copy(b[24:40], dst16[:])
	return b
}

// covIPv6FragmentHeader builds an 8-byte IPv6 fragment header. offsetBytes is the byte
// offset (must be a multiple of 8); it is stored directly in the wire field, which the
// parser reads back as int(flags & 0xfff8). Referenced by >=2 tests, so not U1000.
func covIPv6FragmentHeader(nextHeader byte, offsetBytes int, more bool, id uint32) []byte {
	hdr := make([]byte, 8)
	hdr[0] = nextHeader
	hdr[1] = 0
	flags := uint16(offsetBytes)
	if more {
		flags |= 0x0001
	}
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint32(hdr[4:8], id)
	return hdr
}

func TestNormalizePacketAdapterOptionsDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		opts    PacketAdapterOptions
		wantSub string // non-empty => assert err contains this; empty => assert nil
	}{
		// 1056/1063/1070/1077 default fallbacks + happy return: all-zero options.
		{"defaults accepted", PacketAdapterOptions{}, ""},
		// 1058: flow limit above the maximum.
		{"flow limit too large", PacketAdapterOptions{MaxFlows: maximumPacketAdapterFlows + 1}, "flow limit is invalid"},
		// 1065: packet limit below the minimum.
		{"packet limit too small", PacketAdapterOptions{MaxPacketBytes: 1}, "packet limit is invalid"},
		// 1072: local packet limit above the maximum.
		{"local packet limit too large", PacketAdapterOptions{MaxLocalPackets: maximumPacketAdapterLocalPackets + 1}, "local packet limit is invalid"},
		// 1079: UDP mode neither fallback nor native (0 is normalized to fallback, so
		// pick a distinct uint8 value the validator does not recognize).
		{"udp mode invalid", PacketAdapterOptions{UDPMode: transport.UDPMode(5)}, "UDP mode is invalid"},
		// Explicit valid values (no defaults taken).
		{"explicit valid options", PacketAdapterOptions{MaxFlows: 10, MaxPacketBytes: 1000, MaxLocalPackets: 10, UDPMode: transport.UDPNativeDatagram}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := normalizePacketAdapterOptions(tc.opts)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestParsePacketAdapterIPPacketDecidesPerCondition(t *testing.T) {
	const max = 65535
	// 1086: size invalid (empty).
	if _, err := parsePacketAdapterIPPacket(nil, max); err == nil ||
		!strings.Contains(err.Error(), "IP packet size is invalid") {
		t.Fatalf("empty: err = %v, want IP packet size is invalid", err)
	}
	// 1086: size invalid (too large).
	if _, err := parsePacketAdapterIPPacket(make([]byte, max+1), max); err == nil ||
		!strings.Contains(err.Error(), "IP packet size is invalid") {
		t.Fatalf("oversize: err = %v, want IP packet size is invalid", err)
	}
	// 1094: unsupported IP version (version 1).
	if _, err := parsePacketAdapterIPPacket([]byte{0x10}, max); err == nil ||
		!strings.Contains(err.Error(), "IP version is unsupported") {
		t.Fatalf("version 1: err = %v, want IP version is unsupported", err)
	}
	// IPv4 happy path.
	if _, err := parsePacketAdapterIPPacket(covValidIPv4TCP(), max); err != nil {
		t.Fatalf("IPv4 happy: unexpected error %v", err)
	}
	// IPv6 happy path.
	if _, err := parsePacketAdapterIPPacket(covValidIPv6TCP(), max); err != nil {
		t.Fatalf("IPv6 happy: unexpected error %v", err)
	}
}

func TestParsePacketAdapterIPv4DecidesPerCondition(t *testing.T) {
	// 1100: header malformed — too short.
	short := make([]byte, 19)
	short[0] = 0x45
	if _, err := parsePacketAdapterIPv4(short); err == nil ||
		!strings.Contains(err.Error(), "IPv4 header is malformed") {
		t.Fatalf("short: err = %v, want IPv4 header is malformed", err)
	}
	// 1100: header malformed — IHL < 5.
	ihlBad := make([]byte, 20)
	ihlBad[0] = 0x40 // IHL = 4
	if _, err := parsePacketAdapterIPv4(ihlBad); err == nil ||
		!strings.Contains(err.Error(), "IPv4 header is malformed") {
		t.Fatalf("IHL<5: err = %v, want IPv4 header is malformed", err)
	}
	// 1105: packet malformed — corrupted header checksum (other fields still consistent).
	badChecksum := append([]byte(nil), covValidIPv4TCP()...)
	badChecksum[10] ^= 0xff
	if _, err := parsePacketAdapterIPv4(badChecksum); err == nil ||
		!strings.Contains(err.Error(), "IPv4 packet is malformed") {
		t.Fatalf("bad checksum: err = %v, want IPv4 packet is malformed", err)
	}
	// 1105: packet malformed — total length disagrees with buffer length.
	badTotal := append([]byte(nil), covValidIPv4TCP()...)
	badTotal[2] ^= 0xff
	if _, err := parsePacketAdapterIPv4(badTotal); err == nil ||
		!strings.Contains(err.Error(), "IPv4 packet is malformed") {
		t.Fatalf("bad total length: err = %v, want IPv4 packet is malformed", err)
	}
	// 1109: fragments unsupported — non-zero fragment offset (checksum valid).
	if _, err := parsePacketAdapterIPv4(covIPv4Packet(packetAdapterTCP, 64, 0x00, 0x08, []byte("payload"))); err == nil ||
		!strings.Contains(err.Error(), "IPv4 fragments are unsupported") {
		t.Fatalf("fragment offset: err = %v, want IPv4 fragments are unsupported", err)
	}
	// 1109: fragments unsupported — TTL of zero.
	if _, err := parsePacketAdapterIPv4(covIPv4Packet(packetAdapterTCP, 0, 0x40, 0x00, []byte("payload"))); err == nil ||
		!strings.Contains(err.Error(), "IPv4 fragments are unsupported") {
		t.Fatalf("ttl zero: err = %v, want IPv4 fragments are unsupported", err)
	}
	// Happy path.
	if _, err := parsePacketAdapterIPv4(covValidIPv4TCP()); err != nil {
		t.Fatalf("happy: unexpected error %v", err)
	}
}

func TestParsePacketAdapterIPv4FragmentDecidesPerCondition(t *testing.T) {
	const max = 65535

	// 1125: not IPv4 / empty -> (zero, false, nil), not an error.
	if _, ok, err := parsePacketAdapterIPv4Fragment(nil, max); err != nil || ok {
		t.Fatalf("empty: ok=%v err=%v, want false nil", ok, err)
	}
	if _, ok, err := parsePacketAdapterIPv4Fragment([]byte{0x60, 0}, max); err != nil || ok {
		t.Fatalf("v6: ok=%v err=%v, want false nil", ok, err)
	}

	// 1128: header malformed — too short.
	short := make([]byte, 19)
	short[0] = 0x45
	if _, _, err := parsePacketAdapterIPv4Fragment(short, max); err == nil ||
		!strings.Contains(err.Error(), "IPv4 header is malformed") {
		t.Fatalf("short: err = %v, want IPv4 header is malformed", err)
	}

	// 1133: packet malformed — corrupted header checksum.
	badChecksum := append([]byte(nil), covIPv4Packet(packetAdapterTCP, 64, 0x40, 0x00, []byte("payload"))...)
	badChecksum[10] ^= 0xff
	if _, _, err := parsePacketAdapterIPv4Fragment(badChecksum, max); err == nil ||
		!strings.Contains(err.Error(), "IPv4 packet is malformed") {
		t.Fatalf("bad checksum: err = %v, want IPv4 packet is malformed", err)
	}
	// 1133: packet malformed — TTL of zero.
	if _, _, err := parsePacketAdapterIPv4Fragment(covIPv4Packet(packetAdapterTCP, 0, 0x40, 0x00, []byte("payload")), max); err == nil ||
		!strings.Contains(err.Error(), "IPv4 packet is malformed") {
		t.Fatalf("ttl zero: err = %v, want IPv4 packet is malformed", err)
	}

	// 1137: reserved flag bit set (0x8000).
	reserved := covIPv4Packet(packetAdapterTCP, 64, 0x80, 0x00, []byte("payload"))
	if _, _, err := parsePacketAdapterIPv4Fragment(reserved, max); err == nil ||
		!strings.Contains(err.Error(), "IPv4 fragment flags are invalid") {
		t.Fatalf("reserved: err = %v, want IPv4 fragment flags are invalid", err)
	}
	// 1142: Don't-Fragment set together with a non-zero offset.
	dfConflict := covIPv4Packet(packetAdapterTCP, 64, 0x40, 0x08, []byte("payload"))
	if _, _, err := parsePacketAdapterIPv4Fragment(dfConflict, max); err == nil ||
		!strings.Contains(err.Error(), "Don't Fragment") {
		t.Fatalf("df conflict: err = %v, want Don't Fragment", err)
	}
	// 1145: complete packet (DF, offset 0, no MF) -> (zero, false, nil).
	if _, ok, err := parsePacketAdapterIPv4Fragment(covValidIPv4TCP(), max); err != nil || ok {
		t.Fatalf("complete: ok=%v err=%v, want false nil", ok, err)
	}
	// 1149: fragment malformed — More-Fragments set but payload not a multiple of 8.
	misaligned := covIPv4Packet(packetAdapterTCP, 64, 0x20, 0x00, []byte("12345"))
	if _, _, err := parsePacketAdapterIPv4Fragment(misaligned, max); err == nil ||
		!strings.Contains(err.Error(), "IPv4 fragment is malformed") {
		t.Fatalf("misaligned: err = %v, want IPv4 fragment is malformed", err)
	}
	// 1149: fragment malformed — empty payload with More-Fragments.
	emptyPayload := covIPv4Packet(packetAdapterTCP, 64, 0x20, 0x00, nil)
	if _, _, err := parsePacketAdapterIPv4Fragment(emptyPayload, max); err == nil ||
		!strings.Contains(err.Error(), "IPv4 fragment is malformed") {
		t.Fatalf("empty payload: err = %v, want IPv4 fragment is malformed", err)
	}
	// Happy fragment: MF set, offset 0, 8-byte aligned payload -> (fragment, true, nil).
	if _, ok, err := parsePacketAdapterIPv4Fragment(covIPv4Packet(packetAdapterTCP, 64, 0x20, 0x00, make([]byte, 8)), max); err != nil || !ok {
		t.Fatalf("happy fragment: ok=%v err=%v, want true nil", ok, err)
	}
}

func TestParsePacketAdapterIPv6DecidesPerCondition(t *testing.T) {
	// 1469: malformed — too short.
	short := make([]byte, 30)
	short[0] = 0x60
	if _, err := parsePacketAdapterIPv6(short); err == nil ||
		!strings.Contains(err.Error(), "IPv6 packet is malformed") {
		t.Fatalf("short: err = %v, want IPv6 packet is malformed", err)
	}
	// 1469: malformed — payload length disagrees with buffer length.
	badLen := covIPv6Packet(packetAdapterTCP, nil, []byte("payload"))
	badLen[4] ^= 0xff
	if _, err := parsePacketAdapterIPv6(badLen); err == nil ||
		!strings.Contains(err.Error(), "IPv6 packet is malformed") {
		t.Fatalf("bad payload length: err = %v, want IPv6 packet is malformed", err)
	}
	// 1469: malformed — hop limit of zero.
	hopZero := covIPv6Packet(packetAdapterTCP, nil, nil)
	hopZero[7] = 0
	if _, err := parsePacketAdapterIPv6(hopZero); err == nil ||
		!strings.Contains(err.Error(), "IPv6 packet is malformed") {
		t.Fatalf("hop zero: err = %v, want IPv6 packet is malformed", err)
	}
	// Happy path.
	if _, err := parsePacketAdapterIPv6(covValidIPv6TCP()); err != nil {
		t.Fatalf("happy: unexpected error %v", err)
	}
}

func TestParsePacketAdapterIPv6HeadersDecidesPerCondition(t *testing.T) {
	// 1498: hop-by-hop not first (destination -> hop-by-hop).
	destThenHop := covIPv6Packet(60, /*destination*/
		bytes.Join([][]byte{covIPv6ExtOptions(0 /*hop-by-hop*/, 0, nil)}, nil), nil)
	if _, err := parsePacketAdapterIPv6(destThenHop); err == nil ||
		!strings.Contains(err.Error(), "hop-by-hop header position is invalid") {
		t.Fatalf("hop not first: err = %v, want hop-by-hop header position is invalid", err)
	}
	// 1502: duplicate destination options.
	dupDest := covIPv6Packet(60,
		bytes.Join([][]byte{covIPv6ExtOptions(60, 0, nil), covIPv6ExtOptions(6, 0, nil)}, nil), nil)
	if _, err := parsePacketAdapterIPv6(dupDest); err == nil ||
		!strings.Contains(err.Error(), "destination options are duplicated") {
		t.Fatalf("dup destination: err = %v, want destination options are duplicated", err)
	}
	// 1507: duplicate fragment header.
	dupFrag := covIPv6Packet(44, /*fragment*/
		bytes.Join([][]byte{covIPv6FragmentHeader(44, 0, false, 0), covIPv6FragmentHeader(6, 0, false, 0)}, nil), nil)
	if _, err := parsePacketAdapterIPv6(dupFrag); err == nil ||
		!strings.Contains(err.Error(), "fragment header is duplicated") {
		t.Fatalf("dup fragment: err = %v, want fragment header is duplicated", err)
	}
	// 1512: unsupported extension header.
	unsupported := covIPv6Packet(99, nil, nil)
	if _, err := parsePacketAdapterIPv6(unsupported); err == nil ||
		!strings.Contains(err.Error(), "extension header is unsupported") {
		t.Fatalf("unsupported: err = %v, want extension header is unsupported", err)
	}
	// 1514: extension-header chain too long (hop-by-hop -> destination -> fragment).
	longChain := covIPv6Packet(0, /*hop-by-hop*/
		bytes.Join([][]byte{
			covIPv6ExtOptions(60, 0, nil),         // hop-by-hop -> destination
			covIPv6ExtOptions(44, 0, nil),         // destination -> fragment
			covIPv6FragmentHeader(6, 0, false, 0), // fragment -> TCP
		}, nil), nil)
	if _, err := parsePacketAdapterIPv6(longChain); err == nil ||
		!strings.Contains(err.Error(), "extension header chain is too long") {
		t.Fatalf("chain too long: err = %v, want extension header chain is too long", err)
	}
	// 1523: sub-parse error — truncated fragment header.
	truncatedFrag := covIPv6Packet(44, []byte{6, 0, 0, 0}, nil)
	if _, err := parsePacketAdapterIPv6(truncatedFrag); err == nil ||
		!strings.Contains(err.Error(), "fragment header is malformed") {
		t.Fatalf("truncated fragment: err = %v, want fragment header is malformed", err)
	}
}

func TestParsePacketAdapterIPv6FragmentHeaderDecidesPerCondition(t *testing.T) {
	// 1531: fragment-field parse error — truncated fragment header.
	truncated := append(covIPv6Base(44), []byte{6, 0, 0, 0}...)
	if _, _, err := parsePacketAdapterIPv6FragmentHeader(truncated, 40); err == nil ||
		!strings.Contains(err.Error(), "fragment header is malformed") {
		t.Fatalf("truncated: err = %v, want fragment header is malformed", err)
	}
	// 1534: fragmented (non-zero offset) is unsupported in the non-fragment parser path.
	fragmented := append(covIPv6Base(44), covIPv6FragmentHeader(6, 8, false, 1)...)
	if _, _, err := parsePacketAdapterIPv6FragmentHeader(fragmented, 40); err == nil ||
		!strings.Contains(err.Error(), "fragmented packets are unsupported") {
		t.Fatalf("fragmented: err = %v, want fragmented packets are unsupported", err)
	}
	// Happy atomic fragment (offset 0, !more) returns the next header and payload offset.
	atomic := append(covIPv6Base(44), covIPv6FragmentHeader(6, 0, false, 0)...)
	atomic = append(atomic, make([]byte, 8)...) // payload after the fragment header
	next, payloadOffset, err := parsePacketAdapterIPv6FragmentHeader(atomic, 40)
	if err != nil || next != 6 || payloadOffset != 48 {
		t.Fatalf("atomic: next=%d payloadOffset=%d err=%v, want 6 48 nil", next, payloadOffset, err)
	}
}

func TestParsePacketAdapterIPv6FragmentFieldsDecidesPerCondition(t *testing.T) {
	// 1541: malformed — offset+8 beyond the buffer.
	short := append(covIPv6Base(44), []byte{6, 0, 0, 0}...)
	if _, _, _, _, _, err := parsePacketAdapterIPv6FragmentFields(short, 40); err == nil ||
		!strings.Contains(err.Error(), "fragment header is malformed") {
		t.Fatalf("short: err = %v, want fragment header is malformed", err)
	}
	// 1541: malformed — next-header-length byte (offset+1) non-zero.
	badLen := make([]byte, 48)
	badLen[41] = 1
	if _, _, _, _, _, err := parsePacketAdapterIPv6FragmentFields(badLen, 40); err == nil ||
		!strings.Contains(err.Error(), "fragment header is malformed") {
		t.Fatalf("bad len: err = %v, want fragment header is malformed", err)
	}
	// 1545: reserved bits set in the flags field.
	reserved := append(covIPv6Base(44), covIPv6FragmentHeader(6, 0, false, 0)...)
	binary.BigEndian.PutUint16(reserved[42:44], 0x0006) // reserved bits
	if _, _, _, _, _, err := parsePacketAdapterIPv6FragmentFields(reserved, 40); err == nil ||
		!strings.Contains(err.Error(), "reserved bits are set") {
		t.Fatalf("reserved: err = %v, want reserved bits are set", err)
	}
	// Happy: atomic fragment fields.
	happy := append(covIPv6Base(44), covIPv6FragmentHeader(6, 0, false, 0)...)
	next, payloadOffset, fragmentOffset, more, id, err := parsePacketAdapterIPv6FragmentFields(happy, 40)
	if err != nil || next != 6 || payloadOffset != 48 || fragmentOffset != 0 || more || id != 0 {
		t.Fatalf("happy: next=%d payloadOffset=%d offset=%d more=%v id=%d err=%v", next, payloadOffset, fragmentOffset, more, id, err)
	}
}

func TestParsePacketAdapterIPv6OptionsHeaderDecidesPerCondition(t *testing.T) {
	// 1552: malformed — offset+2 beyond the buffer.
	short := make([]byte, 41)
	if _, _, err := parsePacketAdapterIPv6OptionsHeader(short, 40); err == nil ||
		!strings.Contains(err.Error(), "options header is malformed") {
		t.Fatalf("short: err = %v, want options header is malformed", err)
	}
	// 1556: declared length overflows the available bytes.
	overflow := make([]byte, 48)
	overflow[40] = 6  // next header
	overflow[41] = 10 // length = (10+1)*8 = 88 > 8 available
	if _, _, err := parsePacketAdapterIPv6OptionsHeader(overflow, 40); err == nil ||
		!strings.Contains(err.Error(), "options header is malformed") {
		t.Fatalf("overflow: err = %v, want options header is malformed", err)
	}
	// 1559: options body is malformed (option length exceeds the option bytes).
	badOption := append(covIPv6Base(60), covIPv6ExtOptions(6, 0, []byte{1, 99, 0, 0, 0, 0})...)
	if _, _, err := parsePacketAdapterIPv6OptionsHeader(badOption, 40); err == nil ||
		!strings.Contains(err.Error(), "IPv6 option is malformed") {
		t.Fatalf("bad option: err = %v, want IPv6 option is malformed", err)
	}
	// Happy: valid Pad1-padded options header.
	happy := append(covIPv6Base(60), covIPv6ExtOptions(6, 0, nil)...)
	next, offset, err := parsePacketAdapterIPv6OptionsHeader(happy, 40)
	if err != nil || next != 6 || offset != 48 {
		t.Fatalf("happy: next=%d offset=%d err=%v, want 6 48 nil", next, offset, err)
	}
}

func TestParsePacketAdapterIPv6FragmentDecidesPerCondition(t *testing.T) {
	const max = 65535

	// 1280: not IPv6 / empty -> (zero, false, nil).
	if _, ok, err := parsePacketAdapterIPv6Fragment(nil, max); err != nil || ok {
		t.Fatalf("empty: ok=%v err=%v, want false nil", ok, err)
	}
	// 1283: malformed — too short.
	short := make([]byte, 30)
	short[0] = 0x60
	if _, _, err := parsePacketAdapterIPv6Fragment(short, max); err == nil ||
		!strings.Contains(err.Error(), "IPv6 packet is malformed") {
		t.Fatalf("short: err = %v, want IPv6 packet is malformed", err)
	}
	// 1283: malformed — hop limit of zero.
	hopZero := covIPv6Packet(packetAdapterTCP, nil, nil)
	hopZero[7] = 0
	if _, _, err := parsePacketAdapterIPv6Fragment(hopZero, max); err == nil ||
		!strings.Contains(err.Error(), "IPv6 packet is malformed") {
		t.Fatalf("hop zero: err = %v, want IPv6 packet is malformed", err)
	}

	// 1304: chain too long before the fragment (hop-by-hop -> destination -> fragment).
	longChain := covIPv6Packet(0, /*hop-by-hop*/
		bytes.Join([][]byte{
			covIPv6ExtOptions(60, 0, nil),         // hop-by-hop -> destination
			covIPv6ExtOptions(44, 0, nil),         // destination -> fragment
			covIPv6FragmentHeader(6, 0, false, 0), // fragment -> TCP (header bytes unused)
		}, nil), nil)
	if _, _, err := parsePacketAdapterIPv6Fragment(longChain, max); err == nil ||
		!strings.Contains(err.Error(), "extension header chain is too long") {
		t.Fatalf("chain too long: err = %v, want extension header chain is too long", err)
	}
	// 1308: fragment-field parse error — truncated fragment header.
	truncatedFrag := covIPv6Packet(44, []byte{6, 0, 0, 0}, nil)
	if _, _, err := parsePacketAdapterIPv6Fragment(truncatedFrag, max); err == nil ||
		!strings.Contains(err.Error(), "fragment header is malformed") {
		t.Fatalf("truncated fragment: err = %v, want fragment header is malformed", err)
	}
	// 1314: duplicate destination after the fragment (destination -> fragment -> destination).
	destAfterFrag := covIPv6Packet(60, /*destination*/
		bytes.Join([][]byte{
			covIPv6ExtOptions(44, 0, nil),          // destination -> fragment
			covIPv6FragmentHeader(60, 0, false, 0), // fragment -> destination
		}, nil), []byte("payload"))
	if _, _, err := parsePacketAdapterIPv6Fragment(destAfterFrag, max); err == nil ||
		!strings.Contains(err.Error(), "destination options are duplicated") {
		t.Fatalf("dup dest after fragment: err = %v, want destination options are duplicated", err)
	}
	// 1317: atomic fragment (offset 0, !more) -> (zero, false, nil), not a fragment.
	atomic := covIPv6Packet(44, covIPv6FragmentHeader(6, 0, false, 0), []byte("payload"))
	if _, ok, err := parsePacketAdapterIPv6Fragment(atomic, max); err != nil || ok {
		t.Fatalf("atomic: ok=%v err=%v, want false nil", ok, err)
	}
	// Happy fragment: MF set, offset 0, 8-byte aligned payload -> (fragment, true, nil).
	happyFrag := covIPv6Packet(44, covIPv6FragmentHeader(6, 0, true, 1), make([]byte, 8))
	if _, ok, err := parsePacketAdapterIPv6Fragment(happyFrag, max); err != nil || !ok {
		t.Fatalf("happy fragment: ok=%v err=%v, want true nil", ok, err)
	}
}

func TestParsePacketAdapterTransportDecidesPerCondition(t *testing.T) {
	v4Packet := packetAdapterIPPacket{version: 4, protocol: packetAdapterTCP, source: covIPv4Src, target: covIPv4Dst}
	v4UDP := packetAdapterIPPacket{version: 4, protocol: packetAdapterUDP, source: covIPv4Src, target: covIPv4Dst}
	v6Packet := packetAdapterIPPacket{version: 6, protocol: packetAdapterUDP, source: covIPv6Src, target: covIPv6Dst}

	// TCP 1585: segment too short.
	if _, err := parsePacketAdapterTransport(v4Packet, []byte("short"), false); err == nil ||
		!strings.Contains(err.Error(), "TCP segment is malformed") {
		t.Fatalf("tcp short: err = %v, want TCP segment is malformed", err)
	}
	// TCP 1585: data-offset too large for the segment.
	bigOffset := covTCPSegment(1234, 80, 0x02, nil)
	bigOffset[12] = 6 << 4 // data offset 6 -> 24 bytes > 20
	if _, err := parsePacketAdapterTransport(v4Packet, bigOffset, false); err == nil ||
		!strings.Contains(err.Error(), "TCP segment is malformed") {
		t.Fatalf("tcp big offset: err = %v, want TCP segment is malformed", err)
	}
	// TCP 1585: corrupted transport checksum.
	badChecksum := covTCPSegment(1234, 80, 0x02, []byte("hi"))
	badChecksum[16] ^= 0xff
	if _, err := parsePacketAdapterTransport(v4Packet, badChecksum, false); err == nil ||
		!strings.Contains(err.Error(), "TCP segment is malformed") {
		t.Fatalf("tcp bad checksum: err = %v, want TCP segment is malformed", err)
	}
	// TCP 1589: zero source port (checksum recomputed over the mutated header).
	zeroSrcPort := covTCPSegment(0, 80, 0x02, nil)
	if _, err := parsePacketAdapterTransport(v4Packet, zeroSrcPort, false); err == nil ||
		!strings.Contains(err.Error(), "TCP header is invalid") {
		t.Fatalf("tcp zero src port: err = %v, want TCP header is invalid", err)
	}
	// TCP happy path.
	if _, err := parsePacketAdapterTransport(v4Packet, covTCPSegment(1234, 80, 0x02, []byte("hi")), false); err != nil {
		t.Fatalf("tcp happy: unexpected error %v", err)
	}

	// UDP 1602: segment too short.
	if _, err := parsePacketAdapterTransport(v4UDP, []byte("short"), false); err == nil ||
		!strings.Contains(err.Error(), "UDP segment is malformed") {
		t.Fatalf("udp short: err = %v, want UDP segment is malformed", err)
	}
	// UDP 1602: length field disagrees with the segment length.
	badLen := covUDPSegment(4, 1234, 80, []byte("hi"), 0)
	badLen[4] = 99
	if _, err := parsePacketAdapterTransport(v4UDP, badLen, false); err == nil ||
		!strings.Contains(err.Error(), "UDP segment is malformed") {
		t.Fatalf("udp bad length: err = %v, want UDP segment is malformed", err)
	}
	// UDP 1602: zero source port (length still consistent).
	zeroSrc := covUDPSegment(4, 0, 80, []byte("hi"), covValidUDPChecksum(4, covUDPSegment(4, 0, 80, []byte("hi"), 0)))
	if _, err := parsePacketAdapterTransport(v4UDP, zeroSrc, false); err == nil ||
		!strings.Contains(err.Error(), "UDP segment is malformed") {
		t.Fatalf("udp zero src port: err = %v, want UDP segment is malformed", err)
	}
	// UDP 1606: IPv6 requires a non-zero checksum; zero checksum is rejected.
	v6ZeroCsum := covUDPSegment(6, 1234, 80, []byte("hi"), 0)
	if _, err := parsePacketAdapterTransport(v6Packet, v6ZeroCsum, true); err == nil ||
		!strings.Contains(err.Error(), "UDP checksum is invalid") {
		t.Fatalf("udp v6 zero checksum: err = %v, want UDP checksum is invalid", err)
	}
	// UDP 1606: non-zero but incorrect checksum is rejected.
	corruptUDP := covUDPSegment(4, 1234, 80, []byte("hi"), covValidUDPChecksum(4, covUDPSegment(4, 1234, 80, []byte("hi"), 0)))
	corruptUDP[6] ^= 0xff
	if _, err := parsePacketAdapterTransport(v4UDP, corruptUDP, false); err == nil ||
		!strings.Contains(err.Error(), "UDP checksum is invalid") {
		t.Fatalf("udp corrupt checksum: err = %v, want UDP checksum is invalid", err)
	}
	// UDP happy path (IPv4, valid non-zero checksum).
	validUDP := covUDPSegment(4, 1234, 80, []byte("hi"), covValidUDPChecksum(4, covUDPSegment(4, 1234, 80, []byte("hi"), 0)))
	if _, err := parsePacketAdapterTransport(v4UDP, validUDP, false); err != nil {
		t.Fatalf("udp happy: unexpected error %v", err)
	}

	// 1615: unsupported transport protocol.
	other := packetAdapterIPPacket{version: 4, protocol: 99, source: covIPv4Src, target: covIPv4Dst}
	if _, err := parsePacketAdapterTransport(other, nil, false); err == nil ||
		!strings.Contains(err.Error(), "transport protocol is unsupported") {
		t.Fatalf("unsupported: err = %v, want transport protocol is unsupported", err)
	}
}

func TestBuildPacketAdapterUDPPacketDecidesPerCondition(t *testing.T) {
	// 1635: payload too large.
	if _, err := buildPacketAdapterUDPPacket(4, covIPv4Src, covIPv4Dst, 1234, 80, make([]byte, 65528), 1); err == nil ||
		!strings.Contains(err.Error(), "UDP payload is too large") {
		t.Fatalf("oversize: err = %v, want UDP payload is too large", err)
	}
	// 1644: a computed zero checksum maps to 0xffff. For fixed addresses, payload, and
	// target port there is exactly one source port whose ones-complement sum over the
	// pseudo-header + segment is 0xffff (so the checksum is 0); the builder must then
	// transmit 0xffff. Search for that source port (a local closure, so no package-level
	// helper) and confirm the emitted segment carries 0xffff rather than 0x0000.
	zeroChecksumSourcePort := func(version uint8, targetPort uint16, payload []byte) uint16 {
		src, dst := covIPv4Src, covIPv4Dst
		if version == 6 {
			src, dst = covIPv6Src, covIPv6Dst
		}
		for sp := uint16(0); ; sp++ {
			seg := make([]byte, 8+len(payload))
			binary.BigEndian.PutUint16(seg[:2], sp)
			binary.BigEndian.PutUint16(seg[2:4], targetPort)
			binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
			copy(seg[8:], payload)
			if packetAdapterTransportChecksum(version, src, dst, packetAdapterUDP, seg) == 0 {
				return sp
			}
			if sp == 0xffff {
				t.Fatalf("no source port produces a zero UDP checksum for %d-byte payload", len(payload))
			}
		}
	}
	zpkt, err := buildPacketAdapterUDPPacket(4, covIPv4Src, covIPv4Dst, zeroChecksumSourcePort(4, 80, []byte("payload")), 80, []byte("payload"), 1)
	if err != nil {
		t.Fatalf("zero-checksum build: unexpected error %v", err)
	}
	// IPv4 header is 20 bytes; the UDP checksum sits at segment offset 6, i.e. byte 26.
	got := binary.BigEndian.Uint16(zpkt[26:28])
	if got != 0xffff {
		t.Fatalf("zero-checksum segment checksum = 0x%04x, want 0xffff", got)
	}
	// The normal (non-zero) path is exercised by the IPv6 builder below; confirm it
	// succeeds and round-trips through the IPv6 parser.
	if _, err := buildPacketAdapterUDPPacket(6, covIPv6Src, covIPv6Dst, 1234, 80, []byte("hello"), 1); err != nil {
		t.Fatalf("v6 udp build: unexpected error %v", err)
	}
	// Sanity: the builder output round-trips through the IPv6 parser.
	if _, err := parsePacketAdapterIPv6(covValidIPv6UDP()); err != nil {
		t.Fatalf("v6 udp round-trip: unexpected error %v", err)
	}
}

func TestBuildPacketAdapterIPPacketDecidesPerCondition(t *testing.T) {
	// 1652: invalid addresses (mismatched families).
	if _, err := buildPacketAdapterIPPacket(4, covIPv4Src, covIPv6Dst, packetAdapterTCP, []byte("x"), 1); err == nil ||
		!strings.Contains(err.Error(), "IP addresses are invalid") {
		t.Fatalf("mismatched addrs: err = %v, want IP addresses are invalid", err)
	}
	// 1657: IPv4 payload too large.
	if _, err := buildPacketAdapterIPPacket(4, covIPv4Src, covIPv4Dst, packetAdapterTCP, make([]byte, 65516), 1); err == nil ||
		!strings.Contains(err.Error(), "IPv4 packet is too large") {
		t.Fatalf("v4 oversize: err = %v, want IPv4 packet is too large", err)
	}
	// 1675: IPv6 payload too large.
	if _, err := buildPacketAdapterIPPacket(6, covIPv6Src, covIPv6Dst, packetAdapterTCP, make([]byte, 65536), 1); err == nil ||
		!strings.Contains(err.Error(), "IPv6 packet is too large") {
		t.Fatalf("v6 oversize: err = %v, want IPv6 packet is too large", err)
	}
	// 1689: invalid IP version.
	if _, err := buildPacketAdapterIPPacket(5, covIPv4Src, covIPv4Dst, packetAdapterTCP, []byte("x"), 1); err == nil ||
		!strings.Contains(err.Error(), "IP version is invalid") {
		t.Fatalf("bad version: err = %v, want IP version is invalid", err)
	}
	// Happy paths for both versions.
	if _, err := buildPacketAdapterIPPacket(4, covIPv4Src, covIPv4Dst, packetAdapterTCP, []byte("x"), 1); err != nil {
		t.Fatalf("v4 happy: unexpected error %v", err)
	}
	if _, err := buildPacketAdapterIPPacket(6, covIPv6Src, covIPv6Dst, packetAdapterTCP, []byte("x"), 1); err != nil {
		t.Fatalf("v6 happy: unexpected error %v", err)
	}
}

func TestTCPSequenceBefore(t *testing.T) {
	// 1738: true (left before right in TCP sequence space).
	if !tcpSequenceBefore(10, 20) {
		t.Fatal("tcpSequenceBefore(10, 20) = false, want true")
	}
	// 1738: false (right at or before left).
	if tcpSequenceBefore(20, 10) {
		t.Fatal("tcpSequenceBefore(20, 10) = true, want false")
	}
	if tcpSequenceBefore(100, 100) {
		t.Fatal("tcpSequenceBefore(100, 100) = true, want false")
	}
	// Wrap-around: a large sequence is "before" a small one.
	if !tcpSequenceBefore(0xFFFFFFFF, 0) {
		t.Fatal("tcpSequenceBefore(0xFFFFFFFF, 0) = false, want true (wrap)")
	}
}
