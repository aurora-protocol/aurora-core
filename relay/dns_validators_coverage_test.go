package relay

// Adversarial coverage for the six pure free functions in relay/dns.go that
// the existing socket_egress_test.go / dns_upstream_test.go / dns_fuzz_test.go
// suites reach only on their happy paths (or not at all):
//   - parseSocketDNSQuestion (line 137, 81.6% before): the size-bounds, label-
//     loop-offset-past-end, invalid-label-character, empty-name, trailer-
//     truncated, qclass-not-IN, additional-record-skip-error, and trailing-
//     bytes rejection branches stay uncovered. The existing suites cover only
//     the happy path (fuzz seed corpus) and the flags / oversized-name rejects
//     (TestSocketEgressDNSMessageRejectsMalformedQuestionSections at 142-144
//     and TestSocketEgressDNSMessageRejectsOversizedEncodedName at 158-160).
//   - skipSocketDNSRecord (line 197, 58.3% before): the offset-past-end, label-
//     too-long, invalid-character, multi-label advance, header-too-short, and
//     rdata-overruns branches stay uncovered. The fuzz seed corpus only skips
//     a single root-named OPT record.
//   - validateSocketDNSResponse (line 232, 72.2% before): the size-bounds,
//     flags/transaction mismatch, question-wire mismatch, record-count overflow,
//     and trailing-bytes rejection branches stay uncovered.
//   - validateSocketDNSResponseRecord (line 260, 70.0% before): the name-skip /
//     header-too-short, rdata-overruns, A-record reject, and AAAA-record reject
//     branches stay uncovered. The SVCB egress test only reaches the SVCB/HTTPS
//     case (and the policy-denied IPv4 hint path inside it, 353-354).
//   - skipSocketDNSCompressedName (line 293, 76.2% before): the offset-past-end,
//     compressed-pointer error, reserved-label-byte (0x40/0x80), and label-past-
//     end branches stay uncovered. The SVCB egress test covers only the
//     pointer happy path (300-305) and the root-label return (312-313).
//   - validateSocketDNSServiceBindingHints (line 324, 62.5% before): every
//     structural reject (rdata-too-short, name-skip error, parameter-trailer
//     too short, parameter-length overruns), the IPv4-misaligned reject, the
//     IPv4 multi-address advance, the IPv6-misaligned reject, the IPv6 policy
//     deny, and the IPv6 multi-address advance stay uncovered. The SVCB egress
//     test covers only the single-IPv4-hint policy-deny path (352-354).
//
// All six functions are free (no *SocketEgress receiver) and read only their
// []byte / value-type arguments plus a value-type ExitPolicy, so each branch
// is isolated by crafting a minimal message. parseSocketDNSQuestion and
// validateSocketDNSResponse reuse the existing socketEgressDNSQuestion and
// buildSocketDNSResponse helpers as their valid base; validateSocketDNSResponse
// obtains its socketDNSQuestion via parseSocketDNSQuestion so the transactionID
// and wire fields are mutually consistent. Each perturbation mutates a single
// field so every earlier guard passes and the target branch is the one that
// fires. validateSocketDNSServiceBindingHints is called with message == rdata
// (so base == 0 and the root name at rdata[2] resolves cleanly).
//
// Dead-by-design branches (documented, not contrived):
//   - skipSocketDNSCompressedName:321 (loop-exhaustion return). The loop runs
//     `for labels := 0; labels <= 127; labels++` (128 iterations max) but the
//     name-length cap at 315 (`nameBytes+labelLength > 255`) fires first: every
//     non-root, non-pointer label contributes at least 2 nameBytes (1 length
//     byte + >=1 char), so 128 labels accumulate >=256 nameBytes and the 128th
//     label's bounds check (nameBytes+labelLength > 255) returns at 317 before
//     the counter can exhaust. A pointer or root returns earlier still. The
//     loop-exhaustion return at 321 is therefore unreachable.
//   - validateSocketDNSServiceBindingHints:331 `nameOffset < base ||
//     nameOffset > len(message)`. nameOffset starts at base+2 (> base) and only
//     increases; skipSocketDNSCompressedName, on its nil-return paths, advances
//     *offset by a pointer (2 bytes, guarded by *offset+2 <= len) or past a
//     root/label (guarded by *offset < len), so it always leaves *offset <=
//     len(message). Thus after a successful skip nameOffset is in [base+2, len]
//     and neither half can be true; only the `err != nil` half of the guard is
//     reachable (covered by the name-skip-error case).
//
// Coverage is re-measured per target to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one error so
// the failure is attributable to the perturbed input alone. No context.Context,
// no deprecated APIs.

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseSocketDNSQuestionRejectsEachMalformedQuery(t *testing.T) {
	valid := socketEgressDNSQuery(t, "example.com", socketDNSTypeA)

	// A name with no root terminator and no question trailer: after the single
	// label 'a' the loop top sees offset == len and returns at 149-151.
	noTerminator := append(socketDNSHeaderForCoverage(), 0x01, 'a')

	// A root-only name (just 0x00) with a full question trailer: the label loop
	// breaks immediately, labels is empty, and 171 rejects the empty name.
	rootOnly := append(socketDNSHeaderForCoverage(), 0x00, 0x00, 0x01, 0x00, 0x01)

	invalidChar := append([]byte(nil), valid...)
	invalidChar[13] = 0x7f // first char of "example" is now non-printable (>0x7e)

	trailerTruncated := append([]byte(nil), valid...)
	trailerTruncated = trailerTruncated[:len(trailerTruncated)-2] // drop qclass

	qclassNotIN := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(qclassNotIN[len(qclassNotIN)-2:], socketDNSClassIN+1)

	additionalSkipErr := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(additionalSkipErr[10:12], 1) // arcount = 1
	additionalSkipErr = append(additionalSkipErr, 0xc0)     // record name length 192 > 63

	trailingBytes := append([]byte(nil), valid...)
	trailingBytes = append(trailingBytes, 0xFF)

	cases := []struct {
		name    string
		query   []byte
		wantErr error
	}{
		{"message shorter than header", []byte{0x00, 0x00, 0x00}, ErrExitEventInvalid},
		{"label loop offset past end", noTerminator, ErrExitEventInvalid},
		{"invalid label character", invalidChar, ErrExitEventInvalid},
		{"empty root-only name", rootOnly, ErrExitEventInvalid},
		{"trailer truncated", trailerTruncated, ErrExitEventInvalid},
		{"qclass not IN", qclassNotIN, ErrExitEventInvalid},
		{"malformed additional record", additionalSkipErr, ErrExitEventInvalid},
		{"trailing bytes after question", trailingBytes, ErrExitEventInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSocketDNSQuestion(tc.query)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestParseSocketDNSQuestionAcceptsValidQuery(t *testing.T) {
	question, err := parseSocketDNSQuestion(socketEgressDNSQuery(t, "Example.COM", socketDNSTypeA))
	if err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
	if question.domain != "example.com" || question.queryType != socketDNSTypeA ||
		question.transactionID != 0x1234 || !question.recursion {
		t.Fatalf("parsed question = %+v, want example.com/A/0x1234/recursion", question)
	}
}

func TestSkipSocketDNSRecordRejectsEachMalformedRecord(t *testing.T) {
	cases := []struct {
		name    string
		message []byte
		offset  int
		wantErr error
	}{
		// 200-202: offset already at/past the message end at the loop top.
		{"offset past end", []byte{0x00}, 1, ErrExitEventInvalid},
		// 209-211: a label length byte > 63 (skipSocketDNSRecord does not handle
		// compression pointers, so 0x64 is a plain over-long label length).
		{"label length over 63", []byte{0x64}, 0, ErrExitEventInvalid},
		// 212-215: a valid-length label whose first byte is non-printable.
		{"invalid label character", []byte{0x01, 0x7f}, 0, ErrExitEventInvalid},
		// 220-222: root name consumed but fewer than 10 bytes remain for the
		// fixed type/class/ttl/rdlen header.
		{"header truncated", []byte{0x00, 0x00, 0x00, 0x00}, 0, ErrExitEventInvalid},
		// 225-227: a full 10-byte header whose rdlen claims more rdata than
		// remains. Record: root name + type A + class IN + ttl 0 + rdlen 0x0020.
		{"rdata overruns", []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x20}, 0, ErrExitEventInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offset := tc.offset
			err := skipSocketDNSRecord(tc.message, &offset)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestSkipSocketDNSRecordAcceptsMultiLabelRecord(t *testing.T) {
	// A record whose name has two labels ("a.b") exercises the per-label offset
	// advance at 217-218 (the single-label OPT record in the fuzz corpus breaks
	// at the root before advancing). Record: name "a.b" + type A + class IN +
	// ttl 0 + rdlen 4 + a 4-byte rdata.
	record := []byte{
		0x01, 'a', 0x01, 'b', 0x00, // name "a.b"
		0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x04, // type A, class IN, ttl 0, rdlen 4
		0x5B, 0x00, 0x21, 0x09, // rdata
	}
	offset := 0
	if err := skipSocketDNSRecord(record, &offset); err != nil {
		t.Fatalf("skipSocketDNSRecord(multi-label) failed: %v", err)
	}
	if offset != len(record) {
		t.Fatalf("offset = %d, want %d (full record consumed)", offset, len(record))
	}
}

func TestValidateSocketDNSResponseRejectsEachCondition(t *testing.T) {
	question, err := parseSocketDNSQuestion(socketEgressDNSQuery(t, "example.com", socketDNSTypeA))
	if err != nil {
		t.Fatalf("parse base question: %v", err)
	}
	base := buildSocketDNSResponse(question, socketDNSRCodeOK, nil, 60)

	txnMismatch := append([]byte(nil), base...)
	binary.BigEndian.PutUint16(txnMismatch[0:2], 0xFFFF)

	nameMismatch := append([]byte(nil), base...)
	nameMismatch[13] = 'X' // first char of "example" no longer matches the wire

	recordCountOverflow := append([]byte(nil), base...)
	binary.BigEndian.PutUint16(recordCountOverflow[6:8], maximumSocketDNSRecords+1)

	trailing := append([]byte(nil), base...)
	trailing = append(trailing, 0xFF)

	cases := []struct {
		name    string
		message []byte
		wantErr error
	}{
		{"message shorter than header", []byte{0x00, 0x00, 0x00}, ErrExitEventInvalid},
		{"transaction id mismatch", txnMismatch, ErrExitEventInvalid},
		{"question wire mismatch", nameMismatch, ErrExitEventInvalid},
		{"record count over maximum", recordCountOverflow, ErrExitEventInvalid},
		{"trailing bytes after records", trailing, ErrExitEventInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSocketDNSResponse(question, tc.message, ExitPolicy{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestValidateSocketDNSResponseAcceptsValidRoundTrip(t *testing.T) {
	question, err := parseSocketDNSQuestion(socketEgressDNSQuery(t, "example.com", socketDNSTypeA))
	if err != nil {
		t.Fatalf("parse base question: %v", err)
	}
	response := buildSocketDNSResponse(question, socketDNSRCodeOK, nil, 60)
	if err := validateSocketDNSResponse(question, response, ExitPolicy{}); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
}

func TestValidateSocketDNSResponseRecordDecidesPerTypeAndRdata(t *testing.T) {
	cloudflareV6 := []byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	// recordForCoverage builds a response record: root name + type + class IN +
	// ttl 0 + rdata. The root name keeps skipSocketDNSCompressedName trivial.
	recordForCoverage := func(recordType uint16, rdata []byte) []byte {
		rec := []byte{0x00}
		rec = binary.BigEndian.AppendUint16(rec, recordType)
		rec = binary.BigEndian.AppendUint16(rec, socketDNSClassIN)
		rec = binary.BigEndian.AppendUint32(rec, 0)
		rec = binary.BigEndian.AppendUint16(rec, uint16(len(rdata)))
		rec = append(rec, rdata...)
		return rec
	}

	cases := []struct {
		name    string
		message []byte
		wantErr error // nil = expect success
	}{
		// 261-263 (skipSocketDNSCompressedName error): a 0x40 name byte is a
		// reserved label length (0x40 & 0xc0 != 0, not a pointer) and is rejected.
		{"name skip error", []byte{0x40}, ErrExitEventInvalid},
		// 261-263 (offset+10 > len): root name consumed but the fixed header is
		// truncated (only 3 bytes follow the root).
		{"header truncated", []byte{0x00, 0x00, 0x00, 0x00}, ErrExitEventInvalid},
		// 268-270: rdlen (0x20) exceeds the remaining message after the header.
		{"rdata overruns", []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x20}, ErrExitEventInvalid},
		// 277-280: A record whose rdata is not 4 bytes.
		{"A record rdata too short", recordForCoverage(socketDNSTypeA, []byte{0xAA, 0xBB, 0xCC}), ErrExitPolicyDenied},
		// 277-280: A record with a loopback address (default policy denies it).
		{"A record loopback denied", recordForCoverage(socketDNSTypeA, []byte{127, 0, 0, 1}), ErrExitPolicyDenied},
		// A record with a public address is accepted (falls through the switch).
		{"A record public accepted", recordForCoverage(socketDNSTypeA, []byte{93, 184, 216, 34}), nil},
		// 281-284: AAAA record whose rdata is not 16 bytes.
		{"AAAA record rdata too short", recordForCoverage(socketDNSTypeAAAA, make([]byte, 15)), ErrExitPolicyDenied},
		// 281-284: AAAA record with a loopback address.
		{"AAAA record loopback denied", recordForCoverage(socketDNSTypeAAAA, append(make([]byte, 15), 0x01)), ErrExitPolicyDenied},
		// AAAA record with a public address is accepted.
		{"AAAA record public accepted", recordForCoverage(socketDNSTypeAAAA, cloudflareV6), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offset := 0
			err := validateSocketDNSResponseRecord(tc.message, &offset, ExitPolicy{})
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestSkipSocketDNSCompressedNameRejectsEachMalformedName(t *testing.T) {
	cases := []struct {
		name    string
		message []byte
		offset  int
		wantErr error
	}{
		// 296-298: offset already at the message end at the loop top.
		{"offset past end", []byte{0x00}, 1, ErrExitEventInvalid},
		// 301-303: a compression pointer with no second byte (offset+2 > len).
		{"compressed pointer truncated", []byte{0xc0}, 0, ErrExitEventInvalid},
		// 307-309: a reserved label length byte (0x40 & 0xc0 != 0, not 0xc0).
		{"reserved label byte", []byte{0x40}, 0, ErrExitEventInvalid},
		// 315-317: a normal label whose length runs past the message end.
		{"label runs past end", []byte{0x0a, 0x01, 0x02, 0x03}, 0, ErrExitEventInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offset := tc.offset
			err := skipSocketDNSCompressedName(tc.message, &offset)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestSkipSocketDNSCompressedNameAcceptsPointerAndRoot(t *testing.T) {
	t.Run("valid compression pointer", func(t *testing.T) {
		// A name "a" followed by a pointer to offset 0 (0 < current offset 2, so
		// the pointer is valid): skip returns nil and advances past the pointer.
		message := []byte{0x01, 'a', 0xc0, 0x00}
		offset := 0
		if err := skipSocketDNSCompressedName(message, &offset); err != nil {
			t.Fatalf("pointer skip failed: %v", err)
		}
		if offset != 4 {
			t.Fatalf("offset = %d, want 4 (past the 2-byte pointer)", offset)
		}
	})
	t.Run("root label", func(t *testing.T) {
		offset := 0
		if err := skipSocketDNSCompressedName([]byte{0x00}, &offset); err != nil {
			t.Fatalf("root skip failed: %v", err)
		}
		if offset != 1 {
			t.Fatalf("offset = %d, want 1 (past the root)", offset)
		}
	})
}

func TestValidateSocketDNSServiceBindingHintsDecidesPerParameter(t *testing.T) {
	cloudflareV6 := []byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	// svcRdata builds an SVCB rdata: 2-byte priority, a root target name, then
	// one parameter (key, value). Called with message == rdata so base == 0.
	svcRdata := func(paramKey uint16, value []byte) []byte {
		rdata := []byte{0x00, 0x01, 0x00} // priority 1, root target name
		rdata = binary.BigEndian.AppendUint16(rdata, paramKey)
		rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(value)))
		rdata = append(rdata, value...)
		return rdata
	}

	cases := []struct {
		name    string
		rdata   []byte
		wantErr error // nil = expect success
	}{
		// 325-327: rdata shorter than the 3-byte minimum (priority + name).
		{"rdata too short", []byte{0x00, 0x01}, ErrExitEventInvalid},
		// 331-333: the target name is a reserved label byte (0x40) so the name
		// skip fails.
		{"target name skip error", []byte{0x00, 0x01, 0x40}, ErrExitEventInvalid},
		// 336-338: after the root name one byte remains, fewer than the 4-byte
		// parameter key+length header.
		{"parameter trailer too short", []byte{0x00, 0x01, 0x00, 0xFF}, ErrExitEventInvalid},
		// 342-344: the parameter length (0x00FF) exceeds the remaining rdata.
		{"parameter length overruns", []byte{0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0xFF}, ErrExitEventInvalid},
		// 349-351: an IPv4 hint whose value length is not a multiple of 4.
		{"IPv4 hint misaligned", svcRdata(socketDNSSvcIPv4, []byte{1, 2, 3, 4, 5}), ErrExitEventInvalid},
		// 356: an IPv4 hint with two public addresses exercises the value[4:]
		// advance in the validation loop.
		{"IPv4 hint two addresses", svcRdata(socketDNSSvcIPv4, []byte{93, 184, 216, 34, 8, 8, 8, 8}), nil},
		// 358-361: an IPv6 hint whose value length is not a multiple of 16.
		{"IPv6 hint misaligned", svcRdata(socketDNSSvcIPv6, make([]byte, 17)), ErrExitEventInvalid},
		// 362-365: an IPv6 hint with a loopback address is policy-denied.
		{"IPv6 hint loopback denied", svcRdata(socketDNSSvcIPv6, append(make([]byte, 15), 0x01)), ErrExitPolicyDenied},
		// 366: an IPv6 hint with two public addresses exercises value[16:].
		{"IPv6 hint two addresses", svcRdata(socketDNSSvcIPv6, append(append([]byte{}, cloudflareV6...), cloudflareV6...)), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSocketDNSServiceBindingHints(tc.rdata, tc.rdata, 0, ExitPolicy{})
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// socketDNSHeaderForCoverage returns a valid 12-byte DNS query header
// (transaction 0x1234, recursion-desired flag, one question, no answers,
// authority, or additional records). Used as the base for hand-crafted
// parseSocketDNSQuestion rejection cases. Referenced by two cases so it is
// not U1000.
func socketDNSHeaderForCoverage() []byte {
	return []byte{
		0x12, 0x34, // transaction id
		0x01, 0x00, // flags: recursion desired, query, opcode 0
		0x00, 0x01, // qdcount = 1
		0x00, 0x00, // ancount = 0
		0x00, 0x00, // nscount = 0
		0x00, 0x00, // arcount = 0
	}
}
