package evidence

// Adversarial white-box coverage for the rejection branches of coverage.go
// that the existing coverage_test.go suite does not reach. coverage.go is
// pure stdlib (bufio, fmt, io, math, strconv, strings) — no crypto, no
// context, no aurora-internal packages, no network or filesystem — so every
// branch below is driven with plain string inputs.
//
// Targets covered:
//
//   - VerifyCoverage:28-30 — the `profile == nil` guard. Every existing test
//     passes a non-nil reader (strings.NewReader or errorAfterReader), so the
//     "profile is required" return is never reached. Driving VerifyCoverage
//     with a nil io.Reader hits it before any LimitReader/Scanner is built.
//
//   - VerifyCoverage:38-40 — the `!scanner.Scan()` "missing profile header"
//     return. Every existing profile begins with a valid "mode: atomic"
//     header; an empty reader yields no first token, so Scan returns false and
//     this branch fires.
//
//   - validCoveragePosition:128-130 — `separator <= 0 || separator ==
//     len(position)-1`. The existing malformed-row cases ("count", "-1") keep
//     a well-formed position ("a.go:1.1,2.1") and break the statement/hit
//     fields instead, so the no-colon and colon-at-end position rejections are
//     never exercised. "nocolon" (separator == -1) and "f.go:" (separator at
//     the last byte) both reach this branch.
//
//   - validCoveragePosition:132-134 — `len(points) != 2`. A position with
//     three comma-separated points ("f.go:1.1,2.2,3.3") passes the separator
//     check but fails the point-count check.
//
//   - validCoveragePoint:140-142 — `len(coordinates) != 2`. A point with three
//     dot-separated coordinates ("1.1.1") fails the coordinate-count check.
//     "abc" (one coordinate) covers the same branch the other way.
//
//   - validCoveragePoint:145-147 — `err != nil || value == 0`. A coordinate
//     of "0" (value == 0) and a non-numeric coordinate "x" (ParseUint err)
//     both reach this branch. The existing suite only ever feeds valid 1-based
//     coordinates, so the zero/non-numeric rejection is uncovered.
//
// Each pure helper is also given a true anchor (a well-formed position / point)
// in the same test, so a false result is attributable to the malformed input
// alone rather than a broken helper.
//
// Dead-by-design (documented, NOT covered — and not contrived):
//   - VerifyCoverage:64-66 — the CoveredStatements overflow check. It runs
//     only when `covered` is true (line 63), AFTER the TotalStatements overflow
//     check at line 59 in the same iteration. Since CoveredStatements is a
//     subset of TotalStatements (covered rows add to both, uncovered rows add
//     only to TotalStatements), TotalStatements >= CoveredStatements always,
//     so any input that would overflow CoveredStatements already overflows
//     TotalStatements and returns at line 60 first. The existing
//     TestVerifyCoverageRejectsStatementCountOverflow covers line 60; line 64
//     cannot fire on any input.
//
// Deferred (fiddly, not deterministically coverable here):
//   - VerifyCoverage:70-72 — the post-loop byte-limit check. The in-loop
//     check at line 48 fires whenever BytesRead exceeds the limit after a
//     successful Scan; the post-loop check at 70 fires only when the byte
//     overflow coincides with the *final* Scan that returns false (EOF),
//     skipping the loop body. The existing TestVerifyCoverageRejectsInputBounds
//     "byte limit" case covers the in-loop path (line 48); hitting the post-loop
//     path needs a specifically-sized input where the last read both crosses
//     the 4 MiB limit and ends the stream without yielding another complete
//     line — a timing/sizing artifact, not a distinct logical branch.
//
// No new package-level helpers or types are introduced (only test functions;
// validCoveragePosition / validCoveragePoint / parseCoverageRow are existing
// package symbols already referenced by production code), so there is nothing
// for staticcheck U1000. No context.Context, no goroutines, no real network or
// filesystem.

import (
	"strings"
	"testing"
)

func TestVerifyCoverageRequiresProfile(t *testing.T) {
	// A nil io.Reader hits the explicit nil guard at line 28 before any
	// LimitReader/Scanner is constructed.
	if _, err := VerifyCoverage(nil, 50); err == nil ||
		!strings.Contains(err.Error(), "profile is required") {
		t.Fatalf("VerifyCoverage(nil) err = %v, want \"profile is required\"", err)
	}
}

func TestVerifyCoverageRejectsMissingHeader(t *testing.T) {
	// An empty reader yields no first token, so scanner.Scan() returns false
	// and VerifyCoverage returns "missing profile header" at line 38.
	if _, err := VerifyCoverage(strings.NewReader(""), 50); err == nil ||
		!strings.Contains(err.Error(), "missing profile header") {
		t.Fatalf("VerifyCoverage(empty) err = %v, want \"missing profile header\"", err)
	}
}

func TestValidCoveragePositionRejectsMalformed(t *testing.T) {
	cases := []struct {
		name     string
		position string
	}{
		// 128-130: no colon at all -> separator == -1 (<= 0).
		{"no colon", "nocolon"},
		// 128-130: colon is the last byte -> separator == len(position)-1.
		{"colon at end", "f.go:"},
		// 132-134: two valid checks pass, but three comma-separated points.
		{"three points", "f.go:1.1,2.2,3.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if validCoveragePosition(tc.position) {
				t.Fatalf("validCoveragePosition(%q) = true, want false", tc.position)
			}
		})
	}
	// Anchor: a well-formed position is accepted, proving the false results
	// above are due to the malformed input, not a broken helper.
	if !validCoveragePosition("a.go:1.1,2.1") {
		t.Fatal("validCoveragePosition(a.go:1.1,2.1) = false, want true")
	}
}

func TestValidCoveragePointRejectsMalformed(t *testing.T) {
	cases := []struct {
		name  string
		point string
	}{
		// 140-142: three dot-separated coordinates.
		{"three coordinates", "1.1.1"},
		// 140-142: one coordinate (no dot).
		{"one coordinate", "abc"},
		// 145-147: a coordinate of 0 (value == 0).
		{"zero coordinate", "1.0"},
		// 145-147: a non-numeric coordinate (ParseUint err).
		{"non-numeric coordinate", "1.x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if validCoveragePoint(tc.point) {
				t.Fatalf("validCoveragePoint(%q) = true, want false", tc.point)
			}
		})
	}
	// Anchor: a well-formed point is accepted.
	if !validCoveragePoint("1.1") {
		t.Fatal("validCoveragePoint(1.1) = false, want true")
	}
}
