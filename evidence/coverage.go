package evidence

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

type CoverageReport struct {
	Passed            bool    `json:"passed"`
	CoveredStatements uint64  `json:"covered_statements"`
	TotalStatements   uint64  `json:"total_statements"`
	Percent           float64 `json:"percent"`
	MinimumPercent    float64 `json:"minimum_percent"`
}

const (
	// MaxCoverageProfileBytes bounds all data VerifyCoverage reads from its input.
	MaxCoverageProfileBytes = 4 * 1024 * 1024
	// MaxCoverageProfileRows bounds the number of coverage data rows VerifyCoverage parses.
	MaxCoverageProfileRows = 100_000
)

func VerifyCoverage(profile io.Reader, minimumPercent float64) (CoverageReport, error) {
	if profile == nil {
		return CoverageReport{}, fmt.Errorf("coverage: profile is required")
	}
	if math.IsNaN(minimumPercent) || math.IsInf(minimumPercent, 0) || minimumPercent < 0 || minimumPercent > 100 {
		return CoverageReport{}, fmt.Errorf("coverage: minimum percentage must be between 0 and 100")
	}

	reader := &countingReader{Reader: io.LimitReader(profile, MaxCoverageProfileBytes+1)}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), MaxCoverageProfileBytes+1)
	if !scanner.Scan() {
		return CoverageReport{}, fmt.Errorf("coverage: missing profile header")
	}
	if !validCoverageMode(scanner.Text()) {
		return CoverageReport{}, fmt.Errorf("coverage: invalid profile header")
	}

	report := CoverageReport{MinimumPercent: minimumPercent}
	rows := 0
	for scanner.Scan() {
		if reader.BytesRead > MaxCoverageProfileBytes {
			return CoverageReport{}, fmt.Errorf("coverage: profile byte limit exceeded")
		}
		rows++
		if rows > MaxCoverageProfileRows {
			return CoverageReport{}, fmt.Errorf("coverage: profile row limit exceeded")
		}
		statements, covered, err := parseCoverageRow(scanner.Text())
		if err != nil {
			return CoverageReport{}, err
		}
		if maxUint64-report.TotalStatements < statements {
			return CoverageReport{}, fmt.Errorf("coverage: statement count overflow")
		}
		report.TotalStatements += statements
		if covered {
			if maxUint64-report.CoveredStatements < statements {
				return CoverageReport{}, fmt.Errorf("coverage: statement count overflow")
			}
			report.CoveredStatements += statements
		}
	}
	if reader.BytesRead > MaxCoverageProfileBytes {
		return CoverageReport{}, fmt.Errorf("coverage: profile byte limit exceeded")
	}
	if err := scanner.Err(); err != nil {
		return CoverageReport{}, fmt.Errorf("coverage: read profile")
	}
	if report.TotalStatements == 0 {
		return CoverageReport{}, fmt.Errorf("coverage: profile contains no statements")
	}

	report.Percent = float64(report.CoveredStatements) * 100 / float64(report.TotalStatements)
	report.Passed = report.Percent >= minimumPercent
	if !report.Passed {
		return report, fmt.Errorf("coverage: %.2f%% is below the %.2f%% minimum", report.Percent, minimumPercent)
	}
	return report, nil
}

const maxUint64 = ^uint64(0)

type countingReader struct {
	io.Reader
	BytesRead int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.BytesRead += n
	return n, err
}

func validCoverageMode(header string) bool {
	switch header {
	case "mode: set", "mode: count", "mode: atomic":
		return true
	default:
		return false
	}
}

func parseCoverageRow(row string) (uint64, bool, error) {
	fields := strings.Fields(row)
	if len(fields) != 3 || !validCoveragePosition(fields[0]) {
		return 0, false, fmt.Errorf("coverage: invalid profile row")
	}
	statements, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("coverage: invalid statement count")
	}
	hits, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("coverage: invalid execution count")
	}
	return statements, hits > 0, nil
}

func validCoveragePosition(position string) bool {
	separator := strings.LastIndexByte(position, ':')
	if separator <= 0 || separator == len(position)-1 {
		return false
	}
	points := strings.Split(position[separator+1:], ",")
	if len(points) != 2 {
		return false
	}
	return validCoveragePoint(points[0]) && validCoveragePoint(points[1])
}

func validCoveragePoint(point string) bool {
	coordinates := strings.Split(point, ".")
	if len(coordinates) != 2 {
		return false
	}
	for _, coordinate := range coordinates {
		value, err := strconv.ParseUint(coordinate, 10, 64)
		if err != nil || value == 0 {
			return false
		}
	}
	return true
}
