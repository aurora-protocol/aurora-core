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

func VerifyCoverage(profile io.Reader, minimumPercent float64) (CoverageReport, error) {
	report := CoverageReport{MinimumPercent: minimumPercent}
	if profile == nil {
		return report, fmt.Errorf("coverage: profile is required")
	}
	if math.IsNaN(minimumPercent) || math.IsInf(minimumPercent, 0) || minimumPercent < 0 || minimumPercent > 100 {
		return report, fmt.Errorf("coverage: minimum percentage must be between 0 and 100")
	}

	scanner := bufio.NewScanner(profile)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	if !scanner.Scan() {
		return report, fmt.Errorf("coverage: missing profile header")
	}
	if !validCoverageMode(scanner.Text()) {
		return report, fmt.Errorf("coverage: invalid profile header")
	}

	for scanner.Scan() {
		statements, covered, err := parseCoverageRow(scanner.Text())
		if err != nil {
			return report, err
		}
		if maxUint64-report.TotalStatements < statements {
			return report, fmt.Errorf("coverage: statement count overflow")
		}
		report.TotalStatements += statements
		if covered {
			if maxUint64-report.CoveredStatements < statements {
				return report, fmt.Errorf("coverage: statement count overflow")
			}
			report.CoveredStatements += statements
		}
	}
	if err := scanner.Err(); err != nil {
		return report, fmt.Errorf("coverage: read profile")
	}
	if report.TotalStatements == 0 {
		return report, fmt.Errorf("coverage: profile contains no statements")
	}

	report.Percent = float64(report.CoveredStatements) * 100 / float64(report.TotalStatements)
	report.Passed = report.Percent >= minimumPercent
	if !report.Passed {
		return report, fmt.Errorf("coverage: %.2f%% is below the %.2f%% minimum", report.Percent, minimumPercent)
	}
	return report, nil
}

const maxUint64 = ^uint64(0)

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
	if err != nil || statements == 0 {
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
