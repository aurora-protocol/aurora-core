package evidence

import (
	"strings"
	"testing"
)

func TestVerifyCoverageWeightsStatementCounts(t *testing.T) {
	profile := "mode: atomic\na.go:1.1,2.1 8 1\na.go:3.1,4.1 2 0\n"

	report, err := VerifyCoverage(strings.NewReader(profile), 79)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed || report.CoveredStatements != 8 || report.TotalStatements != 10 || report.Percent != 80 || report.MinimumPercent != 79 {
		t.Fatalf("report = %+v", report)
	}
}

func TestVerifyCoverageRejectsMalformedProfiles(t *testing.T) {
	tests := []struct {
		name    string
		profile string
	}{
		{
			name:    "malformed header",
			profile: "mode atomic\na.go:1.1,2.1 1 1\n",
		},
		{
			name:    "malformed row",
			profile: "mode: atomic\na.go:1.1,2.1 count 1\n",
		},
		{
			name:    "negative count",
			profile: "mode: atomic\na.go:1.1,2.1 1 -1\n",
		},
		{
			name:    "zero statements",
			profile: "mode: atomic\na.go:1.1,2.1 0 0\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyCoverage(strings.NewReader(tc.profile), 70)
			if err == nil {
				t.Fatal("VerifyCoverage accepted malformed profile")
			}
		})
	}
}

func TestVerifyCoverageReportsBelowThreshold(t *testing.T) {
	profile := "mode: atomic\na.go:1.1,2.1 3 1\na.go:3.1,4.1 1 0\n"

	report, err := VerifyCoverage(strings.NewReader(profile), 80)
	if err == nil {
		t.Fatal("VerifyCoverage accepted coverage below the threshold")
	}
	if report.Passed || report.CoveredStatements != 3 || report.TotalStatements != 4 || report.Percent != 75 || report.MinimumPercent != 80 {
		t.Fatalf("report = %+v", report)
	}
}
