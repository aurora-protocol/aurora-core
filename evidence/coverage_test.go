package evidence

import (
	"errors"
	"math"
	"strconv"
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

func TestVerifyCoverageReturnsNoPartialReportOnParseOrReadError(t *testing.T) {
	tests := []struct {
		name    string
		profile interface{ Read([]byte) (int, error) }
	}{
		{
			name:    "malformed after valid row",
			profile: strings.NewReader("mode: atomic\na.go:1.1,2.1 1 1\nnot a profile row\n"),
		},
		{
			name: "reader error after valid row",
			profile: &errorAfterReader{
				data: []byte("mode: atomic\na.go:1.1,2.1 1 1\n"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := VerifyCoverage(tc.profile, 70)
			if err == nil {
				t.Fatal("VerifyCoverage accepted invalid input")
			}
			if report != (CoverageReport{}) {
				t.Fatalf("report = %+v, want empty report", report)
			}
		})
	}
}

func TestVerifyCoverageRejectsInputBounds(t *testing.T) {
	row := strings.Repeat("a", 80) + ":1.1,2.1 1 1\n"
	tooLarge := "mode: atomic\n" + strings.Repeat(row, MaxCoverageProfileBytes/len(row)+1)
	tooManyRows := "mode: atomic\n" + strings.Repeat("a.go:1.1,2.1 1 1\n", MaxCoverageProfileRows+1)

	for name, tc := range map[string]struct {
		profile string
		want    string
	}{
		"byte limit": {profile: tooLarge, want: "byte limit"},
		"row limit":  {profile: tooManyRows, want: "row limit"},
	} {
		t.Run(name, func(t *testing.T) {
			report, err := VerifyCoverage(strings.NewReader(tc.profile), 70)
			if err == nil {
				t.Fatal("VerifyCoverage accepted unbounded input")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if report != (CoverageReport{}) {
				t.Fatalf("report = %+v, want empty report", report)
			}
		})
	}
}

func TestVerifyCoverageRejectsStatementCountOverflow(t *testing.T) {
	profile := "mode: atomic\na.go:1.1,2.1 " + strconv.FormatUint(maxUint64, 10) + " 1\na.go:3.1,4.1 1 1\n"

	report, err := VerifyCoverage(strings.NewReader(profile), 70)
	if err == nil {
		t.Fatal("VerifyCoverage accepted overflowing statement counts")
	}
	if report != (CoverageReport{}) {
		t.Fatalf("report = %+v, want empty report", report)
	}
}

func TestVerifyCoverageRejectsInvalidMinimum(t *testing.T) {
	profile := "mode: atomic\na.go:1.1,2.1 1 1\n"
	for _, minimum := range []float64{-1, 101, math.NaN(), math.Inf(1)} {
		report, err := VerifyCoverage(strings.NewReader(profile), minimum)
		if err == nil {
			t.Fatalf("VerifyCoverage accepted minimum %v", minimum)
		}
		if report != (CoverageReport{}) {
			t.Fatalf("report = %+v, want empty report", report)
		}
	}
}

type errorAfterReader struct {
	data []byte
	read bool
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		return copy(p, r.data), nil
	}
	return 0, errors.New("read failed")
}
