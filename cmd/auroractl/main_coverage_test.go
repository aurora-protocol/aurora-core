package main

// Adversarial coverage for pure helpers in cmd/auroractl that the existing
// main_test.go does not reach directly:
//   - hostBuildTargetsForArgs: the len==0 default, too-many-arguments, --all,
//     and unknown-option branches (the existing tests only pass --portable and
//     --apple-simulator through hostBuildCheckWithRunner).
//   - validateCoverageProfile / closeRejectedCoverageProfile: the nil-file,
//     stat-failure, and close-failure branches. The stat-failure and
//     close-failure branches fire on a closed *os.File (Stat and Close both
//     return "file already closed"), so no filesystem fixture beyond a temp
//     file is needed.
//   - transportCheck / flowCheck / routeCheck: the io.WriteString error branch,
//     exercised via a writer whose Write always fails. The conformance suites
//     themselves run and succeed; only the formatted-report write errors.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// Deferred (need fault-injectable conformance suites, out of scope for this
// pure-validation pillar):
//   - transportCheck:1022 (RunCarrierConformance error) and :1028
//     (!report.Passed): the conformance runners succeed by construction.
//   - flowCheck:1036 / :1042 and routeCheck:1050 / :1056: same reason.

import (
	"errors"
	"os"
	"testing"

	auroraplatform "github.com/aurora-protocol/aurora-core/platform"
)

func TestHostBuildTargetsForArgs(t *testing.T) {
	portable := len(auroraplatform.PortableHostBuildTargets())
	apple := len(auroraplatform.AppleSimulatorHostBuildTargets())
	cases := []struct {
		name    string
		args    []string
		wantErr bool
		wantLen int
	}{
		{"empty defaults to portable", nil, false, portable},
		{"too many arguments", []string{"--portable", "--apple-simulator"}, true, 0},
		{"portable", []string{"--portable"}, false, portable},
		{"apple simulator", []string{"--apple-simulator"}, false, apple},
		{"all combines portable and apple", []string{"--all"}, false, portable + apple},
		{"unknown option", []string{"--bogus"}, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := hostBuildTargetsForArgs(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("hostBuildTargetsForArgs(%v) err=%v, wantErr=%t", tc.args, err, tc.wantErr)
			}
			if !tc.wantErr && len(targets) != tc.wantLen {
				t.Fatalf("hostBuildTargetsForArgs(%v) len=%d, want %d", tc.args, len(targets), tc.wantLen)
			}
		})
	}
}

func TestValidateCoverageProfileRejectsNilAndClosedFile(t *testing.T) {
	t.Run("nil file", func(t *testing.T) {
		if file, err := validateCoverageProfile(nil); err == nil || file != nil {
			t.Fatalf("validateCoverageProfile(nil) = %v, %v, want nil error", file, err)
		}
	})
	t.Run("closed file stat failure surfaces close error", func(t *testing.T) {
		// A closed *os.File errors on Stat, which routes through
		// closeRejectedCoverageProfile; Close also errors on the already-closed
		// file, so the returned error is the close failure (covers both the
		// stat branch at 13-14 and the close branch at 23-24).
		file, err := validateCoverageProfile(closedCoverageFileForCoverage(t))
		if err == nil || file != nil {
			t.Fatalf("validateCoverageProfile(closed) = %v, %v, want non-nil error", file, err)
		}
	})
}

func TestValidateCoverageProfileAcceptsRegularFile(t *testing.T) {
	file := tempCoverageFileForCoverage(t)
	if returned, err := validateCoverageProfile(file); err != nil || returned != file {
		t.Fatalf("validateCoverageProfile(regular) = %v, %v, want the same file", returned, err)
	}
	t.Cleanup(func() { _ = file.Close() })
}

func TestCloseRejectedCoverageProfileSurfacesCloseFailureAndRejection(t *testing.T) {
	t.Run("close failure wins over rejection", func(t *testing.T) {
		// Close on an already-closed file errors, so the close-failure error is
		// returned rather than the rejected error (line 23-24).
		closed := closedCoverageFileForCoverage(t)
		err := closeRejectedCoverageProfile(closed, errors.New("rejected"))
		if err == nil || err.Error() == "rejected" {
			t.Fatalf("closeRejectedCoverageProfile(closed) = %v, want close failure", err)
		}
	})
	t.Run("close success returns rejection", func(t *testing.T) {
		// Close succeeds on an open file, so the rejected error is returned
		// unchanged (line 26).
		open := tempCoverageFileForCoverage(t)
		err := closeRejectedCoverageProfile(open, errors.New("rejected"))
		if err == nil || err.Error() != "rejected" {
			t.Fatalf("closeRejectedCoverageProfile(open) = %v, want rejected", err)
		}
	})
}

func TestCheckCommandsSurfaceWriterFailure(t *testing.T) {
	w := failingCoverageWriter{}
	t.Run("transportCheck", func(t *testing.T) {
		if err := transportCheck(w); err == nil {
			t.Fatal("transportCheck accepted a failing writer")
		}
	})
	t.Run("flowCheck", func(t *testing.T) {
		if err := flowCheck(w); err == nil {
			t.Fatal("flowCheck accepted a failing writer")
		}
	})
	t.Run("routeCheck", func(t *testing.T) {
		if err := routeCheck(w); err == nil {
			t.Fatal("routeCheck accepted a failing writer")
		}
	})
}

// failingCoverageWriter is an io.Writer whose Write always fails, used to
// drive the io.WriteString error branch of the check commands.
type failingCoverageWriter struct{}

func (failingCoverageWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

// tempCoverageFileForCoverage creates and returns an open temp file for
// coverage-profile validation tests; the caller closes it (or relies on the
// test's temp dir cleanup).
func tempCoverageFileForCoverage(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "coverage-*.out")
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// closedCoverageFileForCoverage creates a temp file and closes it, returning
// the closed *os.File so Stat/Close branches that fire on a closed file can be
// exercised. The file lives in the test's temp dir, which is removed on
// cleanup.
func closedCoverageFileForCoverage(t *testing.T) *os.File {
	t.Helper()
	file := tempCoverageFileForCoverage(t)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}