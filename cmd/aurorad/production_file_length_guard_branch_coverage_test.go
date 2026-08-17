package main

// Adversarial white-box coverage for the count-0 length-validation branch of
// readProductionFileWithMode (cmd/aurorad/production.go), the shared read helper
// behind every production file loader. After the file passes the Lstat/regular/
// restricted/open/stat/same-file checks, io.ReadAll reads up to
// maximumProductionConfigurationFileBytes+1 bytes; the guard at :696 rejects an
// empty result (len == 0) or an oversize result (len > max). Both bodies are
// COUNT 0 because the existing loader tests (and the #328/#332/#333/#334
// crafted-content tests) only feed non-empty, in-bounds files.
//
// Coverage target (baseline measured on main; the body was COUNT 0 while its
// condition was already evaluated 84x):
//   - production.go:696.81,699.3 2 0  — len==0 || len>max -> "length is invalid"
//
// Reachable cross-platform via readProductionFile (restricted=false skips the
// o077 + owner checks, so any-perm file reaches ReadAll): an empty regular file
// -> len==0; a file larger than maximumProductionConfigurationFileBytes (1<<20)
// -> the LimitReader(max+1) yields max+1 bytes -> len>max. No real production key
// material is involved; the payloads are empty / arbitrary fill bytes.
//
// No context is involved, so there is no SA1012 surface. The only IO is throwaway
// t.TempDir() files, removed automatically. In-package (package main) because
// readProductionFile / readProductionFileWithMode are unexported.
//
// This test file adds only TestXxx entry points and references existing in-package
// (readProductionFile, maximumProductionConfigurationFileBytes) symbols and the
// standard library os / path/filepath / strings / testing packages, so it adds no
// U1000 surface.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadProductionFileRejectsEmptyFile(t *testing.T) {
	// :696 len==0: a regular, readable, non-empty-permission file that is empty,
	// so ReadAll returns 0 bytes and the length guard rejects it. restricted=false
	// (readProductionFile) skips the o077 + owner checks on every platform, so the
	// empty file reaches ReadAll identically everywhere.
	directory := t.TempDir()
	path := filepath.Join(directory, "empty.cfg")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readProductionFile(path)
	if err == nil {
		t.Fatal("readProductionFile(empty) err = nil, want non-nil (:696 should reject)")
	}
	if !strings.Contains(err.Error(), "length is invalid") {
		t.Fatalf("empty err = %q, want substring \"length is invalid\" (:698)", err.Error())
	}
}

func TestReadProductionFileRejectsOversizeFile(t *testing.T) {
	// :696 len>max: a regular, readable file larger than
	// maximumProductionConfigurationFileBytes (1<<20). io.LimitReader caps the read
	// at max+1 bytes; the file has max+1 bytes, so ReadAll yields exactly max+1,
	// len > max, and the length guard rejects it. Exercises the upper bound of the
	// same guard (the body is shared with the empty case via ||).
	directory := t.TempDir()
	path := filepath.Join(directory, "oversize.cfg")
	payload := bytes.Repeat([]byte{0x41}, maximumProductionConfigurationFileBytes+1)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readProductionFile(path)
	if err == nil {
		t.Fatal("readProductionFile(oversize) err = nil, want non-nil (:696 should reject)")
	}
	if !strings.Contains(err.Error(), "length is invalid") {
		t.Fatalf("oversize err = %q, want substring \"length is invalid\" (:698)", err.Error())
	}
}
