//go:build aurora_lab

package logging

import (
	"strings"
	"testing"
)

func TestLabStringExposesOnlyInLabBuildWhenRuntimeEnabled(t *testing.T) {
	secret := Secret{Kind: TokenAuthenticator, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	if got := LabString(secret, false); strings.Contains(got, "deadbeef") {
		t.Fatalf("secret leaked without runtime lab flag: %s", got)
	}
	if got := LabString(secret, true); !strings.Contains(got, "deadbeef") {
		t.Fatalf("lab build did not expose fixture secret with runtime lab flag: %s", got)
	}
}
