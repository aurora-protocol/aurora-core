package labfixture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// TestLoadRejectsTamperedIssuerMetadata proves a minted directory whose
// issuer metadata no longer verifies under the minted issuer authority (here:
// the relay bucket scopes stripped, breaking the signature) fails closed at
// Load with an error instead of surviving into NewServer, where the missing
// scope previously crashed the lab relay with an index-out-of-range panic.
func TestLoadRejectsTamperedIssuerMetadata(t *testing.T) {
	material := mintForTest(t, nil)
	defer material.Zero()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := material.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tampered := loaded.IssuerMetadata
	tampered.RelayBucketScopes = nil
	tampered.OriginInfoPolicies = nil
	encoded, err := protocol.Encode(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileIssuerMetadata), encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("tampered issuer metadata crashed the lab server instead of failing closed: %v", recovered)
		}
	}()
	reloaded, err := Load(dir, time.Now())
	if err != nil {
		return
	}
	server, err := NewServer(reloaded, ServerOptions{PublicAddress: "0.0.0.0:9443"})
	if err == nil {
		_ = server.Close()
		t.Fatal("tampered issuer metadata was accepted by Load and NewServer")
	}
}
