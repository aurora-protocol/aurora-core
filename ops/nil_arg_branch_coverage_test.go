package ops

// Adversarial white-box coverage for the two count-0 nil-argument guards in
// ops/verifier_transport.go. Both sit on the verifier HTTP/TLS plumbing path
// and stayed count-0 because the existing ops tests only ever drive a fully
// configured verifier transport (a non-nil TLSClientConfig and a real TLS
// connection state), so neither the nil-config default-init nor the nil-state
// rejection ran — even though each is plainly reachable.
//
// These are nil-ARGUMENT guards (none is a ctx==nil guard), so there is no
// SA1012 surface. No network, no goroutine, no crypto — :146 only clones a
// standard http.Transport and installs a fresh tls.Config; :211 returns at its
// first statement. The test is in-package because both functions are unexported.
//
//   - verifier_transport.go:146 issuerVerifierHTTPTransport  tlsConfig == nil
//     -> tlsConfig = &tls.Config{} (default-init). Reachability is subtle: the
//     standard http.Transport auto-enables HTTP/2, and Transport.Clone() runs
//     onceSetNextProtoDefaults -> http2configureTransports, which MATERIALIZES a
//     non-nil TLSClientConfig even when the caller left it nil. So a plain
//     &http.Transport{} reaches the ELSE branch (:149), never :147. The guard is
//     reached only when HTTP/2 is disabled, which is the documented, idiomatic
//     verifier-client configuration: setting TLSNextProto to an empty map is the
//     net/http-documented way to disable HTTP/2 (see Transport.protocols()). With
//     HTTP/2 off, onceSetNextProtoDefaults returns before http2configureTransports,
//     TLSClientConfig stays nil through Clone, :146 fires, :147 installs a fresh
//     config, and :157 pins MinVersion = TLS 1.3. The proof that :147 ran: the
//     input transport's TLSClientConfig is nil (HTTP/2 disabled leaves it nil
//     through Clone), yet the returned transport's TLSClientConfig is non-nil and
//     pinned to TLS 1.3 — a nil config can only become non-nil at :147.
//   - verifier_transport.go:211 verifyIssuerVerifierTLSIdentity  state == nil
//     -> "ops: verifier service did not use TLS" (clean first-statement reject;
//     the nil *tls.ConnectionState is the only argument needed)

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestIssuerVerifierHTTPTransportDefaultsNilTLSConfig(t *testing.T) {
	// 146: an empty (non-nil) TLSNextProto map is the net/http-documented way to
	// disable HTTP/2 on a Transport. With HTTP/2 off, Transport.Clone()'s
	// onceSetNextProtoDefaults returns before http2configureTransports, so a nil
	// TLSClientConfig stays nil through the clone. issuerVerifierHTTPTransport
	// then hits `if tlsConfig == nil` at 146, installs a fresh tls.Config at 147,
	// and pins MinVersion = TLS 1.3 at 157. A nil config can only become non-nil
	// at 147, so a non-nil returned config pinned to TLS 1.3 is the signature of
	// the :147 default-init branch.
	transport, err := issuerVerifierHTTPTransport(&http.Transport{
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	})
	if err != nil {
		t.Fatalf("issuerVerifierHTTPTransport(HTTP/2-disabled transport) err = %v, want nil (:146 should default the nil config)", err)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("issuerVerifierHTTPTransport TLSClientConfig = nil, want non-nil (:147 should install a fresh config from the nil input)")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("issuerVerifierHTTPTransport MinVersion = 0x%x, want TLS 1.3 (0x%x) — :157 should pin the floor after :147 default-init", transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
}

func TestVerifyIssuerVerifierTLSIdentityRejectsNilState(t *testing.T) {
	// 211: a nil *tls.ConnectionState is rejected at the first statement with
	// "ops: verifier service did not use TLS", before the TLS version /
	// certificate checks run.
	err := verifyIssuerVerifierTLSIdentity(nil, protocol.PublicKeyRecord{})
	if err == nil {
		t.Fatal("verifyIssuerVerifierTLSIdentity(nil state) err = nil, want non-nil (:211 should reject)")
	}
	if !strings.Contains(err.Error(), "did not use TLS") {
		t.Fatalf("verifyIssuerVerifierTLSIdentity(nil state) err = %v, want substring \"did not use TLS\" (:211)", err)
	}
}
