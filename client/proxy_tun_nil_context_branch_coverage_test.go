package client

// Adversarial white-box coverage for the count-0 nil-context guards of the
// client proxy/TUN/provisioned-session entrypoints. Six methods/functions open
// (after a receiver nil-guard) with `if ctx == nil { return ... }`; every
// existing caller passes a real context.Background(), so all six nil-context
// bodies are COUNT 0 on main.
//
// Coverage targets (baseline measured on main; all bodies COUNT 0):
//   - packet_tun_runtime.go:81.16,83.3   — PacketTUNRuntime.Serve ("nil packet TUN context")
//   - packet_tun_runtime.go:136.16,138.3 — PacketTUNRuntime.HandleFrameBlock ("nil packet TUN frame context")
//   - provisioned_session.go:160.16,162.3— ProvisionedSession.Complete ("nil provisioned completion context")
//   - tcp_proxy_runtime.go:184.16,186.3  — TCPProxyRuntime.Serve ("nil TCP proxy serve context")
//   - tcp_proxy_runtime.go:233.16,235.3  — TCPProxyRuntime.HandleFrameBlock ("nil TCP proxy frame context")
//   - tcp_proxy_runtime.go:335.16,338.3  — TCPProxyRuntime.serveConnection ("nil TCP proxy connection context")
//
// Each guard is the second statement (right after the receiver nil-guard), so a
// non-nil zero-value receiver + nil context reaches it without reading any
// field/listener/block — except serveConnection (:335), whose nil-context body
// defensively closes the connection before returning, so it is given a real
// net.Pipe end (its Close is a harmless no-op-ish call). The 6.16 col is the
// body block; the condition itself is already evaluated by existing callers.
//
// SA1012 (nil Context literal) is suppressed per the established codebase
// convention (//lint:ignore SA1012 Verifies the public API's explicit
// nil-context rejection.) on each intentional nil-context call (CI-proven on
// #264/#346/#349/#350). serveConnection is unexported, so this is an in-package
// (package client) test; the other five are exported methods. No real network
// I/O (the pipe end is only Close'd). One TestXxx with six t.Run subtests;
// references protocol.FrameBlock + net.Pipe + stdlib strings/testing -> no
// U1000 surface.

import (
	"net"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestProxyTUNProvisionedSessionRejectNilContext(t *testing.T) {
	// :81 — PacketTUNRuntime.Serve.
	t.Run("PacketTUNRuntime.Serve", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := (&PacketTUNRuntime{}).Serve(nil); err == nil || !strings.Contains(err.Error(), "nil packet TUN context") {
			t.Fatalf("Serve(nil ctx) err = %v, want non-nil containing \"nil packet TUN context\" (:81)", err)
		}
	})

	// :136 — PacketTUNRuntime.HandleFrameBlock.
	t.Run("PacketTUNRuntime.HandleFrameBlock", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := (&PacketTUNRuntime{}).HandleFrameBlock(nil, protocol.FrameBlock{}); err == nil || !strings.Contains(err.Error(), "nil packet TUN frame context") {
			t.Fatalf("HandleFrameBlock(nil ctx) err = %v, want non-nil containing \"nil packet TUN frame context\" (:136)", err)
		}
	})

	// :160 — ProvisionedSession.Complete. The deeper Complete() crypto guards
	// were covered by #331 with a real ctx; :160 (the ctx==nil guard) stayed
	// count-0 because that harness always supplies a context.
	t.Run("ProvisionedSession.Complete", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if _, err := (&ProvisionedSession{}).Complete(nil, nil); err == nil || !strings.Contains(err.Error(), "nil provisioned completion context") {
			t.Fatalf("Complete(nil ctx) err = %v, want non-nil containing \"nil provisioned completion context\" (:160)", err)
		}
	})

	// :184 — TCPProxyRuntime.Serve. The nil listener is never read (ctx==nil
	// returns first).
	t.Run("TCPProxyRuntime.Serve", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := (&TCPProxyRuntime{}).Serve(nil, nil); err == nil || !strings.Contains(err.Error(), "nil TCP proxy serve context") {
			t.Fatalf("Serve(nil ctx) err = %v, want non-nil containing \"nil TCP proxy serve context\" (:184)", err)
		}
	})

	// :233 — TCPProxyRuntime.HandleFrameBlock.
	t.Run("TCPProxyRuntime.HandleFrameBlock", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := (&TCPProxyRuntime{}).HandleFrameBlock(nil, protocol.FrameBlock{}); err == nil || !strings.Contains(err.Error(), "nil TCP proxy frame context") {
			t.Fatalf("HandleFrameBlock(nil ctx) err = %v, want non-nil containing \"nil TCP proxy frame context\" (:233)", err)
		}
	})

	// :335 — TCPProxyRuntime.serveConnection. Its nil-context body closes the
	// connection before returning, so pass a real net.Pipe end (Close is a
	// harmless, discarded call). The other end is closed by defer to avoid a
	// leaked pipe.
	t.Run("TCPProxyRuntime.serveConnection", func(t *testing.T) {
		connA, connB := net.Pipe()
		defer connB.Close()
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := (&TCPProxyRuntime{}).serveConnection(nil, connA); err == nil || !strings.Contains(err.Error(), "nil TCP proxy connection context") {
			t.Fatalf("serveConnection(nil ctx) err = %v, want non-nil containing \"nil TCP proxy connection context\" (:335)", err)
		}
	})
}
