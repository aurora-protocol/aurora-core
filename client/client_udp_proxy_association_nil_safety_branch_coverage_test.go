package client

// Adversarial white-box coverage for three count-0 nil-safety guards in the
// SOCKS5 UDP proxy association: a nil-receiver guard on the write path and two
// peer-binding guards on the accept path.
//
//   - tcp_proxy_runtime.go:1141 (*udpProxyAssociation).write
//     a == nil -> return "client: SOCKS5 UDP response is invalid" (the first
//     clause of the compound :1141 guard; short-circuits before len(packet)
//     and before a.mu is touched, so a nil receiver is safe).
//   - tcp_proxy_runtime.go:1127 (*udpProxyAssociation).acceptPeer
//     a.peer != nil -> return a.peer.IP.Equal(peer.IP) && a.peer.Port ==
//     peer.Port (fires after the :1119 nil-receiver/nil-arg guard, the :1122
//     mu.Lock, and the :1124 closed guard; the existing-peer match path).
//   - tcp_proxy_runtime.go:1130 (*udpProxyAssociation).acceptPeer
//     a.peerIP != nil && !a.peerIP.Equal(peer.IP) -> return false (fires after
//     :1127 fell through because a.peer == nil, before the :1133 peerPort
//     check and the :1136 first-association assignment).
//
// The existing client tests drive acceptPeer / write only on a fully-constructed
// association (real connection, bound peer), so :1141 / :1127 / :1130 stayed
// count-0 even though each is plainly reachable with a nil receiver or a
// zero-value association.
//
// Proof technique:
//   - :1141 (nil-receiver clean return): (*udpProxyAssociation)(nil).write(
//     []byte("x")) — a == nil short-circuits before len(packet) and before
//     a.mu; :1142 returns. The non-empty packet isolates the a == nil branch.
//     The error message is unique to :1142.
//   - :1127 (existing-peer match): &udpProxyAssociation{peer: <matching addr>}
//     .acceptPeer(<matching addr>) — a.peer != nil takes :1127 and :1128 returns
//     true on the match. With a.peer pre-set, :1137 (first-association) is
//     unreachable (the :1127 branch returns at :1128), so the true return is
//     uniquely :1128 (every other reachable return with a.peer set is false).
//   - :1130 (peerIP mismatch): &udpProxyAssociation{peerIP: <mismatched IP>}
//     .acceptPeer(<peer>) — a.peer == nil skips :1127; a non-nil mismatched
//     a.peerIP trips :1130 and :1131 returns false before :1136 sets a.peer.
//     With peerPort == 0 (zero value), :1133/:1134 cannot fire, so a.peer still
//     nil after the call uniquely proves the :1131 early return (a matching /
//     nil peerIP would fall through to :1136 and set a.peer). The per-line
//     coverage flip is the rigorous proof; the false return + nil a.peer are
//     supporting behavioral evidence.
//
// No context is involved, so there is no SA1012 surface. No network, no
// goroutine, no file IO — :1141 returns before a.mu; :1127 / :1130 only read
// a.peer / a.peerIP and return; the deferred :1123 Unlock balances the :1122
// Lock on a zero-value mutex. In-package (package client) because
// udpProxyAssociation, acceptPeer, and write are unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (udpProxyAssociation, acceptPeer, write) symbols and
// the standard library net / strings / testing packages, so it adds no U1000
// surface.

import (
	"net"
	"strings"
	"testing"
)

func TestUDPProxyAssociationWriteNilReceiverGuard(t *testing.T) {
	// 1141: a == nil short-circuits before len(packet) and before a.mu is
	// touched; :1142 returns. The non-empty packet isolates the a == nil branch;
	// the message is unique to :1142.
	err := (*udpProxyAssociation)(nil).write([]byte("x"))
	if err == nil {
		t.Fatal("write(nil receiver) returned nil, want non-nil (:1142)")
	}
	if !strings.Contains(err.Error(), "SOCKS5 UDP response is invalid") {
		t.Fatalf("write nil-receiver err = %q, want \"...SOCKS5 UDP response is invalid\" (:1142)", err.Error())
	}
}

func TestUDPProxyAssociationAcceptPeerExistingPeerMatchGuard(t *testing.T) {
	// 1127: a non-nil a.peer takes the :1127 branch; a matching peer makes :1128
	// return true. With a.peer pre-set, :1137 (first-association) is unreachable
	// (the :1127 branch returns at :1128), so the true return is uniquely :1128.
	a := &udpProxyAssociation{peer: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1080}}
	if !a.acceptPeer(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1080}) {
		t.Fatal("acceptPeer(matching existing peer) returned false, want true (:1128)")
	}
}

func TestUDPProxyAssociationAcceptPeerPeerIPMismatchGuard(t *testing.T) {
	// 1130: a.peer == nil skips :1127; a non-nil mismatched a.peerIP trips :1130
	// and :1131 returns false before :1136 sets a.peer. With peerPort == 0,
	// :1133/:1134 cannot fire, so a.peer still nil after the call uniquely proves
	// the :1131 early return.
	a := &udpProxyAssociation{peerIP: net.IPv4(9, 9, 9, 9)}
	if a.acceptPeer(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1080}) {
		t.Fatal("acceptPeer(mismatched peerIP) returned true, want false (:1131)")
	}
	if a.peer != nil {
		t.Fatal("acceptPeer(mismatched peerIP) set a.peer, want a.peer still nil (proves :1131 early-returned before :1136)")
	}
}
