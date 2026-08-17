package relay

// Adversarial white-box coverage for the two count-0 no-resolver-needed
// short-circuit branches in (*SocketEgress).handleDNSMessage (relay/dns.go):
// the policy-deny branch (:58) and the nil-upstream-resolver Fail branch
// (:61). handleDNSMessage is the socket-DNS egress handler. Its switch has
// three arms: (1) policy denies the domain -> RCODE Deny (:58); (2) a
// non-A/AAAA query type with NO upstream resolver configured -> RCODE Fail
// (:61); (3) the A/AAAA resolver path. The existing relay DNS tests drive the
// A/AAAA resolver happy path and the parse/validator rejection paths, so the
// Deny (:58) and nil-resolver Fail (:61) branches stayed COUNT 0.
//
// Both target branches are reachable WITHOUT any resolver/dialer/sink/flow
// wiring: the Deny arm sets RCODE=Deny and breaks to buildSocketDNSResponse
// (no resolver call); the nil-resolver Fail arm detects
// isNilExitDependency(e.dnsResolver) and breaks (no resolver call). ctx is
// only used by the resolver arms (operationContext at :69/:93), so the target
// arms never touch ctx. A white-box &SocketEgress{policy: DefaultExitPolicy(),
// limits: SocketEgressLimits{ResolvedTTLSeconds: 1}} (dnsResolver nil) plus a
// crafted DNS question wire (reusing the in-package socketEgressDNSQuery
// helper) is sufficient. The per-line coverage flip is the rigorous proof.
//
// Reachability:
//   - :58 Deny — AllowDomain("localhost")==false under DefaultExitPolicy
//     (AllowPrivate=false; "localhost" is in the deny list). A type-A query
//     for "localhost" trips the FIRST switch case before any resolver arm.
//   - :61 Fail — AllowDomain("example.com")==true (passes :58), queryType 99
//     (neither A=1 nor AAAA=28) trips the non-A/AAAA case (:60), and the
//     zero-value SocketEgress has dnsResolver==nil -> isNilExitDependency
//     true -> RCODE=Fail + break (no resolver call).
//
// Both arms return a built response frame ([]protocol.AuroraFrame, nil) via
// the shared buildSocketDNSResponse + NewDNSMessageFrame tail (:105-:110);
// the responseCode is internal (not observable on the returned frame), so the
// per-line coverage flip — not a returned value — is the proof. The test
// asserts a non-nil frame slice and nil error (the build tail succeeded).

import (
	"context"
	"testing"
)

func TestHandleDNSMessageDenyAndNilResolverFailBranches(t *testing.T) {
	// White-box SocketEgress with only the fields the two target arms read:
	// policy (AllowDomain) and limits (ResolvedTTLSeconds for the build tail).
	// dnsResolver/resolver/dialer/sink are all zero/nil — unused by the Deny
	// and nil-resolver-Fail arms (they break before any resolver call).
	egress := &SocketEgress{
		policy: DefaultExitPolicy(),
		limits: SocketEgressLimits{ResolvedTTLSeconds: 1},
	}
	cases := []struct {
		name      string
		domain    string
		queryType uint16
	}{
		{
			// dns.go:58 — DefaultExitPolicy (AllowPrivate=false) denies
			// "localhost" (it is in the AllowDomain deny list). A type-A query
			// trips the FIRST switch case before the resolver arms.
			name:      "policy denies domain",
			domain:    "localhost",
			queryType: socketDNSTypeA,
		},
		{
			// dns.go:61 — allowed domain (passes :58), non-A/AAAA query type
			// (trips :60), zero-value dnsResolver==nil -> isNilExitDependency
			// -> RCODE Fail + break (no resolver call).
			name:      "nil upstream resolver for non a aaaa query",
			domain:    "example.com",
			queryType: 99, // neither A(1) nor AAAA(28); parseSocketDNSQuestion accepts any type
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			event := ExitFrameEvent{
				FlowID: 1,
				Data:   socketEgressDNSQuery(t, c.domain, c.queryType),
			}
			frames, err := egress.handleDNSMessage(context.Background(), event)
			if err != nil {
				t.Fatalf("%s: err = %v, want nil", c.name, err)
			}
			if len(frames) == 0 {
				t.Fatalf("%s: returned no frames, want a built DNS response frame", c.name)
			}
		})
	}
}
