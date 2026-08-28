// Package labfixture mints and loads complete, self-consistent Aurora relay
// deployments for LOCAL LAB TESTING ONLY.
//
// Everything this package produces uses freshly generated, self-signed,
// single-tenant credentials with long convenience validity windows. It exists
// so that production clients can be tested end to end against a LAN-reachable
// lab relay without production provisioning infrastructure. The material it
// mints MUST never be deployed as production infrastructure, and the private
// keys it writes MUST never be reused outside a disposable lab deployment.
//
// The package only composes production APIs (trust, issuerd, handshake,
// server, client); it changes no production behavior.
package labfixture
