# One-Time Access Hint Wallet and Linux Carrier Recovery Plan

**Goal:** Keep Linux proxy and packet-tunnel clients recoverable after a transient encrypted-carrier loss without reusing a one-time access hint or treating protocol, authentication, listener, route, or device failures as recoverable.

**Architecture:** Carrier record failures are classified at the transport boundary and command recovery uses a cancellable bounded backoff policy. A provisioning wallet owns distinct validated native provisioning entries, each with one access hint. A selected entry is durably reserved before any session setup that could transmit it. Failed or ambiguous session establishment leaves the entry consumed. Only another unused wallet entry may start a fresh authenticated session.

**Tech Stack:** Go standard library and the existing Aurora `admission`, `client`, `transport`, `handshake`, and Linux platform packages.

**Constraints:**

- An access hint has one use. Never retry a transmitted or ambiguously transmitted entry.
- Maintain a minimum reserve of eight usable entries per active relay bucket and initiate replenishment before the reserve drops below three. Replenishment timing must be policy-driven and non-periodic.
- Keep the native provisioning encoding stable. The wallet is a separate local container of complete provisioning entries.
- Persist a reservation atomically before network transmission, with an owner-only state file and an exclusive process lock on Linux.
- Do not persist raw secrets in logs, output, crash reports, or state metadata. Erase parsed provisioning and issuer work on every exit path.
- Recreate the session, application runtime, listeners, TUN device, and owned route state for each recovery attempt. Do not carry active flows across sessions.
- Retry only encrypted-carrier record I/O failures. Authentication, malformed record, application, listener, route, and device failures are terminal.
- Use bounded backoff with cancellation support and no fixed retry cadence.
- Do not add a protocol or specification version string to code or documentation.
- Preserve the user-owned untracked `route/zz_dump_conf_test.go` in the normal checkout.

## Task 1: Classify Duplex Carrier Failures

- [x] Add read and write error sentinels at the record I/O boundary.
- [x] Keep malformed records and endpoint-handler failures unclassified.
- [x] Add focused unit and race coverage.
- [x] Commit `feat: classify carrier transport failures`.

## Task 2: Add Bounded Command Recovery Control

- [x] Add a cancellable recovery controller with bounded delay policy.
- [x] Use typed component failures so classification does not depend on strings.
- [x] Add deterministic delay and cancellation tests.
- [x] Commit `feat: bound Linux carrier reconnects`.

## Task 3: Implement A Provisioning Wallet

- [x] Write failing client tests for canonical wallet parsing, duplicate hint rejection, expiry handling, reservation, and zeroization.
- [x] Add a bounded wallet container that validates every contained native provisioning entry without altering the existing single-entry format.
- [x] Add a reservation API that removes an entry before a caller can begin session setup, and reports remaining usable entries by relay bucket.
- [x] Add Linux owner-only, atomic reservation persistence and exclusive locking. State records non-secret stable entry identifiers, not raw access-hint secrets.
- [x] Add recovery/refill eligibility accounting without hard-coded probe scheduling.

## Task 4: Wire Fresh Entries Into Linux Clients

- [x] Make `proxy` and `tun` load the wallet and reserve a new entry for each session attempt.
- [x] Rebuild all session-bound resources after a classified carrier failure only when another entry exists.
- [x] Keep a one-entry provisioning invocation durable and terminal after its session ends; it must never perform automatic recovery.
- [x] Add real first-hop integration coverage proving that the failed and recovered sessions use different access hints and distinct application state.

## Task 5: Verify And Review

- [x] Run focused, full, race, static, and cross-compile suites.
- [x] Run fuzz and first-hop integration suites.
- [x] Review for credential reuse, state rollback, symlink/permission races, goroutine leaks, unbounded buffers, session-state reuse, and error misclassification.
- [ ] Commit reviewed implementation in small independently testable changes, publish the branch, open a draft review, and merge only after all checks pass.
