package route

// Adversarial coverage for the pure validators and the VerifyRoutePrelude1Signatures
// orchestrator in route/route.go that the existing route_test.go suite reaches only
// indirectly (and mostly not at all).
//
// Two structural facts drive the strategy:
//
//  1. VerifyRoutePrelude1Signatures signs the TRANSCRIPT = HopPreludeTranscriptHash(suite,
//     binding, p0, p1.Unsigned()) — i.e. p0 plus p1 with its signature fields zeroed —
//     NOT the relay descriptor. So mutating the descriptor (RoleFlags/RelayID/EpochID/
//     SupportedSuiteIDs) changes the descriptor hash but not the transcript, and the
//     descriptor-bound checks (408/415/418) fire before the signature check at 425.
//     Likewise, mutating a p0 field that no earlier validator inspects (ClientNonce at
//     402, RequestedRouteModeID at 422) changes the transcript, but the target branch
//     fires before 425. Every late branch 402-437 is therefore reachable by perturbing
//     exactly one field of the already-signed fixture (signedRoutePreludeVerification
//     Input) without regenerating any signature. This is the opposite of the
//     deployment.go situation, where the descriptor hash gates everything.
//
//  2. RoutePrelude1.ValidateStructural (bootstrap.go:441) already enforces
//     MsgType==MsgRoutePrelude1 and validateVersionKnown (which accepts ONLY Version20),
//     so the re-checks at 372-374 (MsgType) and 375-377 (Version) inside
//     VerifyRoutePrelude1Signatures are unreachable after 369 passes — DEAD by design.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). Each rejection case asserts exactly one error so the failure is
// attributable to the perturbed field alone. New helpers are each referenced by >=2
// tests so there is no U1000 (staticcheck U1000 flags unused package-level helpers and
// is a required CI check).
//
// Uncovered blocks (measured count 0 before this file):
//   - PreviousHopFullTranscriptHash (27): WriteVarint(suite) overflow path 33-35.
//   - RouteHopBinding (39): WriteOpaqueFixed(ClientNonce,32) length path 50-52.
//   - DecodePrivatePrelude (134): r.Err short-input 159-161, trailing-bytes 162-164.
//   - SealPrivatePrelude (168): RoutePreludeWrapContext error 170-172, Encode(private)
//     error 185-187.
//   - OpenPrivatePrelude (207): OpenRoutePrelude AEAD error 212-214.
//   - OpenAndVerifyPrivatePrelude (243): OpenPrivatePrelude propagation 245-247.
//   - OpenAndVerifyPrivatePreludeWithWrapNonceCache (266): propagation 268-270.
//   - WrapNonceReplayCache.InsertIfAbsent (306): nil receiver 307-309, malformed key
//     311-313 (also covers routeWrapNonceReplayKey 332-334).
//   - HopPreludeTranscriptHash (348): Encode(p0) error 350-352, Encode(p1.Unsigned())
//     error 354-356.
//   - validateRoutePreludeMetadata (442): response/request mismatch 446-448, server
//     nonce length 449-451.
//   - ValidateRoutePreludeHybridShares (455): client/server classical + client/server
//     ML-KEM malformed 456-467.
//   - ValidatePrivatePreludeHeader (471): version check 475-477. (The MsgType check
//     472-474 and the extensions check 478-480 are already covered by
//     TestOpenPrivatePreludeRejectsMalformedPrivateHeader and
//     TestValidatePrivatePreludeHeaderRejectsUnknownCriticalExtension — not
//     duplicated.)
//   - containsUint64 (484): the not-found return 490.
//   - VerifyRoutePrelude1Signatures (365): the decision cascade 366-437 reachable via
//     single-field mutations of the signed fixture (see plan above).
//
// Dead-by-design (documented, not covered):
//   - VerifyRoutePrelude1Signatures 372-374 (MsgType re-check) and 375-377 (Version
//     re-check). ValidateStructural at 369 already enforces MsgType==MsgRoutePrelude1 and
//     validateVersionKnown accepts only Version20, so after 369 passes both re-checks
//     are always false. Reaching them would require a RoutePrelude1 that fails
//     ValidateStructural yet passes the re-check, which is impossible.
//
// Out of scope (require a successful AEAD open / real key derivation, not pure
// validators):
//   - SealPrivatePrelude 189-191 (SealRoutePrelude error). SealRoutePrelude only fails
//     through the same RoutePreludeWrapKeyIV path that SealPrivatePrelude already
//     validated at 169; AES-256-GCM seal with a valid 32-byte key and 12-byte nonce never
//     errors. The branch guards a wire-format mismatch no constructible input produces.
//   - OpenPrivatePrelude 216-239 (post-open header/context/share checks). Reaching
//     them requires OpenRoutePrelude to succeed, i.e. a real route-wrap key derivation
//     and a legitimately sealed prelude.
//   - OpenAndVerifyPrivatePrelude 257-262 and WithWrapNonceCache 271-293 (binding +
//     access-hint verification): require a successful open.
//
// No context.Context, no deprecated APIs.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// routeCovMaxVarint exceeds wire.MaxVarint (1<<62 - 1), so WriteVarint/VarintLen reject
// it. Used by the encoder-overflow branches of PreviousHopFullTranscriptHash (33),
// HopPreludeTranscriptHash (350/354), SealPrivatePrelude (185), and
// VerifyRoutePrelude1Signatures (415/422) — >=5 references, so not U1000.
const routeCovMaxVarint uint64 = ^uint64(0)

// routeCovEncodablePrivatePrelude returns a PrivatePrelude that round-trips cleanly
// through protocol.Encode + DecodePrivatePrelude using fixed bytes (no real key
// generation). It feeds the DecodePrivatePrelude trailing/round-trip cases and the
// HopPreludeTranscriptHash p0-overflow case — >=2 references, so not U1000.
func routeCovEncodablePrivatePrelude() PrivatePrelude {
	return PrivatePrelude{
		MsgType:                        registry.MsgRoutePrelude0,
		Version:                        registry.Version20,
		RouteInstanceID:                1,
		HopIndex:                       0,
		PreviousHopRelayDescriptorHash: rb(0x11, 48),
		NextRelayDescriptorHash:        rb(0x12, 48),
		RoutePreludeWrapContext:        rb(0x13, 48),
		PreviousHopFullTranscriptHash:  rb(0x14, 48),
		ClientNonceForThisHop:          rb(0x15, 32),
		OfferedSuites:                  []uint64{registry.SuiteHybrid768AESGCM},
		ClientClassicalEphPub:          rb(0x16, 65),
		ClientMLKEMEncapsulationKey:    rb(0x17, 32),
		HintIssuerID:                   rb(0x18, 16),
		RelayBucketID:                  rb(0x19, 16),
		HintEpochID:                    7,
		HintSelector:                   rb(0x1a, 16),
		AccessHint:                     rb(0x1b, 16),
		RequestedRouteModeID:           registry.RouteSplit2,
		CoverShapeHintID:               registry.ShapeNormal,
	}
}

// routeCovMatchingEnvelope returns a RoutePreludeEnvelope whose visible fields mirror
// env (so validateEnvelopeInput passes) and whose SealedRoutePrelude0 is garbage (so
// OpenRoutePrelude fails the AEAD open). It feeds the OpenPrivatePrelude open-error
// case and, with one field perturbed, the two OpenAndVerify* propagation cases — >=3
// references, so not U1000.
func routeCovMatchingEnvelope(env EnvelopeInput) protocol.RoutePreludeEnvelope {
	return protocol.RoutePreludeEnvelope{
		RouteInstanceID:                env.RouteInstanceID,
		HopIndex:                       env.HopIndex,
		PreviousHopRelayDescriptorHash: append([]byte(nil), env.PreviousHopRelayDescriptorHash...),
		NextRelayDescriptorHash:        append([]byte(nil), env.NextRelayDescriptorHash...),
		HintIssuerID:                   append([]byte(nil), env.HintIssuerID...),
		RelayBucketID:                  append([]byte(nil), env.RelayBucketID...),
		HintEpochID:                    env.HintEpochID,
		HintSelector:                   append([]byte(nil), env.HintSelector...),
		WrapSuiteID:                    env.WrapSuiteID,
		WrapNonce:                      append([]byte(nil), env.WrapNonce...),
		SealedRoutePrelude0:            []byte("garbage"),
	}
}

func TestRoutePureEncodersRejectOverflow(t *testing.T) {
	// PreviousHopFullTranscriptHash 33-35: suite varint out of range.
	if _, err := PreviousHopFullTranscriptHash(routeCovMaxVarint, rb(0, 32)); err == nil {
		t.Fatalf("PreviousHopFullTranscriptHash(maxVarint): expected error, got nil")
	}

	// RouteHopBinding 50-52: ClientNonce not 32 bytes (all other fixed fields valid).
	in := HopBindingInput{
		RouteInstanceID:                1,
		HopIndex:                       0,
		PreviousHopFullTranscriptHash:  rb(0, 48),
		PreviousHopRelayDescriptorHash: rb(0, 48),
		NextRelayDescriptorHash:        rb(0, 48),
		RoutePreludeWrapContext:        rb(0, 48),
		ClientNonceForThisHop:          rb(0, 31),
	}
	if _, err := RouteHopBinding(in); err == nil || !strings.Contains(err.Error(), "fixed opaque length") {
		t.Fatalf("RouteHopBinding(short nonce): err = %v, want fixed opaque length", err)
	}
}

func TestDecodePrivatePreludeRejectsShortAndTrailing(t *testing.T) {
	// 159-161: empty input leaves the reader in error.
	if _, err := DecodePrivatePrelude(nil); err == nil {
		t.Fatalf("DecodePrivatePrelude(nil): expected error, got nil")
	}

	valid, err := protocol.Encode(routeCovEncodablePrivatePrelude())
	if err != nil {
		t.Fatalf("encode base prelude: %v", err)
	}

	// Sanity: a clean encoding decodes without error (guards against a wrong-branch
	// false positive where the base itself fails to round-trip).
	if _, err := DecodePrivatePrelude(valid); err != nil {
		t.Fatalf("DecodePrivatePrelude(valid): unexpected error %v", err)
	}

	// 162-164: a valid encoding plus a trailing byte is rejected.
	trailing := append(append([]byte(nil), valid...), 0xff)
	_, err = DecodePrivatePrelude(trailing)
	if err == nil || !strings.Contains(err.Error(), "trailing private prelude bytes") {
		t.Fatalf("DecodePrivatePrelude(trailing): err = %v, want trailing private prelude bytes", err)
	}
}

func TestWrapNonceReplayCacheRejectsNilAndMalformed(t *testing.T) {
	// 307-309: nil receiver.
	var nilCache *WrapNonceReplayCache
	if _, err := nilCache.InsertIfAbsent(protocol.RoutePreludeEnvelope{}); err == nil ||
		!strings.Contains(err.Error(), "missing route wrap nonce replay cache") {
		t.Fatalf("nilCache.InsertIfAbsent: err = %v, want missing route wrap nonce replay cache", err)
	}

	// 311-313 + routeWrapNonceReplayKey 332-334: HintIssuerID not 16 bytes makes the
	// replay-key encoder reject the fixed opaque length.
	c := NewWrapNonceReplayCache()
	bad := protocol.RoutePreludeEnvelope{
		HintIssuerID:  rb(0, 15),
		RelayBucketID: rb(0, 16),
		HintSelector:  rb(0, 16),
		WrapNonce:     rb(0, 16),
	}
	if _, err := c.InsertIfAbsent(bad); err == nil ||
		!strings.Contains(err.Error(), "fixed opaque length") {
		t.Fatalf("InsertIfAbsent(bad issuer): err = %v, want fixed opaque length", err)
	}
}

func TestHopPreludeTranscriptHashRejectsOverflow(t *testing.T) {
	// 350-352: Encode(p0) fails because RequestedRouteModeID overflows the varint range.
	// p1 is never encoded (p0 errors first), so a zero value suffices.
	p0 := routeCovEncodablePrivatePrelude()
	p0.RequestedRouteModeID = routeCovMaxVarint
	if _, err := HopPreludeTranscriptHash(registry.SuiteHybrid768AESGCM, rb(0, 48), p0, protocol.RoutePrelude1{}); err == nil ||
		!strings.Contains(err.Error(), "varint out of range") {
		t.Fatalf("HopPreludeTranscriptHash(p0 overflow): err = %v, want varint out of range", err)
	}

	// 354-356: p0 encodes cleanly, then Encode(p1.Unsigned()) fails because
	// RouteInstanceID overflows. The fixed-length fields before it must be exact.
	p0 = routeCovEncodablePrivatePrelude()
	p1 := protocol.RoutePrelude1{
		MsgType:                        registry.MsgRoutePrelude1,
		Version:                        registry.Version20,
		RouteInstanceID:                routeCovMaxVarint,
		PreviousHopRelayDescriptorHash: rb(0, 48),
		NextRelayDescriptorHash:        rb(0, 48),
		ServerNonce:                    rb(0, 32),
	}
	if _, err := HopPreludeTranscriptHash(registry.SuiteHybrid768AESGCM, rb(0, 48), p0, p1); err == nil ||
		!strings.Contains(err.Error(), "varint out of range") {
		t.Fatalf("HopPreludeTranscriptHash(p1 overflow): err = %v, want varint out of range", err)
	}
}

func TestValidateRoutePreludeMetadataRejectsMismatch(t *testing.T) {
	base := PrivatePrelude{
		RouteInstanceID:                1,
		HopIndex:                       0,
		PreviousHopRelayDescriptorHash: rb(0, 48),
		NextRelayDescriptorHash:        rb(0, 48),
	}

	// 446-448: response RouteInstanceID differs from request.
	p1 := protocol.RoutePrelude1{
		RouteInstanceID:                2,
		HopIndex:                       0,
		PreviousHopRelayDescriptorHash: rb(0, 48),
		NextRelayDescriptorHash:        rb(0, 48),
		ServerNonce:                    rb(0, 32),
	}
	if err := validateRoutePreludeMetadata(base, p1); err == nil ||
		!strings.Contains(err.Error(), "does not match request") {
		t.Fatalf("metadata mismatch: err = %v, want does not match request", err)
	}

	// 449-451: metadata matches but ServerNonce is not 32 bytes.
	p1 = protocol.RoutePrelude1{
		RouteInstanceID:                1,
		HopIndex:                       0,
		PreviousHopRelayDescriptorHash: rb(0, 48),
		NextRelayDescriptorHash:        rb(0, 48),
		ServerNonce:                    rb(0, 31),
	}
	if err := validateRoutePreludeMetadata(base, p1); err == nil ||
		!strings.Contains(err.Error(), "server nonce length") {
		t.Fatalf("short server nonce: err = %v, want server nonce length", err)
	}

	// Valid metadata is accepted.
	p1 = protocol.RoutePrelude1{
		RouteInstanceID:                1,
		HopIndex:                       0,
		PreviousHopRelayDescriptorHash: rb(0, 48),
		NextRelayDescriptorHash:        rb(0, 48),
		ServerNonce:                    rb(0, 32),
	}
	if err := validateRoutePreludeMetadata(base, p1); err != nil {
		t.Fatalf("valid metadata: unexpected error %v", err)
	}
}

func TestValidateRoutePreludeHybridSharesRejectsMalformed(t *testing.T) {
	// The signed fixture carries real, valid ECDH and ML-KEM shares for the 768 suite;
	// perturb exactly one share per case so the branch under test is the one that fires.
	base := signedRoutePreludeVerificationInput(t)
	suite := base.Suite

	// 456-458: client classical share malformed.
	p0 := base.Prelude0
	p0.ClientClassicalEphPub = []byte{0x01}
	if err := ValidateRoutePreludeHybridShares(suite, p0, base.Prelude1); err == nil ||
		!strings.Contains(err.Error(), "malformed client classical share") {
		t.Fatalf("client classical: err = %v, want malformed client classical share", err)
	}

	// 459-461: server classical share malformed (client classical still valid).
	p1 := base.Prelude1
	p1.ServerClassicalEphPub = []byte{0x01}
	if err := ValidateRoutePreludeHybridShares(suite, base.Prelude0, p1); err == nil ||
		!strings.Contains(err.Error(), "malformed server classical share") {
		t.Fatalf("server classical: err = %v, want malformed server classical share", err)
	}

	// 462-464: client ML-KEM encapsulation key malformed (both classical valid).
	p0 = base.Prelude0
	p0.ClientMLKEMEncapsulationKey = []byte{0x01}
	if err := ValidateRoutePreludeHybridShares(suite, p0, base.Prelude1); err == nil ||
		!strings.Contains(err.Error(), "malformed client ML-KEM share") {
		t.Fatalf("client ML-KEM: err = %v, want malformed client ML-KEM share", err)
	}

	// 465-467: server ML-KEM ciphertext malformed (all prior shares valid).
	p1 = base.Prelude1
	p1.ServerMLKEMCiphertextToClient = []byte{0x01}
	if err := ValidateRoutePreludeHybridShares(suite, base.Prelude0, p1); err == nil ||
		!strings.Contains(err.Error(), "malformed server ML-KEM share") {
		t.Fatalf("server ML-KEM: err = %v, want malformed server ML-KEM share", err)
	}

	// Valid shares are accepted.
	if err := ValidateRoutePreludeHybridShares(suite, base.Prelude0, base.Prelude1); err != nil {
		t.Fatalf("valid shares: unexpected error %v", err)
	}
}

func TestValidatePrivatePreludeHeaderDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		private PrivatePrelude
		wantSub string
	}{
		// 472-474: wrong message type (also covered indirectly via OpenPrivatePrelude;
		// included here to document the decision table).
		{"wrong message type", PrivatePrelude{MsgType: 0xBAD, Version: registry.Version20}, "private prelude message type"},
		// 475-477: wrong version (the previously-uncovered gap).
		{"wrong version", PrivatePrelude{MsgType: registry.MsgRoutePrelude0, Version: 0xBAD}, "private prelude version"},
		// Valid header accepted.
		{"valid header", PrivatePrelude{MsgType: registry.MsgRoutePrelude0, Version: registry.Version20}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePrivatePreludeHeader(tc.private)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestContainsUint64(t *testing.T) {
	// 490: not-found return.
	if containsUint64([]uint64{1, 2, 3}, 4) {
		t.Fatal("containsUint64([1,2,3], 4) = true, want false")
	}
	if !containsUint64([]uint64{1, 2, 3}, 2) {
		t.Fatal("containsUint64([1,2,3], 2) = false, want true")
	}
}

func TestSealAndOpenPrivatePreludeErrorPaths(t *testing.T) {
	env := routeTestEnvelope()

	// SealPrivatePrelude 170-172: RoutePreludeWrapContext rejects a non-route wrap suite.
	badSuiteEnv := env
	badSuiteEnv.WrapSuiteID = 0xBAD
	if _, err := SealPrivatePrelude(badSuiteEnv, routeTestPrivatePrelude(t, env)); err == nil {
		t.Fatalf("SealPrivatePrelude(bad wrap suite): expected error, got nil")
	}

	// SealPrivatePrelude 185-187: wrap context ok, but Encode(private) fails because an
	// un-overwritten field (OfferedSuites) overflows the varint range.
	overflowPrivate := routeTestPrivatePrelude(t, env)
	overflowPrivate.OfferedSuites = []uint64{routeCovMaxVarint}
	if _, err := SealPrivatePrelude(env, overflowPrivate); err == nil ||
		!strings.Contains(err.Error(), "varint out of range") {
		t.Fatalf("SealPrivatePrelude(overflow offered suites): err = %v, want varint out of range", err)
	}

	// OpenPrivatePrelude 212-214: envelope matches env (validateEnvelopeInput passes),
	// but the sealed prelude is garbage so the AEAD open fails.
	if _, err := OpenPrivatePrelude(env, routeCovMatchingEnvelope(env)); err == nil {
		t.Fatalf("OpenPrivatePrelude(garbage sealed): expected error, got nil")
	}

	// OpenAndVerifyPrivatePrelude 245-247: a mismatched envelope fails
	// validateEnvelopeInput inside OpenPrivatePrelude, which propagates.
	mismatched := routeCovMatchingEnvelope(env)
	mismatched.RouteInstanceID = env.RouteInstanceID + 1
	cred := routeTestAccessHintCredential(env)
	if _, _, err := OpenAndVerifyPrivatePrelude(nil, env, mismatched, cred, 0, 0); err == nil {
		t.Fatalf("OpenAndVerifyPrivatePrelude(mismatched envelope): expected error, got nil")
	}

	// OpenAndVerifyPrivatePreludeWithWrapNonceCache 268-270: same propagation path.
	if _, _, err := OpenAndVerifyPrivatePreludeWithWrapNonceCache(nil, NewWrapNonceReplayCache(), env, mismatched, cred, 0, 0); err == nil {
		t.Fatalf("OpenAndVerifyPrivatePreludeWithWrapNonceCache(mismatched envelope): expected error, got nil")
	}
}

func TestVerifyRoutePrelude1SignaturesDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*RoutePreludeVerificationInput)
		wantSub    string // non-empty => assert err contains this substring
		wantAnyErr bool   // true => assert err != nil without a substring (crypto/wire msg)
	}{
		{"valid signatures accepted", nil, "", false},
		// 366-368: private header invalid (version 0 fails the header check before any
		// p1/descriptor check).
		{"private header invalid", func(in *RoutePreludeVerificationInput) { in.Prelude0.Version = 0 }, "private prelude version", false},
		// 369-371: Prelude1 fails ValidateStructural (message type).
		{"prelude1 structural invalid", func(in *RoutePreludeVerificationInput) { in.Prelude1.MsgType = 0xBAD }, "message type", false},
		// 378-380: SelectedSuite != Suite.
		{"selected suite mismatch", func(in *RoutePreludeVerificationInput) { in.Suite = registry.SuiteHybrid1024AESGCM }, "selected suite mismatch", false},
		// 381-383: suite matches but was not offered by the client.
		{"selected suite not offered", func(in *RoutePreludeVerificationInput) {
			in.Suite = registry.SuiteHybrid1024AESGCM
			in.Prelude1.SelectedSuite = registry.SuiteHybrid1024AESGCM
		}, "selected suite was not offered", false},
		// 384-386: suite offered but not in the descriptor's supported list.
		{"selected suite not supported by descriptor", func(in *RoutePreludeVerificationInput) {
			in.Descriptor.SupportedSuiteIDs = []uint64{registry.SuiteHybrid1024AESGCM}
		}, "selected suite is not supported by descriptor", false},
		// 387-389: metadata mismatch (RouteInstanceID differs).
		{"metadata mismatch", func(in *RoutePreludeVerificationInput) {
			in.Prelude1.RouteInstanceID = in.Prelude0.RouteInstanceID + 1
		}, "does not match request", false},
		// 390-392: malformed client classical share.
		{"malformed hybrid shares", func(in *RoutePreludeVerificationInput) {
			in.Prelude0.ClientClassicalEphPub = []byte{0x01}
		}, "malformed client classical share", false},
		// 402-404: RouteHopBinding fails (ClientNonce wrong length).
		{"route hop binding error", func(in *RoutePreludeVerificationInput) {
			in.Prelude0.ClientNonceForThisHop = rb(0x45, 31)
		}, "fixed opaque length", false},
		// 408-410: NextRelayEpochID != descriptor EpochID (NowUnix stays 0 so the
		// validity-window check at 411 is skipped).
		{"next relay epoch mismatch", func(in *RoutePreludeVerificationInput) {
			in.Descriptor.EpochID = 99
		}, "next relay epoch mismatch", false},
		// 415-417: RelayDescriptorHash fails to encode (SupportedSuiteIDs overflow;
		// 768 still present so 384 passes).
		{"descriptor hash computation error", func(in *RoutePreludeVerificationInput) {
			in.Descriptor.SupportedSuiteIDs = append(in.Descriptor.SupportedSuiteIDs, routeCovMaxVarint)
		}, "varint out of range", false},
		// 418-420: descriptor hash recomputes to a different value (RelayID changed);
		// p0/p1 still carry the original hash.
		{"descriptor hash mismatch", func(in *RoutePreludeVerificationInput) {
			in.Descriptor.RelayID = append([]byte(nil), in.Descriptor.RelayID...)
			in.Descriptor.RelayID[0] ^= 0xff
		}, "next relay descriptor hash mismatch", false},
		// 422-424: HopPreludeTranscriptHash fails (RequestedRouteModeID overflow; not
		// part of RouteHopBinding or the descriptor hash, so all prior checks pass).
		{"transcript hash error", func(in *RoutePreludeVerificationInput) {
			in.Prelude0.RequestedRouteModeID = routeCovMaxVarint
		}, "varint out of range", false},
		// 425-427: classical signature absent.
		{"missing classical signature", func(in *RoutePreludeVerificationInput) {
			in.Prelude1.ServerPreludeSignatureClassical = nil
		}, "missing classical route prelude signature", false},
		// 428-430: classical signature present but invalid (corrupted).
		{"classical signature invalid", func(in *RoutePreludeVerificationInput) {
			sig := append([]byte(nil), in.Prelude1.ServerPreludeSignatureClassical...)
			if len(sig) > 0 {
				sig[0] ^= 0xff
			}
			in.Prelude1.ServerPreludeSignatureClassical = sig
		}, "", true},
		// 431-434: PQ required but signature absent.
		{"missing PQ signature when required", func(in *RoutePreludeVerificationInput) {
			in.RequirePQ = true
			in.Prelude1.ServerPreludeSignaturePQ = nil
		}, "missing PQ route prelude signature", false},
		// 435-437: PQ signature present but invalid (garbage verified against the
		// ECDSA epoch-auth key).
		{"PQ signature invalid", func(in *RoutePreludeVerificationInput) {
			in.Prelude1.ServerPreludeSignaturePQ = rb(0xff, 64)
		}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := signedRoutePreludeVerificationInput(t)
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			transcript, err := VerifyRoutePrelude1Signatures(in)
			switch {
			case tc.wantSub != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
				}
			case tc.wantAnyErr:
				if err == nil {
					t.Fatalf("%s: expected error, got nil", tc.name)
				}
			default:
				if err != nil {
					t.Fatalf("%s: expected nil error, got %v", tc.name, err)
				}
				if len(transcript) == 0 {
					t.Fatalf("%s: expected non-empty transcript, got empty", tc.name)
				}
			}
		})
	}
}
