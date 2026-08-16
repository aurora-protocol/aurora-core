package admission

// Adversarial white-box coverage for three reachable count-0 branches in
// admission/proof_harness.go: the extension deep-copy loop of
// cloneAdmissionProof (208-223) and two error-propagation branches of
// bindProofToIssuerMetadata (163-177). The rest of proof_harness's count-0
// lines are dead-by-design and documented below (not claimed).
//
// cloneAdmissionProof deep-copies every slice field of an AdmissionProof so a
// caller can mutate the clone without aliasing the original. The per-extension
// Body copy loop at :219-221 runs only when the proof carries at least one
// extension; the production harness (RunProductionProofHarness) and its test
// fixture (signedBlindRSAProofForTest) both build extension-less proofs, so
// the loop body is unreached. A proof with one extension, cloned and then
// mutated on the clone's extension Body, leaves the original Body unchanged
// only if the Body slice was deep-copied.
//
// bindProofToIssuerMetadata rebinds a proof to an issuer metadata by hashing
// the metadata, decoding the proof's existing TokenPublicMetadata, setting the
// metadata hash, and re-encoding. Its three error branches are:
//
//	:165  auroratrust.IssuerMetadataHash(metadata) -> protocol.Encode of the
//	      metadata's unsigned form. IssuerMetadata.EncodeTo writes IssuerName
//	      as WriteOpaque16 (max 0xffff), so an oversized IssuerName makes the
//	      Encode fail and the hash surfaces it.
//	:169  protocol.DecodeAuroraTokenMetadataBytes(proof.TokenPublicMetadata).
//	      A malformed (truncated/garbage) TokenPublicMetadata fails the wire
//	      decode.
//	:174  protocol.Encode(tokenMetadata) after re-setting IssuerMetadataHash.
//
// :165 and :169 are reachable by direct calls with crafted inputs. :174 is
// dead-by-design: tokenMetadata is the decoded form of a valid encoding, so its
// Opaque16 fields (IssuerName, OriginInfo) are bounded by the source encoding
// (<= 0xffff) and IssuerMetadataHash is a fixed 48-byte PreHash, so the
// re-encode cannot overflow any write.
//
// Targets covered (previously count-0):
//
//   - cloneAdmissionProof:219-221 — the per-extension Body deep-copy loop. A
//     proof with one extension is cloned; mutating the clone's extension Body
//     leaves the original Body unchanged, proving the deep copy.
//   - bindProofToIssuerMetadata:165-167 — an oversized IssuerName (70000 bytes
//     on an otherwise-valid metadata) fails IssuerMetadataHash's Encode at the
//     WriteOpaque16 write, surfaced before the token-metadata decode runs.
//   - bindProofToIssuerMetadata:169-171 — a valid metadata paired with a proof
//     whose TokenPublicMetadata is []byte{0xFF} fails
//     DecodeAuroraTokenMetadataBytes at the wire read, surfaced after
//     IssuerMetadataHash succeeds.
//
// Dead-by-design (documented, NOT claimed):
//   - bindProofToIssuerMetadata:174-176 — Encode of decoded-then-rehashed
//     tokenMetadata. Decoded Opaque16 fields are bounded by the source encoding
//     (<= 0xffff); IssuerMetadataHash is a fixed 48-byte PreHash. The re-encode
//     cannot overflow any write — decoded-then-rehashed-can't-fail-Encode.
//   - signedBlindRSAProof:94 — RFC9577TokenChallengeDigest with fixed valid
//     inputs (ProofType <= 0xffff, non-empty issuerName, 48-byte
//     redemptionContextHash; RFC9577RedemptionContext only errs on len != 48).
//   - signedBlindRSAProof:106 — Encode of the internally-constructed
//     AuroraTokenMetadata, whose fields are all small fixed values.
//   - signedBlindRSAProof:110 — RFC9577AuthenticatorInput with fixed valid
//     inputs (ProofType <= 0xffff, 32-byte TokenNonce/ChallengeDigest/TokenKeyID
//     fixed-width writes).
//   - signedBlindRSAProof:118 — rsa.SignPSS for a freshly generated valid
//     2048-bit key over a SHA-384 digest; cannot error.
//   - marshalRSAPSSPublicKey:184/188 — asn1.Marshal of valid RSA public-key
//     structs (big.Int / int / asn1.ObjectIdentifier / asn1.BitString); none of
//     these types are unsupported, so Marshal cannot error.
//   - RunProductionProofHarness:28 — rsa.GenerateKey(rand.Reader, 2048); 2048-bit
//     RSA key generation does not error in practice.
//   - RunProductionProofHarness:32/36/44/59 — the orchestrator feeds only a
//     freshly generated valid key and valid/derived metadata, so
//     marshalRSAPSSPublicKey, signedBlindRSAProof, and the two
//     bindProofToIssuerMetadata calls (the second with a valid wrongOrigin
//     metadata) all succeed; their error branches are reachable only via
//     direct calls with crafted inputs (covered above for
//     bindProofToIssuerMetadata).
//   - RunProductionProofHarness:40 — blindRSAIssuerMetadata is a pure struct
//     constructor that returns (..., nil) unconditionally, so its error check
//     can never fire.
//
// validProofAndMetadata is referenced by two tests (the :165 and :169 cases),
// so there is no staticcheck U1000 surface; it reuses the in-package
// marshalRSAPSSPublicKeyForTest / signedBlindRSAProofForTest /
// blindRSAIssuerMetadataForTest helpers (each already multi-referenced). The
// cryptography is a single real 2048-bit RSA key per pair of tests (crypto/rand),
// bounded and self-contained: no network, no filesystem, no replay cache, no
// goroutines. No context.Context (no SA1012 surface).

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// validProofAndMetadata returns a validly-signed Blind RSA proof and its
// matching issuer metadata (the bindProofToIssuerMetadata happy-path
// baseline), using the in-package test helpers. The :165 and :169 tests each
// perturb exactly one field of this baseline to trip exactly one error branch.
func validProofAndMetadata(t *testing.T) (protocol.AdmissionProof, protocol.IssuerMetadata) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	keyDER := marshalRSAPSSPublicKeyForTest(t, &priv.PublicKey)
	proof := signedBlindRSAProofForTest(t, priv, keyDER)
	metadata := blindRSAIssuerMetadataForTest(proof, keyDER)
	return proof, metadata
}

func TestCloneAdmissionProofDeepCopiesExtensionBodies(t *testing.T) {
	// 219-221: the per-extension Body deep-copy loop runs only when the proof
	// carries at least one extension; the harness clones extension-less proofs,
	// so the loop body is unreached. Cloning a proof with one extension and then
	// mutating the clone's extension Body must leave the original Body
	// unchanged, which only holds if the Body slice was deep-copied.
	proof := protocol.AdmissionProof{
		Extensions: []protocol.Extension{{
			ExtensionType: 1,
			Body:          []byte("aurora-extension-body"),
		}},
	}
	clone := cloneAdmissionProof(proof)
	if len(clone.Extensions) != 1 {
		t.Fatalf("clone extensions = %d, want 1", len(clone.Extensions))
	}
	if !bytes.Equal(clone.Extensions[0].Body, []byte("aurora-extension-body")) {
		t.Fatalf("clone extension Body = %q, want \"aurora-extension-body\"", clone.Extensions[0].Body)
	}
	clone.Extensions[0].Body[0] ^= 0xFF
	if clone.Extensions[0].Body[0] == 'a' {
		t.Fatal("mutating the clone's extension Body had no effect; clone is not independent")
	}
	if !bytes.Equal(proof.Extensions[0].Body, []byte("aurora-extension-body")) {
		t.Fatalf("mutating the clone's extension Body changed the original: % x", proof.Extensions[0].Body)
	}
}

func TestBindProofToIssuerMetadataRejectsOversizedIssuerName(t *testing.T) {
	// 165-167: IssuerMetadataHash encodes the metadata's unsigned form, and
	// IssuerMetadata.EncodeTo writes IssuerName as WriteOpaque16 (max 0xffff).
	// An oversized IssuerName on an otherwise-valid metadata makes the Encode
	// fail at that write, and bindProofToIssuerMetadata surfaces it before the
	// token-metadata decode runs. The proof argument is irrelevant here because
	// IssuerMetadataHash runs first.
	_, metadata := validProofAndMetadata(t)
	metadata.IssuerName = make([]byte, 70000) // > 0xffff
	_, err := bindProofToIssuerMetadata(protocol.AdmissionProof{}, metadata)
	if err == nil {
		t.Fatal("bindProofToIssuerMetadata(oversized IssuerName) err = nil, want non-nil (IssuerMetadataHash Encode failure)")
	}
	if !strings.Contains(err.Error(), "opaque16 too long") {
		t.Fatalf("bindProofToIssuerMetadata(oversized IssuerName) err = %v, want substring \"opaque16 too long\"", err)
	}
}

func TestBindProofToIssuerMetadataRejectsMalformedTokenMetadata(t *testing.T) {
	// 169-171: a valid metadata (IssuerMetadataHash succeeds) paired with a
	// proof whose TokenPublicMetadata is malformed makes
	// DecodeAuroraTokenMetadataBytes fail at the wire read, and
	// bindProofToIssuerMetadata surfaces it after IssuerMetadataHash succeeds.
	proof, metadata := validProofAndMetadata(t)
	proof.TokenPublicMetadata = []byte{0xFF} // truncated/garbage
	_, err := bindProofToIssuerMetadata(proof, metadata)
	if err == nil {
		t.Fatal("bindProofToIssuerMetadata(malformed TokenPublicMetadata) err = nil, want non-nil (decode failure)")
	}
}
