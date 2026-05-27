package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/aurora-protocol/aurora-core/admission"
	auroraclient "github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/config"
	auroracover "github.com/aurora-protocol/aurora-core/cover"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/evaluation"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/issuerd"
	auroraops "github.com/aurora-protocol/aurora-core/ops"
	auroraplatform "github.com/aurora-protocol/aurora-core/platform"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	aurorarelease "github.com/aurora-protocol/aurora-core/release"
	auroraroute "github.com/aurora-protocol/aurora-core/route"
	auroraserver "github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/transport"
	corevectors "github.com/aurora-protocol/aurora-core/vectors"
	"github.com/aurora-protocol/aurora-core/wire"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "vectors":
		err = vectors(os.Args[2:], os.Stdout)
	case "capabilities":
		capabilities()
	case "negative-vectors-check":
		err = negativeVectorsCheck(os.Stdout)
	case "active-probes":
		err = activeProbes(os.Stdout)
	case "classifier-check":
		err = classifierCheck(os.Stdout)
	case "evaluation-check":
		err = evaluationCheck(os.Stdout)
	case "deployment-security-check":
		err = deploymentSecurityCheck(os.Stdout)
	case "platform-check":
		err = platformCheck(os.Stdout)
	case "packaging-check":
		err = packagingCheck(os.Stdout)
	case "release-check":
		err = releaseCheck(os.Stdout)
	case "proof-check":
		err = proofCheck(os.Stdout)
	case "issuer-check":
		err = issuerCheck(os.Stdout)
	case "issuerd-check":
		err = issuerDCheck(os.Stdout)
	case "issuerd-http-check":
		err = issuerDHTTPCheck(os.Stdout)
	case "server-check":
		err = serverCheck(os.Stdout)
	case "client-check":
		err = clientCheck(os.Stdout)
	case "p0-p8-check":
		err = p0P8Check(os.Stdout)
	case "cover-check":
		err = coverCheck(os.Stdout)
	case "crypto-check":
		err = cryptoCheck(os.Stdout)
	case "wire-check":
		err = wireCheck(os.Stdout)
	case "transport-check":
		err = transportCheck(os.Stdout)
	case "flow-check":
		err = flowCheck(os.Stdout)
	case "route-check":
		err = routeCheck(os.Stdout)
	case "host-build-check":
		err = hostBuildCheck(os.Args[2:], os.Stdout)
	case "check-config":
		if len(os.Args) != 3 {
			err = fmt.Errorf("check-config requires a path")
			break
		}
		err = checkConfig(os.Args[2])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: auroractl <vectors [--check [path]|--real-crypto [--check [path]]|--negative [--check [path]]]|capabilities|negative-vectors-check|active-probes|classifier-check|evaluation-check|deployment-security-check|platform-check|packaging-check|release-check|proof-check|issuer-check|issuerd-check|issuerd-http-check|server-check|client-check|p0-p8-check|cover-check|crypto-check|wire-check|transport-check|flow-check|route-check|host-build-check [--portable|--apple-simulator|--all]|check-config>")
}

const structuralVectorSnapshotPath = "vectors/structural_vectors.txt"
const realCryptoVectorSnapshotPath = "vectors/real_crypto_vectors.txt"
const negativeVectorSnapshotPath = "vectors/negative_vectors.txt"

func vectors(args []string, w io.Writer) error {
	if len(args) == 0 {
		return writeVectors(w)
	}
	switch args[0] {
	case "--check":
		if len(args) > 2 {
			return fmt.Errorf("vectors: too many arguments")
		}
		path := structuralVectorSnapshotPath
		if len(args) == 2 {
			path = args[1]
		}
		return checkVectorSnapshot("structural", path, writeVectors)
	case "--real-crypto":
		switch len(args) {
		case 1:
			return writeRealCryptoVectors(w)
		case 2:
			if args[1] != "--check" {
				return fmt.Errorf("vectors: unknown real-crypto option %q", args[1])
			}
			return checkVectorSnapshot("real crypto", realCryptoVectorSnapshotPath, writeRealCryptoVectors)
		case 3:
			if args[1] != "--check" {
				return fmt.Errorf("vectors: unknown real-crypto option %q", args[1])
			}
			return checkVectorSnapshot("real crypto", args[2], writeRealCryptoVectors)
		default:
			return fmt.Errorf("vectors: too many arguments")
		}
	case "--negative":
		switch len(args) {
		case 1:
			return writeNegativeVectors(w)
		case 2:
			if args[1] != "--check" {
				return fmt.Errorf("vectors: unknown negative option %q", args[1])
			}
			return checkVectorSnapshot("negative", negativeVectorSnapshotPath, writeNegativeVectors)
		case 3:
			if args[1] != "--check" {
				return fmt.Errorf("vectors: unknown negative option %q", args[1])
			}
			return checkVectorSnapshot("negative", args[2], writeNegativeVectors)
		default:
			return fmt.Errorf("vectors: too many arguments")
		}
	default:
		return fmt.Errorf("vectors: unknown option %q", args[0])
	}
}

func checkVectorSnapshot(kind, path string, write func(io.Writer) error) error {
	var generated bytes.Buffer
	if err := write(&generated); err != nil {
		return err
	}
	snapshot, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !equalTextSnapshot(snapshot, generated.Bytes()) {
		return fmt.Errorf("vectors: %s vector snapshot drift; regenerate %s", kind, path)
	}
	return nil
}

func equalTextSnapshot(snapshot, generated []byte) bool {
	if bytes.Equal(snapshot, generated) {
		return true
	}
	return bytes.Equal(normalizeLineEndings(snapshot), normalizeLineEndings(generated))
}

func normalizeLineEndings(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

func writeRealCryptoVectors(w io.Writer) error {
	metadata, err := corevectors.GenerateTrustMetadataRealCryptoBundle()
	if err != nil {
		return err
	}
	firstHop, err := corevectors.GenerateFirstHopRealCryptoBundle()
	if err != nil {
		return err
	}
	firstHopControl, err := corevectors.GenerateFirstHopControlAndApplicationRealCryptoBundle()
	if err != nil {
		return err
	}
	routePrelude, err := corevectors.GenerateRoutePreludeRealCryptoBundle()
	if err != nil {
		return err
	}
	exitLayer, err := corevectors.GenerateExitLayerPacketRealCryptoBundle()
	if err != nil {
		return err
	}
	keyUpdate, err := corevectors.GenerateKeyUpdateRealCryptoBundle()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "metadata_directory_authority_classical_key:", metadata.DirectoryAuthorityClassicalKey)
	fmt.Fprintln(w, "metadata_directory_authority_pq_key:", metadata.DirectoryAuthorityPQKey)
	fmt.Fprintln(w, "metadata_directory_consensus:", metadata.DirectoryConsensus)
	fmt.Fprintln(w, "metadata_directory_consensus_hash:", metadata.DirectoryConsensusHash)
	fmt.Fprintln(w, "metadata_directory_consensus_signature_input_classical:", metadata.DirectoryConsensusSignatureInputClass)
	fmt.Fprintln(w, "metadata_directory_consensus_signature_input_pq:", metadata.DirectoryConsensusSignatureInputPQ)
	fmt.Fprintln(w, "metadata_directory_consensus_signature_classical:", metadata.DirectoryConsensusSignatureClassical)
	fmt.Fprintln(w, "metadata_directory_consensus_signature_pq:", metadata.DirectoryConsensusSignaturePQ)
	fmt.Fprintln(w, "metadata_relay_descriptor:", metadata.RelayDescriptor)
	fmt.Fprintln(w, "metadata_relay_descriptor_hash:", metadata.RelayDescriptorHash)
	fmt.Fprintln(w, "metadata_relay_descriptor_signature_input:", metadata.RelayDescriptorSignatureInput)
	fmt.Fprintln(w, "metadata_relay_descriptor_signature_classical:", metadata.RelayDescriptorSignatureClassical)
	fmt.Fprintln(w, "metadata_relay_descriptor_signature_pq:", metadata.RelayDescriptorSignaturePQ)
	fmt.Fprintln(w, "metadata_cover_template:", metadata.CoverTemplate)
	fmt.Fprintln(w, "metadata_cover_template_hash:", metadata.CoverTemplateHash)
	fmt.Fprintln(w, "metadata_cover_template_family_signature_input:", metadata.CoverTemplateFamilySignatureInput)
	fmt.Fprintln(w, "metadata_cover_template_instance_signature_input:", metadata.CoverTemplateInstanceSignatureInput)
	fmt.Fprintln(w, "metadata_cover_template_family_signature:", metadata.CoverTemplateFamilySignature)
	fmt.Fprintln(w, "metadata_cover_template_instance_signature:", metadata.CoverTemplateInstanceSignature)
	fmt.Fprintln(w, "first_hop_client_classical_eph_pub:", firstHop.ClientClassicalEphPub)
	fmt.Fprintln(w, "first_hop_server_classical_eph_pub:", firstHop.ServerClassicalEphPub)
	fmt.Fprintln(w, "first_hop_classical_shared_secret:", firstHop.ClassicalSharedSecret)
	fmt.Fprintln(w, "first_hop_client_mlkem_encapsulation_key:", firstHop.ClientMLKEMEncapsulationKey)
	fmt.Fprintln(w, "first_hop_server_mlkem_ciphertext_to_client:", firstHop.ServerMLKEMCiphertextToClient)
	fmt.Fprintln(w, "first_hop_mlkem_shared_secret:", firstHop.MLKEMSharedSecret)
	fmt.Fprintln(w, "first_hop_server_pq_public_key:", firstHop.ServerPQPublicKey)
	fmt.Fprintln(w, "first_hop_server_prelude_signature_classical:", firstHop.ServerPreludeSignatureClassical)
	fmt.Fprintln(w, "first_hop_server_prelude_signature_pq:", firstHop.ServerPreludeSignaturePQ)
	fmt.Fprintln(w, "first_hop_cover_prelude0:", firstHop.CoverPrelude0)
	fmt.Fprintln(w, "first_hop_cover_prelude1:", firstHop.CoverPrelude1)
	fmt.Fprintln(w, "first_hop_prelude_transcript_hash:", firstHop.PreludeTranscriptHash)
	fmt.Fprintln(w, "first_hop_handshake_binding_context:", firstHopControl.HandshakeBindingContext)
	fmt.Fprintln(w, "first_hop_cover_capsule1_plaintext:", firstHopControl.CoverCapsule1Plaintext)
	fmt.Fprintln(w, "first_hop_cover_capsule1_ciphertext:", firstHopControl.CoverCapsule1Ciphertext)
	fmt.Fprintln(w, "first_hop_client_finished:", firstHopControl.ClientFinished)
	fmt.Fprintln(w, "first_hop_cover_capsule2_plaintext:", firstHopControl.CoverCapsule2Plaintext)
	fmt.Fprintln(w, "first_hop_cover_capsule2_ciphertext:", firstHopControl.CoverCapsule2Ciphertext)
	fmt.Fprintln(w, "first_hop_server_finished:", firstHopControl.ServerFinished)
	fmt.Fprintln(w, "first_hop_application_transcript_hash:", firstHopControl.ApplicationTranscriptHash)
	fmt.Fprintln(w, "first_hop_client_app_secret0:", firstHopControl.ClientAppSecret0)
	fmt.Fprintln(w, "first_hop_client_app_key0:", firstHopControl.ClientAppKey0)
	fmt.Fprintln(w, "first_hop_client_app_iv0:", firstHopControl.ClientAppIV0)
	fmt.Fprintln(w, "first_hop_first_application_packet_frame_block:", firstHopControl.FirstApplicationPacketFrameBlock)
	fmt.Fprintln(w, "first_hop_first_application_packet:", firstHopControl.FirstApplicationPacket)
	fmt.Fprintln(w, "first_hop_first_application_packet_auth_tag:", firstHopControl.FirstApplicationPacketAuthTag)
	fmt.Fprintln(w, "split2_route_prelude_envelope:", routePrelude.RoutePreludeEnvelope)
	fmt.Fprintln(w, "split2_route_prelude0_plaintext:", routePrelude.RoutePrelude0Plaintext)
	fmt.Fprintln(w, "split2_route_prelude1:", routePrelude.RoutePrelude1)
	fmt.Fprintln(w, "split2_route_hop_binding:", routePrelude.RouteHopBinding)
	fmt.Fprintln(w, "split2_route_prelude_transcript_hash:", routePrelude.RoutePreludeTranscriptHash)
	fmt.Fprintln(w, "split2_route_client_classical_eph_pub:", routePrelude.RouteClientClassicalEphPub)
	fmt.Fprintln(w, "split2_route_server_classical_eph_pub:", routePrelude.RouteServerClassicalEphPub)
	fmt.Fprintln(w, "split2_route_classical_shared_secret:", routePrelude.RouteClassicalSharedSecret)
	fmt.Fprintln(w, "split2_route_client_mlkem_encapsulation_key:", routePrelude.RouteClientMLKEMEncapsulationKey)
	fmt.Fprintln(w, "split2_route_server_mlkem_ciphertext_to_client:", routePrelude.RouteServerMLKEMCiphertext)
	fmt.Fprintln(w, "split2_route_mlkem_shared_secret:", routePrelude.RouteMLKEMSharedSecret)
	fmt.Fprintln(w, "split2_route_server_pq_public_key:", routePrelude.RouteServerPQPublicKey)
	fmt.Fprintln(w, "split2_route_server_prelude_signature_classical:", routePrelude.RouteServerPreludeSignatureClassical)
	fmt.Fprintln(w, "split2_route_server_prelude_signature_pq:", routePrelude.RouteServerPreludeSignaturePQ)
	fmt.Fprintln(w, "exit_layer_route_capsule1_plaintext:", exitLayer.RouteCapsule1Plaintext)
	fmt.Fprintln(w, "exit_layer_route_client_finished:", exitLayer.RouteClientFinished)
	fmt.Fprintln(w, "exit_layer_route_capsule2_plaintext:", exitLayer.RouteCapsule2Plaintext)
	fmt.Fprintln(w, "exit_layer_route_server_finished:", exitLayer.RouteServerFinished)
	fmt.Fprintln(w, "exit_layer_application_transcript_hash:", exitLayer.RouteApplicationTranscriptHash)
	fmt.Fprintln(w, "exit_layer_client_app_key0:", exitLayer.ClientAppKey0)
	fmt.Fprintln(w, "exit_layer_client_app_iv0:", exitLayer.ClientAppIV0)
	fmt.Fprintln(w, "exit_layer_frame_block:", exitLayer.ExitLayerFrameBlock)
	fmt.Fprintln(w, "exit_layer_aurora_packet:", exitLayer.ExitLayerAuroraPacket)
	fmt.Fprintln(w, "exit_layer_packet_ciphertext:", exitLayer.ExitLayerPacketCiphertext)
	fmt.Fprintln(w, "exit_layer_packet_auth_tag:", exitLayer.ExitLayerPacketAuthTag)
	fmt.Fprintln(w, "key_update_frame:", keyUpdate.KeyUpdateFrame)
	fmt.Fprintln(w, "key_update_frame_block:", keyUpdate.KeyUpdateFrameBlock)
	fmt.Fprintln(w, "key_update_ack:", keyUpdate.KeyUpdateACK)
	fmt.Fprintln(w, "key_update_ack_frame_block:", keyUpdate.KeyUpdateACKFrameBlock)
	fmt.Fprintln(w, "key_update_context:", keyUpdate.KeyUpdateContext)
	fmt.Fprintln(w, "key_update_current_app_secret:", keyUpdate.CurrentAppSecret)
	fmt.Fprintln(w, "key_update_next_app_secret:", keyUpdate.NextAppSecret)
	fmt.Fprintln(w, "key_update_next_key:", keyUpdate.NextKey)
	fmt.Fprintln(w, "key_update_next_iv:", keyUpdate.NextIV)
	return nil
}

func writeVectors(w io.Writer) error {
	control := auroracrypto.ControlAADInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		MsgType:                         registry.MsgCoverCapsule1,
		RouteInstanceID:                 1,
		HandshakeBindingContext:         repeated(0xaa, 48),
		PreludeTranscriptHashForThisHop: repeated(0xbb, 48),
	}
	preimage, err := auroracrypto.ControlAADPreimage(control)
	if err != nil {
		return err
	}
	aad, err := auroracrypto.ControlAAD(control)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "control_aad_preimage:", hex.EncodeToString(preimage))
	fmt.Fprintln(w, "control_aad:", hex.EncodeToString(aad))

	route := auroracrypto.RouteWrapInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: repeated(0x41, 48),
		NextRelayDescriptorHash:        repeated(0x42, 48),
		HintIssuerID:                   repeated(0x34, 16),
		RelayBucketID:                  repeated(0x35, 16),
		HintEpochID:                    7,
		HintSelector:                   repeated(0x31, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      repeated(0x32, 16),
		HintSecret:                     repeated(0x33, 32),
	}
	context, key, iv, wrapAAD, sealed, err := auroracrypto.SealRoutePrelude(route, repeated(0x44, 16))
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "route_prelude_wrap_context:", hex.EncodeToString(context))
	fmt.Fprintln(w, "route_prelude_wrap_key:", hex.EncodeToString(key))
	fmt.Fprintln(w, "route_prelude_wrap_iv:", hex.EncodeToString(iv))
	fmt.Fprintln(w, "route_wrap_aad:", hex.EncodeToString(wrapAAD))
	fmt.Fprintln(w, "route_wrap_ciphertext_tag:", hex.EncodeToString(sealed))

	pk := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       repeated(0x04, 65),
	}
	encodedPK, err := wire.Encode(pk)
	if err != nil {
		return err
	}
	keyID := auroracrypto.Truncate128(auroracrypto.PreHashLabel("aurora v2.0 authority key id", encodedPK))
	akr := protocol.AuthorityKeyRecord{
		AuthorityID:    repeated(0x11, 16),
		AuthorityKeyID: keyID,
		AuthorityRole:  1,
		PublicKey:      pk,
		ValidFromUnix:  1700000000,
		ValidUntilUnix: 1800000000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageAllKnownAuthority,
	}
	encodedAKR, err := wire.Encode(akr)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "public_key_record:", hex.EncodeToString(encodedPK))
	fmt.Fprintln(w, "authority_key_id:", hex.EncodeToString(keyID))
	fmt.Fprintln(w, "authority_key_record:", hex.EncodeToString(encodedAKR))
	bundle, err := corevectors.GenerateStructuralBundle()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "object_signature:", bundle.ObjectSignature)
	fmt.Fprintln(w, "object_signature_unsigned:", bundle.ObjectSignatureUnsigned)
	fmt.Fprintln(w, "object_signature_hash:", bundle.ObjectSignatureHash)
	fmt.Fprintln(w, "directory_consensus:", bundle.DirectoryConsensus)
	fmt.Fprintln(w, "relay_descriptor:", bundle.RelayDescriptor)
	fmt.Fprintln(w, "cover_template:", bundle.CoverTemplate)
	fmt.Fprintln(w, "flow_open:", bundle.FlowOpen)
	fmt.Fprintln(w, "udp_target_confirm:", bundle.UDPTargetConfirm)
	fmt.Fprintln(w, "flow_close:", bundle.FlowClose)
	return nil
}

func capabilities() {
	capabilitiesReport(os.Stdout)
}

func capabilitiesReport(w io.Writer) {
	fmt.Fprintln(w, "implemented:")
	fmt.Fprintln(w, "- Section 9 wire scalar, opaque, vector, and struct encoding with opaque8/16/24 boundary test coverage, vector element-count boundary coverage, reserved enum rejection coverage, bootstrap critical extension rejection coverage, and all-object canonical round-trip coverage")
	fmt.Fprintln(w, "- Appendix A registries")
	fmt.Fprintln(w, "- Appendix B.4 and B.5 structural vectors")
	fmt.Fprintln(w, "- DirectoryConsensus, RelayDescriptor, CoverTemplate trust hashes, signature inputs, and strict ML-DSA authority quorum")
	fmt.Fprintln(w, "- AES-256-GCM, HKDF labels, SHA-384/SHA-512 suite hashes, ML-KEM wrappers, ML-KEM provider agreement, and ML-DSA verification")
	fmt.Fprintln(w, "- first-hop prelude transcript hashing, sealed control capsules, Finished messages, application secret derivation, and first packet sealing")
	fmt.Fprintln(w, "- signed directory, relay descriptor, and cover-template real-crypto vectors")
	fmt.Fprintln(w, "- first-hop prelude, first-hop control/application packets, split-2 route-prelude, exit-layer packet, and KEY_UPDATE / KEY_UPDATE_ACK real-crypto vectors with ECDH, ML-KEM, ECDSA, ML-DSA, AEAD, and packet artifacts")
	fmt.Fprintln(w, "- P2 negative vector harness for malformed public keys, wrong key_encoding, wrong signatures, wrong AEAD tag, and replay")
	fmt.Fprintln(w, "- AccessHint, replay keys, packet protection, FrameBlock, FLOW_* validation, KEY_UPDATE")
	fmt.Fprintln(w, "- policy profiles, PAL scoring, PACE reference behavior, local config parsing, P0 host build matrix, HTTP CONNECT/SOCKS5 local interface handlers, client FLOW_OPEN frame emission, relay frame-block flow demux, fake-IP mapped UDP flow integration, UDP target confirm TTL enforcement, synthetic local DNS forwarder responses, negative-cache-aware local DNS responses, P5 split-route conformance harness, P6 proxy-flow conformance harness, shared opaque carrier session adapters, P7 transport conformance harness, append-only file replay cache, protocol decode fuzz harness, HTTP cover-origin gateway handler, gateway-backed active-probe harness, DPI/classifier baseline harness, external evaluation evidence verifier, deployment security assessment evidence verifier, platform adapter conformance profiles, packet-to-core platform ABI forwarding, packet, DNS, socket, and network-path platform ABI forwarding, platform packaging and entitlement conformance matrix, release readiness evidence verifier, Privacy Pass Blind RSA production proof harness, private proof-type validation gates, issuer operations conformance harness, issuer service readiness harness, issuer HTTP daemon readiness harness, runnable Linux server harness, live HTTP/HTTPS server-client interop harness, binary issuer verifier mTLS handler, cover-origin deployment conformance harness")
	fmt.Fprintln(w, "not production-complete:")
	fmt.Fprintln(w, "- external live issuer deployment, real signed platform release execution/device provisioning, real deployment security assessment, external DPI/classifier evaluation, external active-probe evaluation")
}

func writeNegativeVectors(w io.Writer) error {
	report, err := corevectors.GenerateNegativeVectorReport()
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, corevectors.FormatNegativeVectorReport(report))
	return err
}

func negativeVectorsCheck(w io.Writer) error {
	report, err := corevectors.GenerateNegativeVectorReport()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, corevectors.FormatNegativeVectorReport(report)); err != nil {
		return err
	}
	if !report.Passed {
		return fmt.Errorf("negative-vectors-check failed rejection coverage")
	}
	return nil
}

func cryptoCheck(w io.Writer) error {
	results, err := auroracrypto.CheckMLKEMBackendAgreement()
	if err != nil {
		return err
	}
	passed := true
	for _, result := range results {
		passed = passed && result.Passed
	}
	fmt.Fprintf(w, "crypto_check passed=%t backends=%d\n", passed, len(results))
	for _, result := range results {
		fmt.Fprintf(
			w,
			"scheme %s passed=%t stdlib=%s cross_check=%s public_key_bytes=%d ciphertext_bytes=%d shared_secret_bytes=%d\n",
			result.Scheme,
			result.Passed,
			result.StandardLibraryBackend,
			result.CrossCheckBackend,
			result.PublicKeyBytes,
			result.CiphertextBytes,
			result.SharedSecretBytes,
		)
	}
	if !passed {
		return fmt.Errorf("crypto-check failed provider agreement")
	}
	return nil
}

func activeProbes(w io.Writer) error {
	cases := failure.ActiveProbeCases()
	report, err := failure.RunActiveProbeHarness(cases)
	if err != nil {
		return err
	}
	gatewayReport, err := relay.RunGatewayActiveProbeHarness(cases)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "active_probe_baseline passed=%t cases=%d\n", report.Passed, len(report.Cases))
	fmt.Fprintf(
		w,
		"gateway_active_probe passed=%t cases=%d normal_responses=%d forwarded=%d sidecar_forwarded=%d failure_logs=%d\n",
		gatewayReport.Passed,
		len(gatewayReport.Cases),
		gatewayReport.NormalResponses,
		gatewayReport.ForwardedRequests,
		gatewayReport.SidecarForwardedRequests,
		gatewayReport.FailureLogs,
	)
	fmt.Fprintf(w, "canonical %s\n", formatProbeSurface(report.CanonicalSurface))
	for _, finding := range report.Cases {
		fmt.Fprintf(w, "case %s passed=%t %s\n", finding.Name, finding.Passed, formatProbeSurface(finding.Surface))
	}
	if !report.Passed || !gatewayReport.Passed {
		return fmt.Errorf("active-probes failed neutrality check")
	}
	return nil
}

func classifierCheck(w io.Writer) error {
	samples, err := auroracover.DefaultClassifierBaseline()
	if err != nil {
		return err
	}
	report, err := auroracover.EvaluateClassifierBaseline(samples)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"classifier_baseline passed=%t samples=%d features=%d distinguishers=%d forbidden_markers=%d\n",
		report.Passed,
		len(report.Samples),
		report.FeatureCount,
		len(report.Distinguishers),
		len(report.ForbiddenMarkers),
	)
	for _, sample := range report.Samples {
		fmt.Fprintf(
			w,
			"classifier_sample %s passed=%t distinguishers=%d forbidden_markers=%d\n",
			sample.Name,
			sample.Passed,
			len(sample.Distinguishers),
			len(sample.ForbiddenMarkers),
		)
	}
	if !report.Passed {
		return fmt.Errorf("classifier-check failed cover indistinguishability baseline")
	}
	return nil
}

func evaluationCheck(w io.Writer) error {
	report, err := evaluation.VerifyExternalEvaluationEvidence(evaluation.ExternalEvaluationHarnessBundle())
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"evaluation_check passed=%t classifier=%t active_probe=%t interoperability=%t security_reviews=%t release_gates=%t deployment_security=%t findings=%d\n",
		report.Passed,
		report.ClassifierEvidence,
		report.ActiveProbeEvidence,
		report.InteroperabilityEvidence,
		report.SecurityReviewEvidence,
		report.ReleaseGateEvidence,
		report.DeploymentSecurityAssessmentEvidence,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "evaluation_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("evaluation-check failed external evidence conformance")
	}
	return nil
}

func deploymentSecurityCheck(w io.Writer) error {
	bundle := evaluation.ExternalEvaluationHarnessBundle()
	report, err := evaluation.VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		return err
	}
	assessment := bundle.DeploymentSecurityAssessment
	fmt.Fprintf(
		w,
		"deployment_security_check passed=%t independent=%t real_deployment=%t issuer=%t relays=%t directory=%t cover_origins=%t client_update=%t outage_drills=%t redaction=%t open_critical=%d open_high=%d findings=%d\n",
		report.DeploymentSecurityAssessmentEvidence,
		assessment.IndependentAssessor,
		assessment.RealDeployment,
		assessment.IssuerScope,
		assessment.RelayScope,
		assessment.DirectoryScope,
		assessment.CoverOriginScope,
		assessment.ClientUpdateScope,
		assessment.VerifierOutageDrill && assessment.CoverOriginFailoverDrill && assessment.ReplayAbuseDrill,
		assessment.OperationalTelemetryRedacted,
		assessment.CriticalOpen,
		assessment.HighOpen,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "deployment_security_finding %s\n", finding)
	}
	if !report.DeploymentSecurityAssessmentEvidence {
		return fmt.Errorf("deployment-security-check failed assessment evidence conformance")
	}
	return nil
}

func platformCheck(w io.Writer) error {
	report, err := auroraplatform.VerifyAdapterBlueprints(auroraplatform.AdapterBlueprints())
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"platform_adapter_check passed=%t platforms=%d failures=%d\n",
		report.Passed,
		len(report.Platforms),
		len(report.Failures),
	)
	for _, platform := range report.Platforms {
		fmt.Fprintf(
			w,
			"platform %s passed=%t packet=%s local_proxy=%t no_crypto=%t boundary=%t\n",
			platform.Kind,
			platform.Passed,
			platform.PacketMode,
			platform.LocalProxyFallback,
			platform.NoCryptoState,
			platform.BoundaryComplete,
		)
	}
	if !report.Passed {
		return fmt.Errorf("platform-check failed adapter conformance")
	}
	return nil
}

func packagingCheck(w io.Writer) error {
	report, err := auroraplatform.VerifyPackagingBlueprints(auroraplatform.PackagingBlueprints())
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"packaging_check passed=%t targets=%d release_targets=%d entitlement_free_ci=%d thin_adapters=%d no_crypto=%d mock_packet_flow=%d failures=%d\n",
		report.Passed,
		len(report.Targets),
		report.ReleaseTargets,
		report.EntitlementFreeCITargets,
		report.ThinAdapterTargets,
		report.NoCryptoTargets,
		report.MockPacketFlowTargets,
		len(report.Failures),
	)
	for _, target := range report.Targets {
		fmt.Fprintf(
			w,
			"packaging_target %s passed=%t kind=%s release=%t ci=%t packet=%s entitlement_free=%t mock_packet_flow=%t thin_adapter=%t no_crypto=%t local_proxy=%t\n",
			target.Name,
			target.Passed,
			target.Kind,
			target.Release,
			target.CI,
			target.PacketMode,
			target.EntitlementFree,
			target.UsesMockPacketFlow,
			target.UsesThinAdapter,
			target.NoCryptoState,
			target.LocalProxyFallback,
		)
	}
	for _, failure := range report.Failures {
		fmt.Fprintf(w, "packaging_failure target=%s field=%s\n", failure.TargetName, failure.Field)
	}
	if !report.Passed {
		return fmt.Errorf("packaging-check failed platform packaging conformance")
	}
	return nil
}

func releaseCheck(w io.Writer) error {
	report, err := aurorarelease.RunReleaseReadinessHarness(200)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"release_check passed=%t artifacts=%d update_roles=%d signatures=%t provenance=%t reproducible=%t signed_update=%t provisioning=%t incident_response=%t findings=%d\n",
		report.Passed,
		report.ReleaseArtifacts,
		report.UpdateRoles,
		report.ArtifactSignatures,
		report.Provenance,
		report.ReproducibleBuilds,
		report.SignedUpdatePipeline,
		report.DeviceProvisioning,
		report.IncidentResponsePlan,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "release_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("release-check failed release readiness")
	}
	return nil
}

func proofCheck(w io.Writer) error {
	report, err := admission.RunProductionProofHarness(100)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"proof_check passed=%t blind_rsa=%t blind_rsa_tamper_rejected=%t blind_rsa_origin_policy_rejected=%t voprf_proof_only_rejected=%t lab_static_rejected=%t\n",
		report.Passed,
		report.BlindRSA2048Verified,
		report.BlindRSAAuthenticatorTamperRejected,
		report.BlindRSAOriginPolicyRejected,
		report.VOPRFProofOnlyRejected,
		report.LabStaticTokenRejected,
	)
	if !report.Passed {
		return fmt.Errorf("proof-check failed production proof harness")
	}
	return nil
}

func issuerCheck(w io.Writer) error {
	report, err := auroraops.RunIssuerOperationsHarness(200)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"issuer_ops_check passed=%t metadata=%t hint_provisioning=%t atomic_replay_store=%t verifier_fail_closed=%t redacted_logs=%t public_relay_policy=%t findings=%d\n",
		report.Passed,
		report.MetadataVerified,
		report.HintProvisioning,
		report.AtomicReplayStore,
		report.VerifierFailClosed,
		report.SensitiveLogsRedacted,
		report.PublicRelayProofPolicy,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "issuer_ops_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("issuer-check failed operations conformance")
	}
	return nil
}

func issuerDCheck(w io.Writer) error {
	report, err := issuerd.RunServiceReadinessHarness(200)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"issuerd_check passed=%t metadata_published=%t blind_rsa_issue_verify=%t voprf_verifier=%t voprf_fail_closed=%t atomic_spent_store=%t redacted_logs=%t metadata_hash_bound_token=%t findings=%d\n",
		report.Passed,
		report.MetadataPublished,
		report.BlindRSAIssuedAndVerified,
		report.VOPRFVerifierService,
		report.VOPRFVerifierFailClosed,
		report.AtomicSpentTokenStore,
		report.SensitiveLogsRedacted,
		report.MetadataHashBoundToken,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "issuerd_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("issuerd-check failed service readiness")
	}
	return nil
}

func issuerDHTTPCheck(w io.Writer) error {
	report, err := issuerd.RunHTTPReadinessHarness(200)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"issuerd_http_check passed=%t health=%t metadata=%t blind_rsa=%t voprf=%t voprf_fail_closed=%t binary_mtls=%t spend=%t duplicate_rejected=%t redacted_failures=%t method_restrictions=%t findings=%d\n",
		report.Passed,
		report.HealthEndpoint,
		report.MetadataEndpoint,
		report.BlindRSAIssueEndpoint,
		report.VOPRFVerifyEndpoint,
		report.VOPRFFailClosedEndpoint,
		report.BinaryVerifierMTLSEndpoint,
		report.SpendEndpoint,
		report.DuplicateSpendRejected,
		report.RedactedFailureBodies,
		report.MethodRestrictions,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "issuerd_http_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("issuerd-http-check failed daemon readiness")
	}
	return nil
}

func serverCheck(w io.Writer) error {
	report, err := auroraserver.RunReadinessHarness(200)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"server_check passed=%t cover=%t cover_neutral_unknown=%t cover_neutral_issuer_path=%t cover_neutral_health_path=%t issuer_metadata=%t blind_rsa_issue=%t packet_exchange=%t findings=%d\n",
		report.Passed,
		report.CoverEndpoint,
		report.CoverNeutralUnknownPath,
		report.CoverNeutralIssuerPath,
		report.CoverNeutralHealthPath,
		report.IssuerMetadataCarrier,
		report.BlindRSAIssueCarrier,
		report.PacketExchangeEndpoint,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "server_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("server-check failed runnable server readiness")
	}
	return nil
}

func clientCheck(w io.Writer) error {
	report, err := auroraserver.RunClientInteropHarness(200)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, auroraserver.FormatClientInteropReport(report)); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "client_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("client-check failed live server-client interop")
	}
	return nil
}

type p0P8Gate struct {
	Name string
	Run  func(io.Writer) error
}

func p0P8Check(w io.Writer) error {
	return runP0P8Check(w, defaultP0P8Gates())
}

func defaultP0P8Gates() []p0P8Gate {
	return []p0P8Gate{
		{Name: "host-build-portable", Run: func(w io.Writer) error { return hostBuildCheck([]string{"--portable"}, w) }},
		{Name: "vectors-structural", Run: func(w io.Writer) error { return vectors([]string{"--check"}, w) }},
		{Name: "vectors-real-crypto", Run: func(w io.Writer) error { return vectors([]string{"--real-crypto", "--check"}, w) }},
		{Name: "vectors-negative", Run: func(w io.Writer) error { return vectors([]string{"--negative", "--check"}, w) }},
		{Name: "negative-vectors", Run: negativeVectorsCheck},
		{Name: "crypto", Run: cryptoCheck},
		{Name: "wire", Run: wireCheck},
		{Name: "transport", Run: transportCheck},
		{Name: "flow", Run: flowCheck},
		{Name: "route", Run: routeCheck},
		{Name: "active-probes", Run: activeProbes},
		{Name: "classifier", Run: classifierCheck},
		{Name: "evaluation", Run: evaluationCheck},
		{Name: "deployment-security", Run: deploymentSecurityCheck},
		{Name: "platform", Run: platformCheck},
		{Name: "packaging", Run: packagingCheck},
		{Name: "release", Run: releaseCheck},
		{Name: "proof", Run: proofCheck},
		{Name: "issuer-ops", Run: issuerCheck},
		{Name: "issuerd", Run: issuerDCheck},
		{Name: "issuerd-http", Run: issuerDHTTPCheck},
		{Name: "server", Run: serverCheck},
		{Name: "client", Run: clientCheck},
		{Name: "cover", Run: coverCheck},
	}
}

func runP0P8Check(w io.Writer, gates []p0P8Gate) error {
	failures := 0
	for _, gate := range gates {
		var output bytes.Buffer
		err := gate.Run(&output)
		passed := err == nil
		if !passed {
			failures++
		}
		if _, writeErr := fmt.Fprintf(w, "p0_p8_gate %s passed=%t\n", gate.Name, passed); writeErr != nil {
			return writeErr
		}
		if output.Len() > 0 {
			if _, writeErr := io.Copy(w, &output); writeErr != nil {
				return writeErr
			}
			if !bytes.HasSuffix(output.Bytes(), []byte("\n")) {
				if _, writeErr := fmt.Fprintln(w); writeErr != nil {
					return writeErr
				}
			}
		}
		if err != nil {
			if _, writeErr := fmt.Fprintf(w, "p0_p8_finding %s: %v\n", gate.Name, err); writeErr != nil {
				return writeErr
			}
		}
	}
	passed := failures == 0
	if _, err := fmt.Fprintf(w, "p0_p8_check passed=%t gates=%d failures=%d\n", passed, len(gates), failures); err != nil {
		return err
	}
	if !passed {
		return fmt.Errorf("p0-p8-check failed verification gates")
	}
	return nil
}

func coverCheck(w io.Writer) error {
	report, err := relay.RunCoverOriginDeploymentHarness(150)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		w,
		"cover_origin_check passed=%t template=%t gateway_owned_failure=%t sidecar_failure=%t pass_through=%t oversize_failure=%t active_probe=%t findings=%d\n",
		report.Passed,
		report.TemplateValidated,
		report.GatewayOwnedFailureNeutral,
		report.SidecarFailureSanitized,
		report.PassThroughForwarded,
		report.OversizeFailureNeutral,
		report.ActiveProbeNeutral,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "cover_origin_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("cover-check failed deployment conformance")
	}
	return nil
}

func wireCheck(w io.Writer) error {
	carriers := []transport.CarrierRequestInput{
		publicCarrierInput(registry.MethodWebH2Stream, "cover.example", "/assets/app.bin", http.Header{"Content-Type": []string{"application/octet-stream"}}),
		publicCarrierInput(registry.MethodWebH1WS, "cover.example", "/events/stream", http.Header{"User-Agent": []string{"Mozilla/5.0"}}),
		publicCarrierInput(registry.MethodShadowOrigin, "static.example", "/catalog/segment", http.Header{"Accept": []string{"*/*"}}),
		publicCarrierInput(registry.MethodWebH3Stream, "media.example", "/session/42", http.Header{"Content-Type": []string{"application/octet-stream"}}),
		publicH3DatagramCarrierInput(),
	}
	passed := true
	results := make([]wireCheckResult, 0, len(carriers))
	for _, input := range carriers {
		built, err := transport.BuildCarrierRequest(input)
		result := wireCheckResult{Name: input.Plan.Carrier.Name, Passed: err == nil}
		if err == nil {
			if marker := visibleCarrierMarker(built); marker != "" {
				result.Passed = false
				result.Detail = marker
			}
		} else {
			result.Detail = err.Error()
		}
		passed = passed && result.Passed
		results = append(results, result)
	}
	fmt.Fprintf(w, "public_wire_check passed=%t carriers=%d\n", passed, len(results))
	for _, result := range results {
		if result.Detail == "" {
			fmt.Fprintf(w, "carrier %s passed=%t\n", result.Name, result.Passed)
			continue
		}
		fmt.Fprintf(w, "carrier %s passed=%t detail=%s\n", result.Name, result.Passed, result.Detail)
	}
	if !passed {
		return fmt.Errorf("wire-check found forbidden public marker")
	}
	return nil
}

func transportCheck(w io.Writer) error {
	report, err := transport.RunCarrierConformance()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, transport.FormatCarrierConformanceReport(report)); err != nil {
		return err
	}
	if !report.Passed {
		return fmt.Errorf("transport-check failed carrier conformance")
	}
	return nil
}

func flowCheck(w io.Writer) error {
	report, err := auroraclient.RunProxyFlowConformance()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, auroraclient.FormatProxyFlowConformanceReport(report)); err != nil {
		return err
	}
	if !report.Passed {
		return fmt.Errorf("flow-check failed proxy-flow conformance")
	}
	return nil
}

func routeCheck(w io.Writer) error {
	report, err := auroraroute.RunSplitRouteConformance()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, auroraroute.FormatSplitRouteConformanceReport(report)); err != nil {
		return err
	}
	if !report.Passed {
		return fmt.Errorf("route-check failed split-route conformance")
	}
	return nil
}

func hostBuildCheck(args []string, w io.Writer) error {
	return hostBuildCheckWithRunner(args, w, execHostBuildRunner{})
}

func hostBuildCheckWithRunner(args []string, w io.Writer, runner auroraplatform.HostBuildRunner) error {
	targets, err := hostBuildTargetsForArgs(args)
	if err != nil {
		return err
	}
	report := auroraplatform.VerifyHostBuildMatrix(targets, []string{"./..."}, runner)
	failures := 0
	for _, result := range report.Results {
		if !result.Passed {
			failures++
		}
	}
	fmt.Fprintf(w, "host_build_check passed=%t targets=%d failures=%d\n", report.Passed, report.Targets, failures)
	for _, result := range report.Results {
		fmt.Fprintf(
			w,
			"host_build_target %s passed=%t goos=%s goarch=%s cgo=%s\n",
			result.Target.Name,
			result.Passed,
			result.Target.GOOS,
			result.Target.GOARCH,
			result.Target.CGOEnabled,
		)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "host_build_finding %s\n", finding)
	}
	if !report.Passed {
		return fmt.Errorf("host-build-check failed host build matrix")
	}
	return nil
}

func hostBuildTargetsForArgs(args []string) ([]auroraplatform.HostBuildTarget, error) {
	if len(args) == 0 {
		return auroraplatform.PortableHostBuildTargets(), nil
	}
	if len(args) != 1 {
		return nil, fmt.Errorf("host-build-check: too many arguments")
	}
	switch args[0] {
	case "--portable":
		return auroraplatform.PortableHostBuildTargets(), nil
	case "--apple-simulator":
		return auroraplatform.AppleSimulatorHostBuildTargets(), nil
	case "--all":
		targets := auroraplatform.PortableHostBuildTargets()
		targets = append(targets, auroraplatform.AppleSimulatorHostBuildTargets()...)
		return targets, nil
	default:
		return nil, fmt.Errorf("host-build-check: unknown option %q", args[0])
	}
}

type execHostBuildRunner struct{}

func (execHostBuildRunner) RunHostBuild(target auroraplatform.HostBuildTarget, args []string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(),
		"GOOS="+target.GOOS,
		"GOARCH="+target.GOARCH,
		"CGO_ENABLED="+target.CGOEnabled,
	)
	return cmd.CombinedOutput()
}

type wireCheckResult struct {
	Name   string
	Passed bool
	Detail string
}

func publicCarrierInput(method uint64, authority, path string, header http.Header) transport.CarrierRequestInput {
	return transport.CarrierRequestInput{
		Plan: transport.CarrierPlan{
			Carrier: transport.Carrier{MethodID: method, Name: publicCarrierName(method)},
			UDPMode: transport.UDPOverStreamFallback,
		},
		Template:       publicCarrierTemplate(method),
		RequestClassID: 1,
		NeedCapsule:    true,
		Scheme:         "https",
		Authority:      authority,
		Path:           path,
		Header:         header,
		Payload:        []byte{0x80, 0x01},
		WebSocketKeySeed: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		},
	}
}

func publicH3DatagramCarrierInput() transport.CarrierRequestInput {
	input := publicCarrierInput(registry.MethodWebH3ExtDgram, "media.example", "/items/live", http.Header{"Accept": []string{"*/*"}})
	input.Plan.UDPMode = transport.UDPNativeDatagram
	input.Template.H3Profile = protocol.H3CoverProfile{
		ProfileID:                  7,
		SupportsH3Datagram:         true,
		SupportsWebTransportH3:     true,
		WebTransportProfileID:      1,
		QUICDatagramRequired:       true,
		DatagramSizeDistributionID: repeated(0x22, 16),
		DatagramRateDistributionID: repeated(0x33, 16),
	}
	input.H3DatagramSettingsOK = true
	input.QUICMaxDatagramFrameSize = 1200
	return input
}

func publicCarrierTemplate(method uint64) protocol.CoverTemplate {
	return protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{{
		ClassID:             1,
		ClassType:           registry.RequestGatewayOwnedSlot,
		AllowedMethodFamily: method,
		PathTemplateID:      repeated(0x11, 16),
		MayCarryPrelude:     true,
		MayCarryCapsule:     true,
	}}}
}

func publicCarrierName(method uint64) string {
	switch method {
	case registry.MethodWebH2Stream:
		return "web.h2.stream"
	case registry.MethodWebH1WS:
		return "web.h1.ws"
	case registry.MethodShadowOrigin:
		return "web.shadow-origin"
	case registry.MethodWebH3Stream:
		return "web.h3.stream"
	case registry.MethodWebH3ExtDgram:
		return "web.h3.ext-dgram"
	default:
		return "unknown"
	}
}

func visibleCarrierMarker(built transport.BuiltCarrierRequest) string {
	if built.Request == nil {
		return "missing request"
	}
	values := []string{built.Request.Host, built.Request.URL.Host, built.Request.URL.Path, built.ProtocolToken}
	for _, value := range values {
		if marker := forbiddenPublicWireMarker(value); marker != "" {
			return marker
		}
	}
	for key, values := range built.Request.Header {
		if marker := forbiddenPublicWireMarker(key); marker != "" {
			return marker
		}
		for _, value := range values {
			if marker := forbiddenPublicWireMarker(value); marker != "" {
				return marker
			}
		}
	}
	return ""
}

func forbiddenPublicWireMarker(value string) string {
	lower := strings.ToLower(value)
	for _, marker := range forbiddenPublicWireMarkers {
		if strings.Contains(lower, marker) {
			return marker
		}
	}
	return ""
}

var forbiddenPublicWireMarkers = []string{
	"aurora",
	"proxy",
	"vpn",
	"gfw",
	"china",
	"auth",
	"tunnel",
	"bridge",
	"relay",
	"policy",
	"adversarial",
	"dpi",
}

func formatProbeSurface(surface failure.ProbeSurface) string {
	return fmt.Sprintf("http_status=%d close_code=%d tls_alert=%d quic_close=%d websocket_close=%d timing_class=%s reflected_log=%s",
		surface.HTTPStatus,
		surface.CloseCode,
		surface.TLSAlertClass,
		surface.QUICCloseCode,
		surface.WebSocketCloseCode,
		surface.TimingClass,
		surface.ReflectedLog,
	)
}

func checkConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	cfg, err := config.Parse(f)
	if err != nil {
		return err
	}
	fmt.Printf("ok profile=%s route=%s speed=%s effective=%s\n", cfg.Profile, cfg.Route, cfg.Speed, cfg.EffectiveProfile("normal").Name)
	return nil
}

func repeated(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
