package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/aurora-protocol/aurora-core/config"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/failure"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
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
		err = vectors(os.Stdout)
	case "capabilities":
		capabilities()
	case "active-probes":
		err = activeProbes(os.Stdout)
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
	fmt.Fprintln(os.Stderr, "usage: auroractl <vectors|capabilities|active-probes|check-config>")
}

func vectors(w io.Writer) error {
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
	fmt.Fprintln(w, "flow_open:", bundle.FlowOpen)
	fmt.Fprintln(w, "udp_target_confirm:", bundle.UDPTargetConfirm)
	fmt.Fprintln(w, "flow_close:", bundle.FlowClose)
	return nil
}

func capabilities() {
	fmt.Println("implemented:")
	fmt.Println("- Section 9 wire scalar, opaque, vector, and struct encoding")
	fmt.Println("- Appendix A registries")
	fmt.Println("- Appendix B.4 and B.5 structural vectors")
	fmt.Println("- DirectoryConsensus, RelayDescriptor, CoverTemplate trust hashes and signature inputs")
	fmt.Println("- AES-256-GCM, HKDF labels, SHA-384/SHA-512 suite hashes, ML-KEM wrappers")
	fmt.Println("- first-hop prelude transcript hashing, Finished messages, and application secret derivation")
	fmt.Println("- AccessHint, replay keys, packet protection, FrameBlock, FLOW_* validation, KEY_UPDATE")
	fmt.Println("- policy profiles, PAL scoring, PACE reference behavior, local config parsing")
	fmt.Println("not production-complete:")
	fmt.Println("- ML-DSA signatures, Privacy Pass production proof verification, cover-origin gateway, active-probe harness, platform adapters, DPI evaluation")
}

func activeProbes(w io.Writer) error {
	report, err := failure.RunActiveProbeHarness(failure.ActiveProbeCases())
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "active_probe_baseline passed=%t cases=%d\n", report.Passed, len(report.Cases))
	fmt.Fprintf(w, "canonical %s\n", formatProbeSurface(report.CanonicalSurface))
	for _, finding := range report.Cases {
		fmt.Fprintf(w, "case %s passed=%t %s\n", finding.Name, finding.Passed, formatProbeSurface(finding.Surface))
	}
	if !report.Passed {
		return fmt.Errorf("active-probes failed neutrality check")
	}
	return nil
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
