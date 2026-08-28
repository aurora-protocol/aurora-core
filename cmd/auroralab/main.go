// Command auroralab mints and serves complete, self-consistent Aurora lab
// deployments for LOCAL LAB TESTING ONLY.
//
// auroralab exists so production clients (Android, Apple, aurorac) can be
// exercised end to end against a LAN-reachable relay without production
// provisioning infrastructure. Every deployment it mints uses freshly
// generated self-signed credentials with convenience validity windows.
// auroralab and everything it mints MUST never be deployed as production
// infrastructure.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/internal/labfixture"
)

// labBanner is printed on every run so the lab-only nature of this binary is
// impossible to miss in logs.
const labBanner = "auroralab: LOCAL LAB TESTING ONLY — mints and serves self-signed lab deployments; NEVER deploy this binary or its output as production infrastructure"

// labNonLoopbackWarning is printed when the operator explicitly exposes the
// lab relay or issuer on a non-loopback address.
const labNonLoopbackWarning = "auroralab: WARNING: binding a non-loopback address exposes this lab deployment to the local network; proceed only on trusted lab networks"

const (
	labIssuerReadTimeout  = 15 * time.Second
	labIssuerWriteTimeout = 15 * time.Second
	labIssuerIdleTimeout  = time.Minute
	labIssuerMaxHeader    = 8 << 10
)

var labSignalContext = defaultLabSignalContext

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, labBanner)
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: auroralab <mint|serve|import-code> [options]")
		return 2
	}
	switch args[0] {
	case "mint":
		return runMint(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "import-code":
		return runImportCode(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "auroralab: unknown command %q; use mint, serve, or import-code\n", args[0])
		return 2
	}
}

type mintConfig struct {
	dir        string
	relayHost  string
	relayPort  int
	issuerPort int
	entries    int
	validity   time.Duration
}

func parseMintConfig(args []string, stderr io.Writer) (mintConfig, error) {
	flags := flag.NewFlagSet("auroralab mint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := mintConfig{}
	flags.StringVar(&config.dir, "dir", "", "lab deployment output directory (must not contain a previous mint)")
	flags.StringVar(&config.relayHost, "relay-host", labfixture.DefaultRelayHost, "relay/issuer hostname or IP clients dial (recorded in the wallet and TLS certificate)")
	flags.IntVar(&config.relayPort, "relay-port", labfixture.DefaultRelayPort, "public relay port recorded in the wallet")
	flags.IntVar(&config.issuerPort, "issuer-port", labfixture.DefaultIssuerPort, "public issuer port recorded in the wallet")
	flags.IntVar(&config.entries, "entries", labfixture.DefaultEntries, "one-time provisioning entries in the wallet")
	flags.DurationVar(&config.validity, "validity", labfixture.DefaultValidity, "deployment validity window")
	if err := flags.Parse(args); err != nil {
		return mintConfig{}, err
	}
	if flags.NArg() != 0 {
		return mintConfig{}, fmt.Errorf("auroralab mint: unexpected arguments")
	}
	if strings.TrimSpace(config.dir) == "" || strings.TrimSpace(config.dir) != config.dir {
		return mintConfig{}, fmt.Errorf("auroralab mint: --dir is required")
	}
	return config, nil
}

func runMint(args []string, stdout, stderr io.Writer) int {
	config, err := parseMintConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	material, err := labfixture.Mint(labfixture.MintOptions{
		RelayHost:  config.relayHost,
		RelayPort:  config.relayPort,
		IssuerPort: config.issuerPort,
		Entries:    config.entries,
		Validity:   config.validity,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer material.Zero()
	if err := material.WriteTo(config.dir); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	manifest := material.Manifest
	fmt.Fprintf(stdout, "auroralab minted lab deployment dir=%s entries=%d\n", config.dir, manifest.Entries)
	fmt.Fprintf(stdout, "auroralab relay=%s issuer=%s valid_until=%s\n",
		manifest.Relay.URL, manifest.Issuer.URL, time.Unix(int64(manifest.ValidUntilUnix), 0).UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "auroralab client wallet=%s/%s trust=%s/%s\n",
		config.dir, labfixture.FileWallet, config.dir, labfixture.FileNativeProvisioningTrust)
	fmt.Fprintf(stdout, "auroralab client trust anchor=%s/%s — install this CA on lab client devices so the relay/issuer HTTPS exchange validates\n",
		config.dir, labfixture.FileCA)
	fmt.Fprintln(stdout, "auroralab reminder: LOCAL LAB TESTING ONLY — never deploy this material")
	return 0
}

type serveConfig struct {
	dir              string
	listen           string
	issuerListen     string
	dnsUpstream      string
	allowNonLoopback bool
}

func parseServeConfig(args []string, stderr io.Writer) (serveConfig, error) {
	flags := flag.NewFlagSet("auroralab serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := serveConfig{}
	flags.StringVar(&config.dir, "dir", "", "minted lab deployment directory")
	flags.StringVar(&config.listen, "listen", "", "relay listen address IP:port (loopback unless --allow-non-loopback)")
	flags.StringVar(&config.issuerListen, "issuer-listen", "", "issuer listen address IP:port (default: minted issuer endpoint)")
	flags.StringVar(&config.dnsUpstream, "dns-upstream", "", "numeric UDP DNS resolver for real internet egress (default: lab loopback egress — every flow lands on the in-process cover origin/echo endpoint)")
	flags.BoolVar(&config.allowNonLoopback, "allow-non-loopback", false, "allow binding non-loopback addresses (prints a warning)")
	if err := flags.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if flags.NArg() != 0 {
		return serveConfig{}, fmt.Errorf("auroralab serve: unexpected arguments")
	}
	if strings.TrimSpace(config.dir) == "" || strings.TrimSpace(config.dir) != config.dir {
		return serveConfig{}, fmt.Errorf("auroralab serve: --dir is required")
	}
	if _, _, err := validateLabListenAddress(config.listen, "relay"); err != nil {
		return serveConfig{}, err
	}
	return config, nil
}

// validateLabListenAddress requires a concrete host:port with a resolvable
// loopback-or-not classification.
func validateLabListenAddress(address, label string) (string, int, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || portText == "" {
		return "", 0, fmt.Errorf("auroralab serve: %s listen address must be a concrete host:port", label)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("auroralab serve: %s listen port is invalid", label)
	}
	return host, int(port), nil
}

// isLabLoopbackHost reports whether a listen host is loopback-only.
func isLabLoopbackHost(host string) bool {
	trimmed := strings.Trim(host, "[]")
	if strings.EqualFold(trimmed, "localhost") {
		return true
	}
	ip := net.ParseIP(trimmed)
	return ip != nil && ip.IsLoopback()
}

func runServe(args []string, stdout, stderr io.Writer) int {
	config, err := parseServeConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := serveLab(config, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func serveLab(config serveConfig, stdout, stderr io.Writer) error {
	loaded, err := labfixture.Load(config.dir, time.Now().UTC())
	if err != nil {
		return err
	}
	manifest := loaded.Manifest

	relayHost, relayPort, err := validateLabListenAddress(config.listen, "relay")
	if err != nil {
		return err
	}
	if relayPort != manifest.Relay.Port {
		return fmt.Errorf("auroralab serve: relay listen port %d does not match the minted wallet relay port %d", relayPort, manifest.Relay.Port)
	}
	issuerListen := config.issuerListen
	if issuerListen == "" {
		issuerListen = net.JoinHostPort(relayHost, strconv.Itoa(manifest.Issuer.Port))
	}
	_, issuerPort, err := validateLabListenAddress(issuerListen, "issuer")
	if err != nil {
		return err
	}
	if issuerPort != manifest.Issuer.Port {
		return fmt.Errorf("auroralab serve: issuer listen port %d does not match the minted wallet issuer port %d", issuerPort, manifest.Issuer.Port)
	}
	for _, endpoint := range []struct {
		label string
		host  string
	}{
		{"relay", relayHost},
		{"issuer", issuerListen[:strings.LastIndex(issuerListen, ":")]},
	} {
		if !isLabLoopbackHost(endpoint.host) {
			if !config.allowNonLoopback {
				return fmt.Errorf("auroralab serve: %s listen address %s is not loopback; pass --allow-non-loopback to expose the lab on the LAN", endpoint.label, endpoint.host)
			}
			fmt.Fprintln(stderr, labNonLoopbackWarning)
		}
	}
	if issuerPort == relayPort {
		return fmt.Errorf("auroralab serve: relay and issuer listen ports must differ")
	}

	labServer, err := labfixture.NewServer(loaded, labfixture.ServerOptions{
		PublicAddress: net.JoinHostPort("0.0.0.0", strconv.Itoa(manifest.Relay.Port)),
		DNSUpstream:   config.dnsUpstream,
	})
	if err != nil {
		return err
	}
	defer func() { _ = labServer.Close() }()

	relayListener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return fmt.Errorf("auroralab serve: relay listen: %w", err)
	}
	defer relayListener.Close()
	issuerListener, err := net.Listen("tcp", issuerListen)
	if err != nil {
		return fmt.Errorf("auroralab serve: issuer listen: %w", err)
	}
	defer issuerListener.Close()

	issuerServer := &http.Server{
		Handler:           labServer.IssuerHandler(),
		TLSConfig:         labServer.IssuerTLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       labIssuerReadTimeout,
		WriteTimeout:      labIssuerWriteTimeout,
		IdleTimeout:       labIssuerIdleTimeout,
		MaxHeaderBytes:    labIssuerMaxHeader,
	}

	egressMode := "lab-loopback"
	if config.dnsUpstream != "" {
		egressMode = "internet dns=" + config.dnsUpstream
	}
	fmt.Fprintf(stdout, "auroralab serving relay=%s listen=%s issuer=%s issuer_listen=%s cover=http://%s egress=%s\n",
		manifest.Relay.URL, relayListener.Addr(), manifest.Issuer.URL, issuerListener.Addr(), labServer.CoverAddress(), egressMode)
	fmt.Fprintln(stdout, "auroralab reminder: LOCAL LAB TESTING ONLY — this deployment must never be exposed beyond a trusted lab network")

	ctx, stop := labSignalContext()
	defer stop()
	serveResults := make(chan error, 2)
	go func() { serveResults <- labServer.ServeFirstHop(relayListener) }()
	go func() {
		serveResults <- issuerServer.Serve(tlsListener(issuerListener, issuerServer.TLSConfig))
	}()
	select {
	case serveErr := <-serveResults:
		if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("auroralab serve: %w", serveErr)
		}
		return fmt.Errorf("auroralab serve: a listener stopped unexpectedly")
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownErr := labServer.Shutdown(shutdownCtx)
	issuerShutdownErr := issuerServer.Shutdown(shutdownCtx)
	<-serveResults
	<-serveResults
	return errors.Join(shutdownErr, issuerShutdownErr)
}
