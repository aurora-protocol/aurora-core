package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/platform"
	"github.com/aurora-protocol/aurora-core/server"
)

const packetModeLoopback = "loopback"

var (
	listenAndServe        = server.ListenAndServe
	listenAndServeTLS     = server.ListenAndServeTLS
	newCoverOrigin        = newReverseProxyCoverOrigin
	openLinuxPacketDevice = func(config platform.LinuxTUNConfig) (io.ReadWriteCloser, int, error) {
		device, err := platform.OpenLinuxTUNDevice(config)
		if err != nil {
			return nil, 0, err
		}
		return device, device.MTU(), nil
	}
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("aurorad", flag.ContinueOnError)
	flags.SetOutput(stderr)
	defaultTUN := platform.DefaultLinuxTUNConfig()
	listen := flags.String("listen", "127.0.0.1:9443", "listen address")
	coverBody := flags.String("cover-body", "<html><body>ok</body></html>", "ordinary cover-origin response body")
	coverOriginURL := flags.String("cover-origin-url", "", "ordinary cover-origin URL to reverse proxy")
	tlsCert := flags.String("tls-cert", "", "TLS certificate file for HTTPS serving")
	tlsKey := flags.String("tls-key", "", "TLS private key file for HTTPS serving")
	now := flags.Uint64("harness-now", 200, "harness unix timestamp")
	readinessCheck := flags.Bool("readiness-check", false, "run the server readiness harness and exit")
	packetMode := flags.String("packet-mode", packetModeLoopback, "packet exchange mode: loopback or tun")
	spentTokenCachePath := flags.String("spent-token-cache", "", "append-only spent-token replay cache path")
	tunDevice := flags.String("tun-device", defaultTUN.DevicePath, "Linux TUN device path")
	tunInterface := flags.String("tun-iface", defaultTUN.InterfaceName, "Linux TUN interface name")
	tunMTU := flags.Int("tun-mtu", defaultTUN.MTU, "Linux TUN MTU")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *listen == "" {
		fmt.Fprintln(stderr, "server: listen address is required")
		return 2
	}
	if !isValidPacketMode(*packetMode) {
		fmt.Fprintf(stderr, "server: packet mode %q must be loopback or tun\n", *packetMode)
		return 2
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(stderr, "server: TLS certificate and key must be configured together")
		return 2
	}
	if *readinessCheck {
		report, err := server.RunReadinessHarness(*now)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		printReadiness(stdout, report)
		if !report.Passed {
			return 1
		}
		return 0
	}
	packetExchanger, packetCloser, err := newPacketExchanger(*packetMode, platform.LinuxTUNConfig{
		DevicePath:    *tunDevice,
		InterfaceName: *tunInterface,
		MTU:           *tunMTU,
		PacketMode:    platform.PacketTUN,
		LocalModes:    defaultTUN.LocalModes,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if packetCloser != nil {
		defer packetCloser.Close()
	}
	var spentTokenCache admission.ReplayCache
	var spentTokenCacheCloser io.Closer
	if *spentTokenCachePath != "" {
		cache, err := admission.NewFileReplayCache(*spentTokenCachePath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		spentTokenCache = cache
		spentTokenCacheCloser = cache
	}
	if spentTokenCacheCloser != nil {
		defer spentTokenCacheCloser.Close()
	}
	var coverOrigin http.Handler
	if *coverOriginURL != "" {
		coverOrigin, err = newCoverOrigin(*coverOriginURL)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	handler, err := server.NewHarnessHandler(server.HarnessOptions{
		NowUnix:         *now,
		CoverBody:       []byte(*coverBody),
		CoverOrigin:     coverOrigin,
		PacketExchanger: packetExchanger,
		SpentTokenCache: spentTokenCache,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	fmt.Fprintf(stdout, "aurorad listening=%s scheme=%s packet_mode=%s\n", *listen, scheme, *packetMode)
	var serveErr error
	if *tlsCert != "" {
		serveErr = listenAndServeTLS(*listen, handler, *tlsCert, *tlsKey)
	} else {
		serveErr = listenAndServe(*listen, handler)
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		fmt.Fprintln(stderr, serveErr)
		return 1
	}
	return 0
}

func newReverseProxyCoverOrigin(raw string) (http.Handler, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	return server.NewReverseProxyCoverOrigin(parsed)
}

func isValidPacketMode(mode string) bool {
	return mode == packetModeLoopback || mode == platform.PacketTUN
}

func newPacketExchanger(mode string, tunConfig platform.LinuxTUNConfig) (server.PacketExchanger, io.Closer, error) {
	switch mode {
	case packetModeLoopback:
		return server.LoopbackPacketExchanger{}, nil, nil
	case platform.PacketTUN:
		device, mtu, err := openLinuxPacketDevice(tunConfig)
		if err != nil {
			return nil, nil, err
		}
		if mtu == 0 {
			mtu = tunConfig.MTU
		}
		exchanger, err := server.NewDevicePacketExchanger(device, server.DevicePacketExchangerOptions{
			MTU:          mtu,
			QueuePackets: 64,
		})
		if err != nil {
			_ = device.Close()
			return nil, nil, err
		}
		return exchanger, exchanger, nil
	default:
		return nil, nil, fmt.Errorf("server: unsupported packet mode %q", mode)
	}
}

func printReadiness(w io.Writer, report server.ReadinessReport) {
	fmt.Fprintf(
		w,
		"server_check passed=%t health=%t cover=%t issuer_metadata=%t blind_rsa_issue=%t packet_exchange=%t cover_neutral_unknown=%t findings=%d\n",
		report.Passed,
		report.HealthEndpoint,
		report.CoverEndpoint,
		report.IssuerMetadataEndpoint,
		report.BlindRSAIssueEndpoint,
		report.PacketExchangeEndpoint,
		report.CoverNeutralUnknownPath,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintln(w, "server_finding "+finding)
	}
}
