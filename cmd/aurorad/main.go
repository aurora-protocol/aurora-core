package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aurora-protocol/aurora-core/server"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("aurorad", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "127.0.0.1:9443", "listen address")
	coverBody := flags.String("cover-body", "<html><body>ok</body></html>", "ordinary cover-origin response body")
	now := flags.Uint64("harness-now", 200, "harness unix timestamp")
	readinessCheck := flags.Bool("readiness-check", false, "run the server readiness harness and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *listen == "" {
		fmt.Fprintln(stderr, "server: listen address is required")
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
	handler, err := server.NewHarnessHandler(server.HarnessOptions{
		NowUnix:   *now,
		CoverBody: []byte(*coverBody),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "aurorad listening=%s\n", *listen)
	if err := server.ListenAndServe(*listen, handler); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func printReadiness(w io.Writer, report server.ReadinessReport) {
	fmt.Fprintf(
		w,
		"server_check passed=%t health=%t cover=%t issuer_metadata=%t blind_rsa_issue=%t cover_neutral_unknown=%t findings=%d\n",
		report.Passed,
		report.HealthEndpoint,
		report.CoverEndpoint,
		report.IssuerMetadataEndpoint,
		report.BlindRSAIssueEndpoint,
		report.CoverNeutralUnknownPath,
		len(report.Findings),
	)
	for _, finding := range report.Findings {
		fmt.Fprintln(w, "server_finding "+finding)
	}
}
