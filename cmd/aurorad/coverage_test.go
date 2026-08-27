package main

// Adversarial coverage for pure helpers in cmd/aurorad that the existing
// integration-style tests (which drive the full run/parse path) do not reach
// directly:
//   - isLoopbackListenAddress: the SplitHostPort-error (return false) and the
//     literal-"localhost" (return true) branches. The existing tests reach the
//     function only via run() with real loopback/non-loopback IPs, so the
//     malformed-address and "localhost"-string branches stay uncovered.
//   - printReadiness: the per-finding fmt.Fprintln loop body. The existing
//     readiness-check test drives a passing report with no findings, so the
//     range body never executes.
//   - zeroRSAPrivateKey: the nil-receiver early return and the legacy
//     Precomputed.CRTValues zeroing loop. The existing test uses a 2-prime
//     rsa.GenerateKey + Precompute, which populates Dp/Dq/Qinv but leaves
//     CRTValues empty (CRTValues is only populated for multi-prime RSA).
//   - issuerProductionConfig.validate: the four rejection branches delegated
//     after validateRequiredFields (required-field failure, malformed listen
//     address, wrong relay-bucket length, zero origin-info policy). The
//     existing tests exercise validate only through the full argument parser,
//     which mostly hits the happy path and the relay-bucket length check.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).

import (
	"bytes"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/aurora-protocol/aurora-core/server"
)

func TestIsLoopbackListenAddressClassification(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"malformed address has no port", "no-port", false}, // SplitHostPort error -> return false
		{"literal localhost", "localhost:443", true},        // EqualFold("localhost") -> return true
		{"loopback ipv4", "127.0.0.1:443", true},            // ip.IsLoopback -> return true
		{"loopback ipv6 bracketed", "[::1]:443", true},      // Trim "[]" + ip.IsLoopback -> return true
		{"non-loopback ipv4", "203.0.113.7:443", false},     // ip not loopback -> return false
		{"non-ip hostname", "example.com:443", false},       // ParseIP nil -> return false
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLoopbackListenAddress(tc.addr); got != tc.want {
				t.Fatalf("isLoopbackListenAddress(%q) = %t, want %t", tc.addr, got, tc.want)
			}
		})
	}
}

func TestPrintReadinessEmitsSummaryAndFindings(t *testing.T) {
	t.Run("summary line with no findings", func(t *testing.T) {
		var out bytes.Buffer
		printReadiness(&out, server.ReadinessReport{Passed: true, CoverEndpoint: true})
		text := out.String()
		if !bytes.Contains([]byte(text), []byte("server_check passed=true")) {
			t.Fatalf("readiness summary missing passed flag:\n%s", text)
		}
		if bytes.Contains([]byte(text), []byte("server_finding")) {
			t.Fatalf("readiness output with no findings emitted a finding line:\n%s", text)
		}
	})
	t.Run("one finding line per finding", func(t *testing.T) {
		var out bytes.Buffer
		report := server.ReadinessReport{
			Passed: false,
			Findings: []string{
				"cover endpoint unreachable",
				"issuer metadata carrier missing",
			},
		}
		printReadiness(&out, report)
		text := out.String()
		for _, finding := range report.Findings {
			want := "server_finding " + finding
			if !bytes.Contains([]byte(text), []byte(want)) {
				t.Fatalf("readiness output missing %q:\n%s", want, text)
			}
		}
	})
}

func TestZeroRSAPrivateKeyHandlesNilAndLegacyCRTValues(t *testing.T) {
	t.Run("nil receiver is a no-op", func(t *testing.T) {
		// Must not panic on a nil key (early return at line 402-403).
		zeroRSAPrivateKey(nil)
	})
	t.Run("legacy CRT limbs are zeroed", func(t *testing.T) {
		// A minimal key whose only populated material is the legacy
		// Precomputed.CRTValues slice (multi-prime RSA leftovers). D, Primes,
		// Dp, Dq and Qinv are nil/empty, so the only non-trivial work is the
		// CRTValues loop at lines 413-417.
		exp := big.NewInt(0x11)
		coeff := big.NewInt(0x22)
		r := big.NewInt(0x33)
		key := &rsa.PrivateKey{
			Precomputed: rsa.PrecomputedValues{
				CRTValues: []rsa.CRTValue{{Exp: exp, Coeff: coeff, R: r}},
			},
		}
		zeroRSAPrivateKey(key)
		for name, value := range map[string]*big.Int{
			"legacy CRT exponent":    exp,
			"legacy CRT coefficient": coeff,
			"legacy CRT remainder":   r,
		} {
			if value.Sign() != 0 {
				t.Fatalf("RSA %s retained material after zeroization (sign=%d)", name, value.Sign())
			}
		}
	})
}

func TestIssuerProductionConfigValidateRejectsEachInvalidField(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*issuerProductionConfig)
	}{
		{
			"missing required field",
			func(c *issuerProductionConfig) { c.listenAddress = "" }, // validateRequiredFields fails -> line 164-165
		},
		{
			"malformed listen address",
			func(c *issuerProductionConfig) { c.listenAddress = "bad" }, // SplitHostPort fails -> line 167-168
		},
		{
			"relay bucket id wrong length",
			func(c *issuerProductionConfig) { c.relayBucketID = make([]byte, 15) }, // -> line 170-171
		},
		{
			"zero origin info policy",
			func(c *issuerProductionConfig) { c.originInfoPolicyID = 0 }, // -> line 173-174
		},
		{
			"zero signing concurrency",
			func(c *issuerProductionConfig) { c.maxConcurrentIssues = 0 },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validIssuerProductionConfigForCoverage()
			tc.mutate(&c)
			if err := c.validate(); err == nil {
				t.Fatalf("validate accepted %s", tc.name)
			}
		})
	}
}

func TestIssuerProductionConfigValidateAcceptsValid(t *testing.T) {
	c := validIssuerProductionConfigForCoverage()
	if err := c.validate(); err != nil {
		t.Fatalf("valid issuer production config rejected: %v", err)
	}
}

// validIssuerProductionConfigForCoverage returns an issuerProductionConfig that
// passes every validate() check, used as the base for each rejection subtest
// (each subtest perturbs exactly one field so the rejection is attributable to
// that field alone).
func validIssuerProductionConfigForCoverage() issuerProductionConfig {
	return issuerProductionConfig{
		listenAddress:            "127.0.0.1:443",
		tlsCertificatePath:       "/tls/cert.pem",
		tlsPrivateKeyPath:        "/tls/key.pem",
		gatewayClientCAPath:      "/tls/gateway-client-ca.pem",
		issuerMetadataPath:       "/issuer/metadata.bin",
		metadataAuthorityKeyPath: "/issuer/auth.key",
		blindRSAKeyPath:          "/issuer/blind.key",
		spentTokenCachePath:      "/issuer/spent.cache",
		relayBucketID:            make([]byte, 16),
		originInfoPolicyID:       1,
		maxConcurrentIssues:      1,
	}
}
