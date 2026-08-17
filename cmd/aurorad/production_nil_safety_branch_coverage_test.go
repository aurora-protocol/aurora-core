package main

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across cmd/aurorad/issuer_production.go and cmd/aurorad/production.go.
// Each guard exists so a caller that passes a nil runtime / nil production
// service / nil PEM block does not panic or proceed into the close / HTTP
// server build / field-erase path: the function returns at its very first
// statement, before any field is dereferenced (runtime.Close, runtime.service,
// runtime.tlsConfig, block.Bytes) or any helper is called
// (newProductionIssuerHTTPServer's downstream, zeroProductionBytes). The
// existing aurorad tests only ever drive a populated runtime along the live
// production issuer path and real PEM blocks, so the nil guards stayed
// count-0 even though each is plainly reachable.
//
//   - :327 closeProductionIssuerRuntime(runtime io.Closer, stderr io.Writer) error
//     runtime == nil -> nil (the runtime==nil guard fires before runtime.Close;
//     stderr is never read, so a nil stderr writer is safe)
//   - :377 newProductionIssuerHTTPServer(runtime *productionIssuerService) (*http.Server, error)
//     runtime == nil || runtime.service == nil || runtime.tlsConfig == nil
//     -> (nil, "issuer: production service is required") (the || short-circuits
//     on the nil-runtime side, firing before runtime.service / runtime.tlsConfig
//     would be dereferenced)
//   - :731 zeroPrivatePEMBlock(block *pem.Block)
//     block == nil -> no-op return (void; fires before zeroProductionBytes /
//     the *block = pem.Block{} assignment)
//
// These are nil-ARGUMENT first-statement guards. None take a context, so there
// is no SA1012 surface. No network connection is opened — the nil guards
// return before runtime.Close / the http.Server is built / any bytes are
// zeroed. The test is in-package (package main) because
// closeProductionIssuerRuntime, newProductionIssuerHTTPServer, and
// zeroPrivatePEMBlock are unexported.
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestCloseProductionIssuerRuntimeNilArgumentGuard(t *testing.T) {
	// 327: closeProductionIssuerRuntime(nil, nil) returns nil. The runtime==nil
	// guard fires before runtime.Close; stderr is never read, so a nil writer is
	// safe.
	if err := closeProductionIssuerRuntime(nil, nil); err != nil {
		t.Fatalf("closeProductionIssuerRuntime(nil,nil) err = %v, want nil (:327 should return nil)", err)
	}
}

func TestNewProductionIssuerHTTPServerNilArgumentGuard(t *testing.T) {
	// 377: newProductionIssuerHTTPServer(nil) returns the required-service error
	// and a nil server. The runtime==nil side of the || short-circuits, firing
	// before runtime.service / runtime.tlsConfig would be dereferenced.
	server, err := newProductionIssuerHTTPServer(nil)
	if err == nil {
		t.Fatal("newProductionIssuerHTTPServer(nil) err = nil, want non-nil (:377 should reject)")
	} else if !strings.Contains(err.Error(), "production service is required") {
		t.Fatalf("newProductionIssuerHTTPServer(nil) err = %q, want substring \"production service is required\" (:377)", err.Error())
	}
	if server != nil {
		t.Fatalf("newProductionIssuerHTTPServer(nil) server = %v, want nil (:377)", server)
	}
}

func TestZeroPrivatePEMBlockNilArgumentGuard(t *testing.T) {
	// 731: zeroPrivatePEMBlock(nil) is a void no-op; the block==nil guard fires
	// before zeroProductionBytes / the *block assignment. The proof is that the
	// call completes without panicking (a panic surfaces as a test failure).
	zeroPrivatePEMBlock(nil)
}
