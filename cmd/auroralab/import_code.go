package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/internal/labfixture"
)

// importCodeFileName is the file the provisioning code is written to beside
// the wallet.
const importCodeFileName = "import-code.txt"

// runImportCode wraps a minted wallet in the mobile-FFI import envelope (zero
// spent hint keys) and prints the canonical base64 provisioning code a client
// app accepts in its "import provisioning code" field.
func runImportCode(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("auroralab import-code", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "minted lab deployment directory (reads wallet.bin)")
	walletPath := flags.String("wallet", "", "explicit wallet file path (overrides --dir wallet lookup)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "auroralab import-code: unexpected arguments")
		return 2
	}
	if strings.TrimSpace(*dir) == "" && *dir != "" {
		fmt.Fprintln(stderr, "auroralab import-code: --dir is invalid")
		return 2
	}
	if *dir == "" && *walletPath == "" {
		fmt.Fprintln(stderr, "auroralab import-code: --dir or --wallet is required")
		return 2
	}
	resolvedWallet := *walletPath
	if resolvedWallet == "" {
		resolvedWallet = filepath.Join(*dir, labfixture.FileWallet)
	}
	wallet, err := readImportCodeWallet(resolvedWallet)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	envelope, err := client.EncodeNativeProvisioningImportEnvelope(wallet, nil)
	zeroLabCLIBytes(wallet)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	code := base64.StdEncoding.EncodeToString(envelope)
	zeroLabCLIBytes(envelope)
	outputPath := filepath.Join(filepath.Dir(resolvedWallet), importCodeFileName)
	if err := writeImportCodeFile(outputPath, code); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "auroralab import code (base64, also written to %s):\n%s\n", outputPath, code)
	fmt.Fprintln(stdout, "auroralab reminder: LOCAL LAB TESTING ONLY — this code carries live lab credentials; never import it on a production device profile")
	return 0
}

// readImportCodeWallet reads one bounded wallet file.
func readImportCodeWallet(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("auroralab import-code: inspect wallet: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("auroralab import-code: wallet must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("auroralab import-code: open wallet: %w", err)
	}
	defer file.Close()
	wallet, err := io.ReadAll(io.LimitReader(file, int64(client.MaximumNativeProvisioningWalletBytes)+1))
	if err != nil {
		zeroLabCLIBytes(wallet)
		return nil, fmt.Errorf("auroralab import-code: read wallet: %w", err)
	}
	if len(wallet) == 0 || len(wallet) > client.MaximumNativeProvisioningWalletBytes {
		zeroLabCLIBytes(wallet)
		return nil, fmt.Errorf("auroralab import-code: wallet length is invalid")
	}
	return wallet, nil
}

// writeImportCodeFile writes the provisioning code owner-only with a trailing
// newline, replacing any previously generated code for the same wallet.
func writeImportCodeFile(path, code string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("auroralab import-code: create %s: %w", importCodeFileName, err)
	}
	if _, err := io.WriteString(file, code+"\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("auroralab import-code: write %s: %w", importCodeFileName, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("auroralab import-code: close %s: %w", importCodeFileName, err)
	}
	return nil
}

func zeroLabCLIBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
