// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package configseal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	keyringPath string
	inputPath   string
	outPath     string
	trustRef    string
)

// ConfigCmd is the parent command for config management.
var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Wardex configuration files",
	Long: `Configuration management commands for the Wardex trust system.

Use 'wardex config seal' to cryptographically seal a draft config
so that 'wardex evaluate' can verify its integrity.`,
}

// SealCmd seals a draft wardex-config.yaml into a signed .wexstate file.
var SealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal a draft config into a signed .wexstate file",
	Long: `Read a draft wardex-config.yaml, verify it has no PENDING_APPROVAL fields,
and produce a signed wardex.wexstate file.

Only operators with role 'ciso' or 'admin' can seal configs.
The sealed file binds the config to the trust store state at seal time —
any subsequent trust store changes require re-sealing.`,
	RunE: runConfigSeal,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultKeyring := filepath.Join(home, ".crypto", "trust", "root.key")

	SealCmd.Flags().StringVar(&keyringPath, "keyring", defaultKeyring, "Path to private key (required)")
	SealCmd.Flags().StringVar(&inputPath, "input", "", "Path to wardex-config.yaml draft (required)")
	SealCmd.Flags().StringVar(&outPath, "out", "./wardex.wexstate", "Output path for sealed config")
	SealCmd.Flags().StringVar(&trustRef, "trust", "", "Path or URL to wardex-trust.yaml\nOverrides WARDEX_TRUST_STORE if set (default: ./wardex-trust.yaml)")
	_ = SealCmd.MarkFlagRequired("input")

	ConfigCmd.AddCommand(SealCmd, HashCmd, ShowCmd)
}

func runConfigSeal(cmd *cobra.Command, args []string) error {
	stderr := cmd.ErrOrStderr()
	resolvedTrust := trust.ResolveTrustStoreRef(trustRef, "")
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(buildConfigSealSession(keyringPath, inputPath, outPath, resolvedTrust))
	reportProgress := func(number int, name, status, detail string) {
		progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
	}

	reportProgress(1, "Validating seal inputs", "RUNNING", "")
	reportProgress(1, "Validating seal inputs", "DONE", "inputs accepted")
	reportProgress(2, "Sealing configuration", "RUNNING", outPath)
	if err := trust.SealConfig(cmd.Context(), keyringPath, inputPath, outPath, trustRef); err != nil {
		reportProgress(2, "Sealing configuration", "FAILED", err.Error())
		return err
	}
	reportProgress(2, "Sealing configuration", "DONE", outPath)
	reportProgress(3, "Finalizing sealed config", "RUNNING", "")
	reportProgress(3, "Finalizing sealed config", "DONE", "configuration ready")

	if configResultEnabled(cmd, progress) {
		renderConfigSealResults(stderr, progress, inputPath, outPath, resolvedTrust)
		return nil
	}

	w := configCommandOutput(cmd)
	fmt.Fprintln(w, "Config sealed successfully.")
	inputLabel, outputLabel, trustLabel := "Input:", "Output:", "Trust:"
	if ui.IsTerminal(w) {
		inputLabel = ui.Colorize(inputLabel, ui.Gray)
		outputLabel = ui.Colorize(outputLabel, ui.Gray)
		trustLabel = ui.Colorize(trustLabel, ui.Gray)
	}
	fmt.Fprintf(w, "  %s %s\n", inputLabel, inputPath)
	fmt.Fprintf(w, "  %s %s\n", outputLabel, outPath)
	fmt.Fprintf(w, "  %s %s\n\n", trustLabel, resolvedTrust)
	fmt.Fprintln(w, "The sealed config can now be used with:")
	fmt.Fprintf(w, "  wardex evaluate --config %s --evidence vulns.yaml controls.yaml\n\n", outPath)
	fmt.Fprintln(w, "Commit the .wexstate file (not the draft yaml) to your repository.")
	return nil
}
