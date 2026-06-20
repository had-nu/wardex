// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package configseal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/pkg/trust"
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
	defaultKeyring := filepath.Join(home, ".wardex", "keyring.wex")

	SealCmd.Flags().StringVar(&keyringPath, "keyring", defaultKeyring, "Path to private key (required)")
	SealCmd.Flags().StringVar(&inputPath, "input", "", "Path to wardex-config.yaml draft (required)")
	SealCmd.Flags().StringVar(&outPath, "out", "./wardex.wexstate", "Output path for sealed config")
	SealCmd.Flags().StringVar(&trustRef, "trust", "", "Path or URL to wardex-trust.yaml\nOverrides WARDEX_TRUST_STORE if set (default: ./wardex-trust.yaml)")
	_ = SealCmd.MarkFlagRequired("input")

	ConfigCmd.AddCommand(SealCmd)
}

func runConfigSeal(cmd *cobra.Command, args []string) error {
	if err := trust.SealConfig(keyringPath, inputPath, outPath, trustRef); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), `Config sealed successfully.
  Input   : %s
  Output  : %s
  Trust   : %s

The sealed config can now be used with:
  wardex evaluate --config %s --evidence vulns.yaml controls.yaml

Commit the .wexstate file (not the draft yaml) to your repository.
`, inputPath, outPath, trust.ResolveTrustStoreRef(trustRef, ""), outPath)

	return nil
}
