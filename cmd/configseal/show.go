// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package configseal

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/spf13/cobra"
)

var showConfigPath string

// ShowCmd displays configuration metadata and hash.
var ShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show configuration metadata and hash",
	Long: `Display key configuration fields and compute the SHA-256 hash
of the configuration file. Useful for verifying which configuration
is active and comparing across environments.`,
	RunE: runConfigShow,
}

func init() {
	ShowCmd.Flags().StringVar(&showConfigPath, "config", "./wardex-config.yaml", "Path to wardex-config.yaml")
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(showConfigPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	data, err := os.ReadFile(showConfigPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	hash, err := cpl.ComputeConfigHash(data, cpl.AlgoSHA256)
	if err != nil {
		return fmt.Errorf("computing hash: %w", err)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Configuration: %s\n", showConfigPath)
	fmt.Fprintf(w, "  Hash (SHA-256):    %s\n", hash)
	fmt.Fprintf(w, "  Risk appetite:     %.2f\n", cfg.ReleaseGate.RiskAppetite)
	fmt.Fprintf(w, "  Warn above:        %.2f\n", cfg.ReleaseGate.WarnAbove)
	fmt.Fprintf(w, "  Gate mode:         %s\n", cfg.ReleaseGate.Mode)
	fmt.Fprintf(w, "  Gate enabled:      %t\n", cfg.ReleaseGate.Enabled)
	fmt.Fprintf(w, "  CRA Art.14:        %t\n", cfg.CRA.Art14.ProductName != "")
	if cfg.CRA.Art14.ProductName != "" {
		fmt.Fprintf(w, "  Product name:      %s\n", cfg.CRA.Art14.ProductName)
		fmt.Fprintf(w, "  Product version:   %s\n", cfg.CRA.Art14.ProductVersion)
	}
	fmt.Fprintf(w, "  State store:       %t\n", cfg.StateStore.Enabled)
	fmt.Fprintf(w, "  Reporting format:  %s\n", cfg.Reporting.Format)

	return nil
}
