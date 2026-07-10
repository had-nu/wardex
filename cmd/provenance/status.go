// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show provenance anchor health",
	RunE: func(cmd *cobra.Command, args []string) error {
		anchorer, err := getAnchorer()
		if err != nil {
			return err
		}
		defer anchorer.Close()

		health, err := anchorer.Status(cmd.Context())
		if err != nil {
			return fmt.Errorf("status failed: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "PROVENANCE ANCHOR STATUS\n")
		fmt.Fprintf(cmd.OutOrStdout(), "========================\n\n")
		fmt.Fprintf(cmd.OutOrStdout(), "Block Height:  %d\n", health.BlockHeight)
		fmt.Fprintf(cmd.OutOrStdout(), "Active Peers:  %d\n", health.ActivePeers)
		fmt.Fprintf(cmd.OutOrStdout(), "Pending:       %d\n", health.Pending)
		return nil
	},
}
