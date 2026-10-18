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
		u := beginProvenanceUI(cmd, "status", "anchor health")
		u.report(1, "Connecting to anchor", "RUNNING", "")
		anchorer, err := getAnchorerFn()
		if err != nil {
			u.report(1, "Connecting to anchor", "FAILED", err.Error())
			return err
		}
		defer func() { _ = anchorer.Close() }()
		u.report(1, "Connecting to anchor", "DONE", "anchor ready")

		u.report(2, "Reading anchor health", "RUNNING", "")
		health, err := anchorer.Status(cmd.Context())
		if err != nil {
			u.report(2, "Reading anchor health", "FAILED", err.Error())
			return fmt.Errorf("status failed: %w", err)
		}
		u.report(2, "Reading anchor health", "DONE", "health received")
		u.report(3, "Preparing status result", "RUNNING", "")
		u.report(3, "Preparing status result", "DONE", "status ready")
		if u.dashboardEnabled() {
			u.render(buildProvenanceStatusDashboard(health))
			return nil
		}
		if health == nil {
			return fmt.Errorf("status failed: empty health response")
		}
		if health.DryRun {
			fmt.Fprintln(u.output, "Provenance anchor is in dry-run mode; no persistence or health query is available")
			return nil
		}

		fmt.Fprintln(u.output, "PROVENANCE ANCHOR STATUS")
		fmt.Fprintln(u.output, "========================")
		fmt.Fprintln(u.output)
		fmt.Fprintf(u.output, "Block Height:  %d\n", health.BlockHeight)
		fmt.Fprintf(u.output, "Active Peers:  %d\n", health.ActivePeers)
		fmt.Fprintf(u.output, "Pending:       %d\n", health.Pending)
		return nil
	},
}
