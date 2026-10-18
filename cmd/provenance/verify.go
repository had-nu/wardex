// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <hex-hash>",
	Short: "Verify a hash in the provenance chain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginProvenanceUI(cmd, "verify", args[0])
		u.report(1, "Decoding hash", "RUNNING", "")
		hash, err := hex.DecodeString(args[0])
		if err != nil {
			u.report(1, "Decoding hash", "FAILED", err.Error())
			return fmt.Errorf("invalid hex hash: %w", err)
		}
		u.report(1, "Decoding hash", "DONE", args[0])

		u.report(2, "Connecting to anchor", "RUNNING", "")
		anchorer, err := getAnchorerFn()
		if err != nil {
			u.report(2, "Connecting to anchor", "FAILED", err.Error())
			return err
		}
		defer func() { _ = anchorer.Close() }()
		u.report(2, "Connecting to anchor", "DONE", "anchor ready")

		u.report(3, "Verifying provenance hash", "RUNNING", "")
		result, err := anchorer.Verify(cmd.Context(), hash)
		if err != nil {
			u.report(3, "Verifying provenance hash", "FAILED", err.Error())
			return fmt.Errorf("verify failed: %w", err)
		}
		if result.DryRun {
			u.report(3, "Verifying provenance hash", "SKIPPED", "dry-run backend")
		} else {
			u.report(3, "Verifying provenance hash", "DONE", "verification complete")
		}
		if u.dashboardEnabled() {
			u.render(buildProvenanceVerifyDashboard(args[0], result))
			return nil
		}

		if result.DryRun {
			fmt.Fprintln(u.output, "Dry-run backend: hash was not checked")
			return nil
		}
		if result == nil || !result.Found {
			fmt.Fprintln(u.output, "Hash not found in provenance chain")
			return nil
		}
		fmt.Fprintln(u.output, "Hash FOUND in provenance chain")
		fmt.Fprintf(u.output, "  Block:       %d\n", result.BlockIndex)
		fmt.Fprintf(u.output, "  Timestamp:   %s\n", time.Unix(0, result.BlockTime).UTC().Format(time.RFC3339))
		fmt.Fprintf(u.output, "  State Root:  %x\n", result.StateRoot)
		fmt.Fprintf(u.output, "  Label:       %s\n", result.Label)
		fmt.Fprintf(u.output, "  SMT Proof:   %x (len=%d)\n", result.Proof, len(result.Proof))
		return nil
	},
}
