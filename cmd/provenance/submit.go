// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"encoding/hex"
	"fmt"

	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	submitLabel string
)

var submitCmd = &cobra.Command{
	Use:   "submit <hex-hash>",
	Short: "Submit a hash for anchoring",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginProvenanceUI(cmd, "submit", args[0])
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

		u.report(3, "Submitting provenance hash", "RUNNING", submitLabel)
		result, err := anchorer.Submit(cmd.Context(), hash, submitLabel)
		if err != nil {
			u.report(3, "Submitting provenance hash", "FAILED", err.Error())
			return fmt.Errorf("submit failed: %w", err)
		}
		u.report(3, "Submitting provenance hash", "DONE", result.Label)
		if u.progress.Enabled() {
			u.render(buildProvenanceActionDashboard("SUBMITTED", []ui.Field{
				{Label: "HASH", Value: args[0]},
				{Label: "LABEL", Value: result.Label},
				{Label: "STATUS", Value: "pending"},
			}))
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Hash submitted for anchoring")
		fmt.Fprintf(cmd.OutOrStdout(), "  Label:     %s\n", result.Label)
		fmt.Fprintln(cmd.OutOrStdout(), "  Status:    pending")
		return nil
	},
}

func init() {
	submitCmd.Flags().StringVar(&submitLabel, "label", "", "Artifact label (optional)")
	_ = submitCmd.MarkFlagRequired("label")
}
