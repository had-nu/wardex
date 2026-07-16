// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	submitLabel  string
)

var submitCmd = &cobra.Command{
	Use:   "submit <hex-hash>",
	Short: "Submit a hash for anchoring",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash, err := hex.DecodeString(args[0])
		if err != nil {
			return fmt.Errorf("invalid hex hash: %w", err)
		}

		anchorer, err := getAnchorer()
		if err != nil {
			return err
		}
		defer func() { _ = anchorer.Close() }()

		result, err := anchorer.Submit(cmd.Context(), hash, submitLabel)
		if err != nil {
			return fmt.Errorf("submit failed: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Hash submitted for anchoring\n")
		fmt.Fprintf(cmd.OutOrStdout(), "  Label:     %s\n", result.Label)
		fmt.Fprintf(cmd.OutOrStdout(), "  Status:    pending\n")
		return nil
	},
}

func init() {
	submitCmd.Flags().StringVar(&submitLabel, "label", "", "Artifact label (optional)")
	_ = submitCmd.MarkFlagRequired("label")
}
