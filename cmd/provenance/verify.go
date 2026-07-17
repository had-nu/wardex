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
		hash, err := hex.DecodeString(args[0])
		if err != nil {
			return fmt.Errorf("invalid hex hash: %w", err)
		}

		anchorer, err := getAnchorerFn()
		if err != nil {
			return err
		}
		defer func() { _ = anchorer.Close() }()

		result, err := anchorer.Verify(cmd.Context(), hash)
		if err != nil {
			return fmt.Errorf("verify failed: %w", err)
		}

		if !result.Found {
			fmt.Fprintf(cmd.OutOrStdout(), "Hash not found in provenance chain\n")
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Hash FOUND in provenance chain\n")
		fmt.Fprintf(cmd.OutOrStdout(), "  Block:       %d\n", result.BlockIndex)
		fmt.Fprintf(cmd.OutOrStdout(), "  Timestamp:   %s\n", time.Unix(0, result.BlockTime).UTC().Format(time.RFC3339))
		fmt.Fprintf(cmd.OutOrStdout(), "  State Root:  %x\n", result.StateRoot)
		fmt.Fprintf(cmd.OutOrStdout(), "  Label:       %s\n", result.Label)
		fmt.Fprintf(cmd.OutOrStdout(), "  SMT Proof:   %x (len=%d)\n", result.Proof, len(result.Proof))
		return nil
	},
}
