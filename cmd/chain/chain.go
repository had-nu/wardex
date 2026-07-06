// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package chain

import (
	"github.com/spf13/cobra"
)

// ChainCmd manages chain seals for artifact integrity.
var ChainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Manage chain seals for artifact integrity",
	Long: `Create and verify chain seals that bind artifacts together
using cryptographic hashes. Chain seals provide evidence of
artifact integrity over time.`,
}

func init() {
	ChainCmd.AddCommand(SealCmd)
}
