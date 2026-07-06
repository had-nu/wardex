// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package assets

import (
	"github.com/spf13/cobra"
)

// AssetsCmd manages ICT asset inventory.
var AssetsCmd = &cobra.Command{
	Use:   "assets",
	Short: "Manage ICT asset inventory",
	Long: `View and manage the ICT asset inventory for compliance analysis.

Use 'assets inventory' to display the current inventory.`,
}

func init() {
	AssetsCmd.AddCommand(InventoryCmd)
}
