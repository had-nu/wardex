// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package contract

import (
	"github.com/spf13/cobra"
)

// ContractCmd manages contract file verification.
var ContractCmd = &cobra.Command{
	Use:   "contract",
	Short: "Manage contract file verification",
	Long: `Verify contract file integrity using SHA-256 hashes.

Use 'contract verify' to compute and optionally verify a contract file's hash.`,
}

func init() {
	ContractCmd.AddCommand(VerifyCmd)
}
