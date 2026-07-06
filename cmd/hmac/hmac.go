// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package hmac

import (
	"github.com/spf13/cobra"
)

// HMACCmd manages HMAC signatures.
var HMACCmd = &cobra.Command{
	Use:   "hmac",
	Short: "Manage HMAC-SHA256 signatures",
	Long: `Compute and verify HMAC-SHA256 signatures for file integrity.

Use 'hmac sign' to compute a signature and 'hmac verify' to check one.`,
}

func init() {
	HMACCmd.AddCommand(SignCmd)
}
