// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"github.com/had-nu/immutable-provenance/cli"
	"github.com/spf13/cobra"
)

// ProvenanceCmd handles cryptographic source code seals, Bitcoin timestamps (OTS), and EVM (Ethereum/Polygon) anchors.
var ProvenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Cryptographic, ledger-anchored source code provenance tool",
	Long: `Create and verify cryptographic seals of source trees and anchor
them into Bitcoin (via OpenTimestamps) and Ethereum/Polygon smart contracts.`,
}

func init() {
	// Add all child commands from the standalone sub-module to 'wardex provenance'
	for _, child := range cli.RootCmd.Commands() {
		ProvenanceCmd.AddCommand(child)
	}
}
