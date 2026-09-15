// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package gatecmd provides the `wardex gate` command group.
package gatecmd

import "github.com/spf13/cobra"

// GateCmd is the parent of release-gate maintenance commands.
var GateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Release gate maintenance and verification",
	Long: `Commands for maintaining and verifying the release gate chain.

Use 'wardex gate check-version' to enforce the one-seal-per-version
anti-regression rule before (re)running a release job.`,
}

func init() {
	GateCmd.AddCommand(CheckVersionCmd)
}
