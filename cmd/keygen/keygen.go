// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package keygen

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/pkg/trust"
	"github.com/spf13/cobra"
)

var (
	outPath string
	force   bool
)

// KeygenCmd generates an ed25519 keypair for use with the Wardex trust system.
var KeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an ed25519 keypair for the Wardex trust system",
	Long: `Generate an ed25519 keypair. The private key is written with mode 0400
(read-only for the owner). The public key is written alongside with a .pub extension.

The keypair has no role until an admin adds the public key to the trust store
via 'wardex trust add'.`,
	RunE: runKeygen,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultPath := filepath.Join(home, ".wardex", "keyring.wex")

	KeygenCmd.Flags().StringVar(&outPath, "out", defaultPath, "Path for the private key")
	KeygenCmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing key (requires confirmation)")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	_, err := trust.GenerateKeypair(outPath, force)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), `Keypair generated.
  Private key : %s     (mode 0400 — do not copy)
  Public key  : %s.pub (send this to your admin)

This keypair has no role until an admin adds it to the trust store.
`, outPath, outPath)

	return nil
}
