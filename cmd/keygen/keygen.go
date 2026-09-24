// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package keygen

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	outPath    string
	force      bool
	encrypt    bool
	passphrase string
)

// KeygenCmd generates an ed25519 keypair for use with the Wardex trust system.
var KeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an ed25519 keypair for the Wardex trust system",
	Long: `Generate an ed25519 keypair. The private key is written with mode 0400
(read-only for the owner). The public key is written alongside with a .pub extension.

Keys are stored in ~/.crypto/trust/ by default. The keypair has no role until
an admin adds the public key to the trust store via 'wardex trust add'.

With --encrypt, the private key is sealed in an opt-in encrypted envelope (L6):
Argon2id derivation + AES-256-GCM with a verification tag (store-cipher pattern).
The passphrase is read from --passphrase or the WARDEX_KEY_PASSPHRASE
environment variable; WARDEX_KEY_PASSPHRASE is used automatically at load time.`,
	RunE: runKeygen,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultPath := filepath.Join(home, ".crypto", "trust", "root.key")

	KeygenCmd.Flags().StringVar(&outPath, "out", defaultPath, "Path for the private key")
	KeygenCmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing key (requires confirmation)")
	KeygenCmd.Flags().BoolVar(&encrypt, "encrypt", false, "Seal the private key in an encrypted envelope (Argon2id + AES-256-GCM)")
	KeygenCmd.Flags().StringVar(&passphrase, "passphrase", "", "Passphrase for the encrypted envelope (or WARDEX_KEY_PASSPHRASE)")
}

func runKeygen(cmd *cobra.Command, _ []string) error {
	stderr := cmd.ErrOrStderr()
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(buildKeygenSession(outPath, encrypt, force))
	reportProgress := func(number int, name, status, detail string) {
		progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
	}

	reportProgress(1, "Validating key options", "RUNNING", "")
	var publicKey []byte
	var err error
	if encrypt {
		pass := passphrase
		if pass == "" {
			pass = os.Getenv("WARDEX_KEY_PASSPHRASE")
		}
		if pass == "" {
			err = fmt.Errorf("keygen: --encrypt requires --passphrase or WARDEX_KEY_PASSPHRASE")
			reportProgress(1, "Validating key options", "FAILED", err.Error())
			return err
		}
		reportProgress(1, "Validating key options", "DONE", "encrypted mode")
		reportProgress(2, "Generating keypair", "RUNNING", "")
		publicKey, err = trust.GenerateKeypairEncrypted(outPath, force, pass)
	} else {
		reportProgress(1, "Validating key options", "DONE", "standard mode")
		reportProgress(2, "Generating keypair", "RUNNING", "")
		publicKey, err = trust.GenerateKeypair(outPath, force)
	}
	if err != nil {
		reportProgress(2, "Generating keypair", "FAILED", err.Error())
		return err
	}
	reportProgress(2, "Generating keypair", "DONE", outPath)

	reportProgress(3, "Finalizing key metadata", "RUNNING", "")
	reportProgress(3, "Finalizing key metadata", "DONE", "keypair ready")
	if keygenResultEnabled(cmd, progress) {
		_ = ui.RenderResults(stderr, buildKeygenDashboard(outPath, publicKey, encrypt))
		return nil
	}

	w := keygenCommandOutput(cmd)
	if encrypt {
		fmt.Fprintln(w, "Encrypted keypair generated (envelope v1 — Argon2id + AES-256-GCM).")
	} else {
		fmt.Fprintln(w, "Keypair generated.")
	}
	privateLabel, publicLabel := "Private key:", "Public key:"
	if ui.IsTerminal(w) {
		privateLabel = ui.Colorize(privateLabel, ui.Gray)
		publicLabel = ui.Colorize(publicLabel, ui.Gray)
	}
	fmt.Fprintf(w, "  %s %s     (mode 0400 — do not copy)\n", privateLabel, outPath)
	fmt.Fprintf(w, "  %s %s.pub (send this to your admin)\n\n", publicLabel, outPath)
	fmt.Fprintln(w, "This keypair has no role until an admin adds it to the trust store.")
	return nil
}
