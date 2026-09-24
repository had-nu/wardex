// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package keygen

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

func keygenCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func keygenResultEnabled(cmd *cobra.Command, progress *ui.TerminalProgress) bool {
	return progress != nil && progress.Enabled() && ui.IsTerminal(keygenCommandOutput(cmd))
}

func buildKeygenSession(outPath string, encrypted, force bool) ui.SessionView {
	protection := "standard private key"
	if encrypted {
		protection = "encrypted envelope v1"
	}
	overwrite := "no"
	if force {
		overwrite = "yes"
	}
	return ui.SessionView{
		Title:  "KEY GENERATION SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "PRIVATE KEY", Value: outPath},
			{Label: "PROTECTION", Value: protection},
			{Label: "OVERWRITE", Value: overwrite},
		},
	}
}

func buildKeygenDashboard(outPath string, publicKey ed25519.PublicKey, encrypted bool) ui.Dashboard {
	fingerprint := "unknown"
	if len(publicKey) > 0 {
		end := min(8, len(publicKey))
		fingerprint = fmt.Sprintf("%x", publicKey[:end])
	}
	protection := "standard private key"
	if encrypted {
		protection = "encrypted envelope v1"
	}
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: "GENERATED",
			Fields: []ui.Field{
				{Label: "PRIVATE KEY", Value: outPath},
				{Label: "PUBLIC KEY", Value: outPath + ".pub"},
				{Label: "PROTECTION", Value: protection},
				{Label: "FINGERPRINT", Value: fingerprint},
			},
		},
	}
}
