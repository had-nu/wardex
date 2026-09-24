// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package hmac

import (
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type hmacUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func hmacCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginHMACUI(cmd *cobra.Command, payload string) *hmacUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := hmacCommandOutput(cmd)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "HMAC SIGNATURE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "PAYLOAD", Value: payload},
			{Label: "ALGORITHM", Value: "HMAC-SHA256"},
		},
	})
	return &hmacUI{
		progress:          progress,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *hmacUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *hmacUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *hmacUI) render(output string, size int, signature string) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, ui.Dashboard{Summary: ui.SummaryView{
		Decision: "SIGNED",
		Fields: []ui.Field{
			{Label: "OUTPUT", Value: output},
			{Label: "PAYLOAD SIZE", Value: fmt.Sprintf("%d bytes", size)},
			{Label: "SIGNATURE", Value: signature + "..."},
		},
	}})
}
