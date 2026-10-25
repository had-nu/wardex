// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package chain

import (
	"fmt"
	"io"

	"github.com/had-nu/wardex/v3/pkg/ui"
	"github.com/spf13/cobra"
)

type chainUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func beginChainUI(cmd *cobra.Command, baseDir, output string) *chainUI {
	stderr := cmd.ErrOrStderr()
	outputWriter := cmd.OutOrStdout()
	progress := ui.NewTerminalProgressForOutput(stderr, outputWriter)
	progress.Begin(ui.SessionView{
		Title:  "CHAIN SEAL SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "BASE DIRECTORY", Value: baseDir},
			{Label: "OUTPUT", Value: output},
		},
	})
	return &chainUI{
		progress:          progress,
		stderr:            stderr,
		output:            outputWriter,
		resultInteractive: ui.IsTerminal(outputWriter) && ui.IsTerminal(stderr),
	}
}

func (u *chainUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *chainUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *chainUI) render(output string, files int, hash string) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, ui.Dashboard{Summary: ui.SummaryView{
		Decision: "SEALED",
		Fields: []ui.Field{
			{Label: "OUTPUT", Value: output},
			{Label: "FILES", Value: fmt.Sprintf("%d", files)},
			{Label: "CHAIN HASH", Value: hash},
		},
	}})
}
