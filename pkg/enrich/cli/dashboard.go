// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"fmt"
	"io"

	"github.com/had-nu/wardex/v3/pkg/ui"
	"github.com/spf13/cobra"
)

type enrichUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func beginEnrichUI(cmd *cobra.Command, input, output string) *enrichUI {
	stderr := cmd.ErrOrStderr()
	outputWriter := cmd.OutOrStdout()
	progress := ui.NewTerminalProgressForOutput(stderr, outputWriter)
	progress.Begin(ui.SessionView{
		Title:  "EPSS ENRICHMENT SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "INPUT", Value: input},
			{Label: "OUTPUT", Value: output},
		},
	})
	return &enrichUI{
		progress:          progress,
		stderr:            stderr,
		output:            outputWriter,
		resultInteractive: ui.IsTerminal(outputWriter) && ui.IsTerminal(stderr),
	}
}

func (u *enrichUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *enrichUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *enrichUI) render(count int) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, ui.Dashboard{Summary: ui.SummaryView{
		Decision: "ENRICHED",
		Fields: []ui.Field{
			{Label: "SCORES", Value: fmt.Sprintf("%d", count)},
			{Label: "FORMAT", Value: "signed YAML"},
		},
	}})
}
