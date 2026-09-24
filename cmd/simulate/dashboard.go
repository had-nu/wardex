// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package simulate

import (
	"fmt"
	"io"

	"github.com/had-nu/wardex/v2/pkg/ui"
)

func buildSimulatorSession(outputPath string) ui.SessionView {
	return ui.SessionView{
		Title:  "SIMULATOR SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "OUTPUT", Value: outputPath},
			{Label: "FORMAT", Value: "HTML"},
		},
	}
}

func buildSimulatorDashboard(outputPath string, size int) ui.Dashboard {
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: "READY",
			Fields: []ui.Field{
				{Label: "FILE", Value: outputPath},
				{Label: "SIZE", Value: fmt.Sprintf("%d bytes", size)},
				{Label: "FORMAT", Value: "standalone HTML"},
			},
		},
	}
}

func renderSimulatorResults(w io.Writer, progress *ui.TerminalProgress, outputPath string, size int) {
	dashboard := buildSimulatorDashboard(outputPath, size)
	if progress != nil && progress.Enabled() {
		_ = ui.RenderResults(w, dashboard)
		return
	}
	_ = ui.RenderDashboard(w, dashboard)
}
