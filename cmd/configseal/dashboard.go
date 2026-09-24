// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package configseal

import (
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

func configCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func configResultEnabled(cmd *cobra.Command, progress *ui.TerminalProgress) bool {
	return progress != nil && progress.Enabled() && ui.IsTerminal(configCommandOutput(cmd))
}

func buildConfigSealSession(keyring, input, output, trustRef string) ui.SessionView {
	return ui.SessionView{
		Title:  "CONFIG SEAL SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "KEYRING", Value: keyring},
			{Label: "INPUT", Value: input},
			{Label: "OUTPUT", Value: output},
			{Label: "TRUST", Value: trustRef},
		},
	}
}

func buildConfigSealDashboard(input, output, trustRef string) ui.Dashboard {
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: "SEALED",
			Fields: []ui.Field{
				{Label: "INPUT", Value: input},
				{Label: "OUTPUT", Value: output},
				{Label: "TRUST", Value: trustRef},
				{Label: "NEXT", Value: "wardex evaluate"},
			},
		},
	}
}

func buildConfigHashSession(path, algorithm string) ui.SessionView {
	return ui.SessionView{
		Title:  "CONFIG HASH SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "CONFIG", Value: path},
			{Label: "ALGORITHM", Value: algorithm},
		},
	}
}

func buildConfigHashDashboard(path, algorithm, hash string) ui.Dashboard {
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: "COMPUTED",
			Fields: []ui.Field{
				{Label: "CONFIG", Value: path},
				{Label: "ALGORITHM", Value: algorithm},
				{Label: "HASH", Value: hash},
			},
		},
	}
}

func buildConfigShowSession(path string) ui.SessionView {
	return ui.SessionView{
		Title:  "CONFIG INSPECTION SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "CONFIG", Value: path},
		},
	}
}

func buildConfigShowDashboard(path, hash string, cfg *config.Config) ui.Dashboard {
	return ui.Dashboard{
		Summary: ui.SummaryView{
			Decision: "LOADED",
			Fields: []ui.Field{
				{Label: "CONFIG", Value: path},
				{Label: "HASH", Value: hash},
				{Label: "RISK APPETITE", Value: fmt.Sprintf("%.2f", cfg.ReleaseGate.RiskAppetite)},
				{Label: "WARN ABOVE", Value: fmt.Sprintf("%.2f", cfg.ReleaseGate.WarnAbove)},
				{Label: "GATE MODE", Value: cfg.ReleaseGate.Mode},
				{Label: "GATE ENABLED", Value: fmt.Sprintf("%t", cfg.ReleaseGate.Enabled)},
				{Label: "CRA ART.14", Value: fmt.Sprintf("%t", cfg.CRA.Art14.ProductName != "")},
				{Label: "STATE STORE", Value: fmt.Sprintf("%t", cfg.StateStore.Enabled)},
				{Label: "REPORTING", Value: cfg.Reporting.Format},
			},
		},
	}
}

func renderConfigSealResults(w io.Writer, progress *ui.TerminalProgress, input, output, trustRef string) {
	dashboard := buildConfigSealDashboard(input, output, trustRef)
	if progress != nil && progress.Enabled() {
		_ = ui.RenderResults(w, dashboard)
		return
	}
	_ = ui.RenderDashboard(w, dashboard)
}
