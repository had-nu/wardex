// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package assets

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type assetsUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func assetsCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func beginAssetsUI(cmd *cobra.Command, path, format string) *assetsUI {
	stderr := io.Writer(os.Stderr)
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	output := assetsCommandOutput(cmd)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(ui.SessionView{
		Title:  "ASSET INVENTORY SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "INPUT", Value: path},
			{Label: "FORMAT", Value: format},
		},
	})
	return &assetsUI{
		progress:          progress,
		stderr:            stderr,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *assetsUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *assetsUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *assetsUI) render(path string, assets []assetEntry) {
	if !u.dashboardEnabled() {
		return
	}
	dashboard := ui.Dashboard{}
	internetFacing := 0
	for _, asset := range assets {
		if asset.Exposure.InternetFacing {
			internetFacing++
		}
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "ICT ASSET",
			Severity: assetSeverity(asset.Criticality),
			Title:    assetTitle(asset),
			Fields: []ui.Field{
				{Label: "ASSET ID", Value: asset.ID},
				{Label: "TYPE", Value: asset.Type},
				{Label: "CRITICALITY", Value: fmt.Sprintf("%.2f", asset.Criticality)},
				{Label: "INTERNET", Value: fmt.Sprintf("%t", asset.Exposure.InternetFacing)},
				{Label: "ZONE", Value: asset.Exposure.NetworkZone},
				{Label: "OWNER", Value: asset.Owner},
				{Label: "CONTROLS", Value: fmt.Sprintf("%d", len(asset.Controls))},
			},
		})
	}
	dashboard.Summary = ui.SummaryView{
		Decision: "LOADED",
		Fields: []ui.Field{
			{Label: "INPUT", Value: path},
			{Label: "ASSETS", Value: fmt.Sprintf("%d", len(assets))},
			{Label: "INTERNET-FACING", Value: fmt.Sprintf("%d", internetFacing)},
		},
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func assetSeverity(criticality float64) string {
	switch {
	case criticality >= 0.8:
		return "HIGH"
	case criticality >= 0.5:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func assetTitle(asset assetEntry) string {
	if strings.TrimSpace(asset.Name) != "" {
		return asset.Name
	}
	return asset.ID
}
