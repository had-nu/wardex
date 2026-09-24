// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

type acceptUI struct {
	progress          *ui.TerminalProgress
	stderr            io.Writer
	output            io.Writer
	resultInteractive bool
}

func acceptCommandOutput(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func acceptErrorWriter(cmd *cobra.Command) io.Writer {
	// The package-level writer is an intentional test seam. In normal
	// execution it is os.Stderr, so prefer Cobra's configured error writer.
	if file, ok := stderr.(*os.File); ok && file == os.Stderr && cmd != nil {
		if configured := cmd.ErrOrStderr(); configured != nil {
			return configured
		}
	}
	if stderr != nil {
		return stderr
	}
	return os.Stderr
}

func beginAcceptUI(cmd *cobra.Command, command, detail string) *acceptUI {
	writer := acceptErrorWriter(cmd)
	output := acceptCommandOutput(cmd)
	progress := ui.NewTerminalProgress(writer)
	progress.Begin(ui.SessionView{
		Title:  "RISK ACCEPTANCE SESSION",
		Status: "RUNNING",
		Fields: []ui.Field{
			{Label: "COMMAND", Value: strings.ToUpper(command)},
			{Label: "TARGET", Value: detail},
		},
	})
	return &acceptUI{
		progress:          progress,
		stderr:            writer,
		output:            output,
		resultInteractive: ui.IsTerminal(output),
	}
}

func (u *acceptUI) dashboardEnabled() bool {
	return u != nil && u.progress != nil && u.progress.Enabled() && u.resultInteractive
}

func (u *acceptUI) report(number int, name, status, detail string) {
	if u == nil || u.progress == nil {
		return
	}
	u.progress.Report(ui.PhaseEvent{Number: number, Name: name, Status: status, Detail: detail})
}

func (u *acceptUI) render(dashboard ui.Dashboard) {
	if !u.dashboardEnabled() {
		return
	}
	_ = ui.RenderResults(u.stderr, dashboard)
}

func acceptPrint(u *acceptUI, format string, args ...any) {
	if u != nil && u.dashboardEnabled() {
		return
	}
	writer := io.Writer(os.Stdout)
	if u != nil && u.output != nil {
		writer = u.output
	}
	fmt.Fprintf(writer, format, args...)
}

func safeBackendLabel(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "configured endpoint"
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		// Bare host:port values are useful diagnostics, but anything that
		// resembles a URL or carries userinfo/query data is not safe to echo.
		if strings.ContainsAny(raw, "@?/#") {
			return "configured endpoint"
		}
		return raw
	}
	// Keep only the scheme and authority in human-facing diagnostics. Query
	// strings, paths, fragments and userinfo commonly carry tokens/passwords.
	return parsed.Scheme + "://" + parsed.Host
}

func safeBackendError(err error, raw string) string {
	if err == nil {
		return ""
	}
	// URL errors can include a redirect target, escaped userinfo or query
	// parameters that differ from the original input. Do not echo them.
	if parsed, parseErr := url.Parse(raw); parseErr == nil && parsed.Scheme != "" && parsed.Host != "" {
		return "request failed"
	}
	if strings.Contains(raw, "://") {
		return "request failed"
	}
	detail := err.Error()
	if raw != "" {
		detail = strings.ReplaceAll(detail, raw, safeBackendLabel(raw))
	}
	return detail
}

func buildAcceptVerifyDashboard(total int, configHash, output string) ui.Dashboard {
	fields := []ui.Field{
		{Label: "ACCEPTANCES", Value: fmt.Sprintf("%d", total)},
		{Label: "CONFIG HASH", Value: configHash},
	}
	if output != "" {
		fields = append(fields, ui.Field{Label: "REPORT", Value: output})
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "ACCEPTANCE STORE",
			Severity: "LOW",
			Title:    "PASS",
			Fields:   fields,
		}},
		Summary: ui.SummaryView{
			Decision: "VERIFIED",
			Fields: []ui.Field{
				{Label: "TOTAL", Value: fmt.Sprintf("%d", total)},
				{Label: "STATUS", Value: "PASS"},
			},
		},
	}
}

func buildAcceptRequestDashboard(report string, cves, ids []string, acceptedBy string, reportHash string) ui.Dashboard {
	fields := []ui.Field{
		{Label: "REPORT", Value: report},
		{Label: "REPORT HASH", Value: reportHash},
		{Label: "CVES", Value: fmt.Sprintf("%d", len(cves))},
		{Label: "CREATED", Value: fmt.Sprintf("%d", len(ids))},
	}
	if acceptedBy != "" {
		fields = append(fields, ui.Field{Label: "ACCEPTED BY", Value: acceptedBy})
	}
	return ui.Dashboard{
		Findings: []ui.FindingView{{
			Kind:     "RISK ACCEPTANCE",
			Severity: "LOW",
			Title:    "CREATED",
			Fields:   fields,
		}},
		Summary: ui.SummaryView{
			Decision: "CREATED",
			Fields: []ui.Field{
				{Label: "CREATED", Value: fmt.Sprintf("%d", len(ids))},
				{Label: "STATUS", Value: "RECORDED"},
			},
		},
	}
}

type expiringAcceptance struct {
	ID      string
	CVE     string
	Expires time.Time
}

func buildAcceptExpiryDashboard(expiring []expiringAcceptance) ui.Dashboard {
	decision := "CLEAR"
	severity := "LOW"
	if len(expiring) > 0 {
		decision = "REVIEW"
		severity = "MEDIUM"
	}
	dashboard := ui.Dashboard{}
	for _, acceptance := range expiring {
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "ACCEPTANCE EXPIRY",
			Severity: severity,
			Title:    acceptance.CVE,
			Fields: []ui.Field{
				{Label: "ACCEPTANCE", Value: acceptance.ID},
				{Label: "CVE", Value: acceptance.CVE},
				{Label: "EXPIRES", Value: acceptance.Expires.UTC().Format(time.RFC3339)},
			},
		})
	}
	dashboard.Summary = ui.SummaryView{
		Decision: decision,
		Fields: []ui.Field{
			{Label: "EXPIRING", Value: fmt.Sprintf("%d", len(expiring))},
			{Label: "WINDOW", Value: expiryWarnBefore},
		},
	}
	return dashboard
}

func buildAcceptListDashboard(acceptances []model.Acceptance, filter string) ui.Dashboard {
	dashboard := ui.Dashboard{}
	active, expired, revoked := 0, 0, 0
	now := time.Now()
	for _, acceptance := range acceptances {
		status := "VALID"
		severity := "LOW"
		switch {
		case acceptance.Revoked:
			status = "REVOKED"
			severity = "HIGH"
			revoked++
		case now.After(acceptance.ExpiresAt):
			status = "EXPIRED"
			severity = "HIGH"
			expired++
		default:
			active++
		}
		if len(dashboard.Findings) >= 25 {
			continue
		}
		dashboard.Findings = append(dashboard.Findings, ui.FindingView{
			Kind:     "RISK ACCEPTANCE",
			Severity: severity,
			Title:    acceptance.CVE,
			Fields: []ui.Field{
				{Label: "ID", Value: acceptance.ID},
				{Label: "CVE", Value: acceptance.CVE},
				{Label: "ACCEPTED BY", Value: acceptance.AcceptedBy},
				{Label: "EXPIRES", Value: acceptance.ExpiresAt.UTC().Format("2006-01-02")},
				{Label: "STATUS", Value: status},
			},
		})
	}
	dashboard.Summary = ui.SummaryView{
		Decision: "LOADED",
		Fields: []ui.Field{
			{Label: "FILTER", Value: filter},
			{Label: "TOTAL", Value: fmt.Sprintf("%d", len(acceptances))},
			{Label: "VALID", Value: fmt.Sprintf("%d", active)},
			{Label: "EXPIRED", Value: fmt.Sprintf("%d", expired)},
			{Label: "REVOKED", Value: fmt.Sprintf("%d", revoked)},
		},
	}
	return dashboard
}

func buildAcceptRevokeDashboard(id, revokedBy string) ui.Dashboard {
	return ui.Dashboard{Summary: ui.SummaryView{
		Decision: "REVOKED",
		Fields: []ui.Field{
			{Label: "ACCEPTANCE", Value: id},
			{Label: "REVOKED BY", Value: revokedBy},
		},
	}}
}

func buildAcceptForwardingUnavailableDashboard(logPath string) ui.Dashboard {
	return ui.Dashboard{Summary: ui.SummaryView{
		Decision: "NO EVENTS",
		Fields: []ui.Field{
			{Label: "AUDIT LOG", Value: logPath},
			{Label: "EVENTS", Value: "0"},
		},
	}}
}

func buildAcceptForwardingDashboard(logPath string, size int64, events int, since string, backendConfigured bool) ui.Dashboard {
	backend := "not configured"
	if backendConfigured {
		backend = "configured"
	}
	return ui.Dashboard{Summary: ui.SummaryView{
		Decision: "FORWARDING READY",
		Fields: []ui.Field{
			{Label: "AUDIT LOG", Value: logPath},
			{Label: "LOG SIZE", Value: fmt.Sprintf("%d bytes", size)},
			{Label: "EVENTS", Value: fmt.Sprintf("%d", events)},
			{Label: "SINCE", Value: since},
			{Label: "BACKEND", Value: backend},
		},
	}}
}

func buildAcceptActiveExploitDashboard(cve, artefactPath string) ui.Dashboard {
	artefact := "not supplied"
	if artefactPath != "" {
		artefact = artefactPath
	}
	return ui.Dashboard{Summary: ui.SummaryView{
		Decision: "ACKNOWLEDGED",
		Fields: []ui.Field{
			{Label: "CVE", Value: cve},
			{Label: "ARTEFACT", Value: artefact},
			{Label: "AUDIT", Value: "chained entry written"},
		},
	}}
}
