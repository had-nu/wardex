// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package art14

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/accept"
	"github.com/had-nu/wardex/v2/pkg/art14"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	configPath     string
	artOutputDir   string
	phase          string
	patchDate      string
	vulnDesc       string
	severity       string
	impact         string
	threatActor    string
	updateDetails  string
	nonInteractive bool

	// For testing
	exitFunc = os.Exit
)

// Art14Cmd is the top-level command for CRA Article 14 notification lifecycle.
var Art14Cmd = &cobra.Command{
	Use:   "art14",
	Short: "Manage CRA Article 14 notification artefacts",
}

func init() {
	Art14Cmd.PersistentFlags().StringVar(&configPath, "config", "./wardex-config.yaml", "Path to wardex-config.yaml")
	Art14Cmd.PersistentFlags().StringVar(&artOutputDir, "dir", "", "Directory containing artefacts (overrides config)")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List generated Article 14 artefacts",
		RunE:  runList,
	}

	showCmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show details of an Article 14 artefact",
		Args:  cobra.ExactArgs(1),
		RunE:  runShow,
	}

	markCmd := &cobra.Command{
		Use:   "mark-dispatched <id>",
		Short: "Mark an Article 14 artefact phase as dispatched",
		Args:  cobra.ExactArgs(1),
		RunE:  runMarkDispatched,
	}
	markCmd.Flags().StringVar(&phase, "phase", "", "Phase to mark as dispatched: early-warning|notification|final-report (required)")
	_ = markCmd.MarkFlagRequired("phase")

	finalizeCmd := &cobra.Command{
		Use:   "finalize <id>",
		Short: "Finalize final report fields of an Article 14 artefact",
		Args:  cobra.ExactArgs(1),
		RunE:  runFinalize,
	}
	finalizeCmd.Flags().StringVar(&patchDate, "patch-date", "", "Patch available date (RFC3339 format, e.g. 2026-06-09T12:00:00Z)")
	finalizeCmd.Flags().StringVar(&vulnDesc, "description", "", "Detailed description of the vulnerability")
	finalizeCmd.Flags().StringVar(&severity, "severity", "", "Severity of the vulnerability")
	finalizeCmd.Flags().StringVar(&impact, "impact", "", "Detailed impact description")
	finalizeCmd.Flags().StringVar(&threatActor, "threat-actor", "", "Information about threat actor/exploitation details")
	finalizeCmd.Flags().StringVar(&updateDetails, "update-details", "", "Details about security update and patch")
	finalizeCmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Disable interactive prompts and use provided flags")

	verifyCmd := &cobra.Command{
		Use:   "verify <id>",
		Short: "Verify HMAC signature integrity of an Article 14 artefact",
		Args:  cobra.ExactArgs(1),
		RunE:  runVerify,
	}

	Art14Cmd.AddCommand(listCmd, showCmd, markCmd, finalizeCmd, verifyCmd)
}

func getOutputDir(cfg *config.Config) string {
	if artOutputDir != "" {
		return artOutputDir
	}
	if cfg.CRA.Art14.OutputDir != "" {
		return cfg.CRA.Art14.OutputDir
	}
	return "."
}

func shortID(id string) string {
	if len(id) > 7 {
		return id[:7]
	}
	return id
}

func shortHMAC(h string) string {
	if len(h) > 8 {
		return h[len(h)-8:]
	}
	return h
}

func statusColor(status string) string {
	switch {
	case strings.HasPrefix(status, "dispatched"):
		return ui.Green
	case status == "draft":
		return ui.Yellow
	default:
		return ui.Red
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func deadlineOverdue(deadline time.Time, status string) bool {
	if deadline.IsZero() {
		return false
	}
	if strings.HasPrefix(status, "dispatched") {
		return false
	}
	return time.Now().UTC().After(deadline)
}

func runList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = &config.Config{}
	}
	dir := getOutputDir(cfg)
	u := beginArt14UI(cmd, "list", dir)
	u.report(1, "Loading artefact directory", "RUNNING", "")
	artefacts, err := art14.ListArtefacts(dir)
	if err != nil {
		u.report(1, "Loading artefact directory", "FAILED", err.Error())
		return fmt.Errorf("list: %w", err)
	}
	u.report(1, "Loading artefact directory", "DONE", fmt.Sprintf("%d artefact(s)", len(artefacts)))

	u.report(2, "Preparing inventory", "RUNNING", "")
	u.report(2, "Preparing inventory", "DONE", "inventory ready")
	if u.progress.Enabled() {
		u.render(buildArt14ListDashboard(artefacts, dir))
		return nil
	}

	if len(artefacts) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No Article 14 artefacts found in %s\n", dir)
		return nil
	}

	w := cmd.OutOrStdout()
	hdr := func(s string, width int) string {
		if ui.IsTerminal(w) {
			return ui.PadANSI(ui.Colorize(s, ui.Cyan+ui.Bold), width)
		}
		return ui.PadANSI(s, width)
	}

	const (
		wID    = 10
		wCVE   = 18
		wDet   = 21
		wEW    = 21
		wNotif = 21
		wStat  = 22
		wHMAC  = 10
	)

	lineChar := '─'
	if !ui.IsTerminal(w) {
		lineChar = '-'
	}
	fill := func(n int) string {
		return strings.Repeat(string(lineChar), n)
	}

	fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s\n",
		hdr("ID", wID), hdr("CVE", wCVE), hdr("Detected", wDet),
		hdr("Early Warning", wEW), hdr("Notification", wNotif),
		hdr("Status", wStat), hdr("HMAC", wHMAC))
	rule := func(value string) string {
		if ui.IsTerminal(w) {
			return ui.Colorize(value, ui.Gray)
		}
		return value
	}
	fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s\n",
		rule(fill(wID)),
		rule(fill(wCVE)),
		rule(fill(wDet)),
		rule(fill(wEW)),
		rule(fill(wNotif)),
		rule(fill(wStat)),
		rule(fill(wHMAC)))

	for _, a := range artefacts {
		id := shortID(a.ArtefactID)
		cves := strings.Join(a.Notification.CVEIDs, ", ")
		if len(cves) > 16 {
			cves = cves[:13] + "..."
		}
		detected := fmtTime(a.EarlyWarning.AwarenessTimestamp)
		ewDeadline := fmtTime(a.EarlyWarning.Deadline)
		notifDeadline := fmtTime(a.Notification.Deadline)

		statusStr := a.Status
		sc := statusColor(a.Status)
		switch statusStr {
		case "draft":
			statusStr = "draft"
		case "dispatched:early-warning":
			statusStr = "EW"
		case "dispatched:notification":
			statusStr = "NT"
		case "dispatched:final-report":
			statusStr = "FR"
		}

		hmacShort := shortHMAC(a.HMAC)

		if ui.IsTerminal(w) {
			if deadlineOverdue(a.EarlyWarning.Deadline, a.Status) {
				ewDeadline = ui.Colorize(ewDeadline, ui.Red)
			}
			if deadlineOverdue(a.Notification.Deadline, a.Status) {
				notifDeadline = ui.Colorize(notifDeadline, ui.Red)
			}
		}

		statusValue := statusStr
		hmacValue := hmacShort
		if ui.IsTerminal(w) {
			statusValue = ui.Colorize(statusStr, sc)
			hmacValue = ui.Colorize(hmacShort, ui.Gray)
		}
		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s\n",
			ui.PadANSI(id, wID),
			ui.PadANSI(cves, wCVE),
			ui.PadANSI(detected, wDet),
			ui.PadANSI(ewDeadline, wEW),
			ui.PadANSI(notifDeadline, wNotif),
			ui.PadANSI(statusValue, wStat),
			ui.PadANSI(hmacValue, wHMAC))
	}

	return nil
}

func runShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = &config.Config{}
	}
	dir := getOutputDir(cfg)
	u := beginArt14UI(cmd, "show", dir)
	u.report(1, "Loading artefact", "RUNNING", args[0])
	_, artefact, err := art14.FindArtefactByID(dir, args[0])
	if err != nil {
		u.report(1, "Loading artefact", "FAILED", err.Error())
		return err
	}
	u.report(1, "Loading artefact", "DONE", shortID(artefact.ArtefactID))
	u.report(2, "Preparing artefact details", "RUNNING", "")
	u.report(2, "Preparing artefact details", "DONE", "details ready")

	if u.progress.Enabled() {
		u.render(buildArt14DetailDashboard(artefact, ""))
		return nil
	}

	data, err := json.MarshalIndent(artefact, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func runMarkDispatched(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = &config.Config{}
	}
	dir := getOutputDir(cfg)
	u := beginArt14UI(cmd, "mark-dispatched", dir)
	u.report(1, "Loading artefact", "RUNNING", args[0])
	path, artefact, err := art14.FindArtefactByID(dir, args[0])
	if err != nil {
		u.report(1, "Loading artefact", "FAILED", err.Error())
		return err
	}
	u.report(1, "Loading artefact", "DONE", shortID(artefact.ArtefactID))

	u.report(2, "Resolving signing secret", "RUNNING", "")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving signing secret", "FAILED", err.Error())
		return fmt.Errorf("mark-dispatched: WARDEX_ACCEPT_SECRET is required to sign dispatched status: %w", err)
	}
	u.report(2, "Resolving signing secret", "DONE", "secret available")

	u.report(3, "Updating dispatch status", "RUNNING", phase)
	if err := art14.MarkDispatched(path, phase, key); err != nil {
		u.report(3, "Updating dispatch status", "FAILED", err.Error())
		return err
	}
	u.report(3, "Updating dispatch status", "DONE", phase)

	logPath := "wardex-gate-audit.log"
	if cfg.Reporting.GateLog.Path != "" {
		logPath = cfg.Reporting.GateLog.Path
	}

	configHash, _ := accept.ConfigHash(configPath)
	entry := model.AuditEntry{
		Timestamp:                     time.Now().UTC(),
		Event:                         "active-exploit.dispatched",
		ConfigHash:                    configHash,
		OverallDecision:               model.DecisionBlock,
		Status:                        "block",
		Detail:                        fmt.Sprintf("Article 14 notification marked as dispatched (phase: %s) for CVE(s): %s", phase, strings.Join(artefact.Notification.CVEIDs, ", ")),
		ActivelyExploited:             artefact.Notification.CVEIDs,
		Art14NotificationArtefactPath: path,
	}

	if err := accept.ChainedAuditLog(logPath, entry); err != nil {
		fmt.Fprintf(u.stderr, "[WARN] Failed to write dispatch event to gate audit log: %v\n", err)
	}

	if u.progress.Enabled() {
		updated, readErr := art14.ReadArtefact(path)
		if readErr == nil {
			u.render(buildArt14DetailDashboard(updated, "marked "+phase))
		}
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Successfully marked artefact %s as dispatched (phase: %s) and re-signed.\n", args[0], phase)
	return nil
}

func runFinalize(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = &config.Config{}
	}
	dir := getOutputDir(cfg)
	u := beginArt14UI(cmd, "finalize", dir)
	u.report(1, "Loading artefact", "RUNNING", args[0])
	path, art, err := art14.FindArtefactByID(dir, args[0])
	if err != nil {
		u.report(1, "Loading artefact", "FAILED", err.Error())
		return err
	}
	u.report(1, "Loading artefact", "DONE", shortID(art.ArtefactID))

	u.report(2, "Resolving signing secret", "RUNNING", "")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving signing secret", "FAILED", err.Error())
		return fmt.Errorf("finalize: WARDEX_ACCEPT_SECRET is required to sign finalized report: %w", err)
	}
	u.report(2, "Resolving signing secret", "DONE", "secret available")

	u.report(3, "Collecting final report", "RUNNING", "")
	if nonInteractive {
		// Use flags
		var pTime time.Time
		if patchDate != "" {
			var err error
			pTime, err = time.Parse(time.RFC3339, patchDate)
			if err != nil {
				u.report(3, "Collecting final report", "FAILED", err.Error())
				return fmt.Errorf("invalid patch-date: %w", err)
			}
		} else {
			pTime = time.Now().UTC()
		}

		art.FinalReport.PatchAvailableAt = pTime
		art.FinalReport.Deadline = pTime.Add(art14.FinalReportWindow)
		if vulnDesc != "" {
			art.FinalReport.VulnerabilityDescription = vulnDesc
		}
		if severity != "" {
			art.FinalReport.Severity = severity
		}
		if impact != "" {
			art.FinalReport.Impact = impact
		}
		if threatActor != "" {
			art.FinalReport.ThreatActorInfo = threatActor
		}
		if updateDetails != "" {
			art.FinalReport.SecurityUpdateDetails = updateDetails
		}
	} else {
		// Interactive mode
		reader := bufio.NewReader(cmd.InOrStdin())
		fmt.Fprint(cmd.OutOrStdout(), "Patch Available Date (RFC3339, default: now): ")
		pStr, _ := reader.ReadString('\n')
		pStr = strings.TrimSpace(pStr)
		pTime := time.Now().UTC()
		if pStr != "" {
			var err error
			pTime, err = time.Parse(time.RFC3339, pStr)
			if err != nil {
				u.report(3, "Collecting final report", "FAILED", err.Error())
				return fmt.Errorf("invalid date format: %w", err)
			}
		}

		fmt.Fprint(cmd.OutOrStdout(), "Vulnerability Description: ")
		desc, _ := reader.ReadString('\n')
		desc = strings.TrimSpace(desc)

		fmt.Fprint(cmd.OutOrStdout(), "Severity: ")
		sev, _ := reader.ReadString('\n')
		sev = strings.TrimSpace(sev)

		fmt.Fprint(cmd.OutOrStdout(), "Impact: ")
		imp, _ := reader.ReadString('\n')
		imp = strings.TrimSpace(imp)

		fmt.Fprint(cmd.OutOrStdout(), "Threat Actor Info: ")
		ta, _ := reader.ReadString('\n')
		ta = strings.TrimSpace(ta)

		fmt.Fprint(cmd.OutOrStdout(), "Security Update Details: ")
		sud, _ := reader.ReadString('\n')
		sud = strings.TrimSpace(sud)

		art.FinalReport.PatchAvailableAt = pTime
		art.FinalReport.Deadline = pTime.Add(art14.FinalReportWindow)
		if desc != "" {
			art.FinalReport.VulnerabilityDescription = desc
		}
		if sev != "" {
			art.FinalReport.Severity = sev
		}
		if imp != "" {
			art.FinalReport.Impact = imp
		}
		if ta != "" {
			art.FinalReport.ThreatActorInfo = ta
		}
		if sud != "" {
			art.FinalReport.SecurityUpdateDetails = sud
		}
	}
	u.report(3, "Collecting final report", "DONE", "final report fields ready")

	u.report(4, "Signing and writing artefact", "RUNNING", "")
	if err := art14.SignArtefact(art, key); err != nil {
		u.report(4, "Signing and writing artefact", "FAILED", err.Error())
		return err
	}

	data, err := json.MarshalIndent(art, "", "  ")
	if err != nil {
		u.report(4, "Signing and writing artefact", "FAILED", err.Error())
		return err
	}

	if err := cli.SafeWriteFile(path, data); err != nil {
		u.report(4, "Signing and writing artefact", "FAILED", err.Error())
		return err
	}
	u.report(4, "Signing and writing artefact", "DONE", "artefact re-signed")

	if u.progress.Enabled() {
		updated, readErr := art14.ReadArtefact(path)
		if readErr == nil {
			u.render(buildArt14DetailDashboard(updated, "finalized"))
		}
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Successfully finalized artefact %s and re-signed.\n", args[0])
	return nil
}

func runVerify(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = &config.Config{}
	}
	dir := getOutputDir(cfg)
	u := beginArt14UI(cmd, "verify", dir)
	u.report(1, "Loading artefact", "RUNNING", args[0])
	_, artefact, err := art14.FindArtefactByID(dir, args[0])
	if err != nil {
		u.report(1, "Loading artefact", "FAILED", err.Error())
		return err
	}
	u.report(1, "Loading artefact", "DONE", shortID(artefact.ArtefactID))

	u.report(2, "Resolving verification secret", "RUNNING", "")
	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		u.report(2, "Resolving verification secret", "FAILED", err.Error())
		return fmt.Errorf("verify: WARDEX_ACCEPT_SECRET is required for Art. 14 HMAC verification.\n\nHINT: Generate a key with:\n  openssl rand -base64 32\n\nThen export:\n  export WARDEX_ACCEPT_SECRET=\"$(openssl rand -base64 32)\"\n\nOriginal error: %w", err)
	}
	u.report(2, "Resolving verification secret", "DONE", "secret available")

	u.report(3, "Verifying HMAC integrity", "RUNNING", "")
	err = art14.VerifyArtefact(artefact, key)
	if err != nil {
		u.report(3, "Verifying HMAC integrity", "FAILED", err.Error())
		if u.progress.Enabled() {
			u.render(buildArt14DetailDashboard(artefact, "verification failed"))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "[TAMPERED] HMAC verification failed for %s: %v\n", args[0], err)
		}
		exitFunc(exitcodes.IntegrityFailure)
		return nil
	}
	u.report(3, "Verifying HMAC integrity", "DONE", "integrity valid")
	if u.progress.Enabled() {
		u.render(buildArt14DetailDashboard(artefact, "verified"))
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "[PASS] HMAC integrity verification passed for %s\n", args[0])
	return nil
}
