// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/pkg/accept"
	"github.com/had-nu/wardex/v2/pkg/accept/cli"
	"github.com/had-nu/wardex/v2/pkg/art14"
	"github.com/had-nu/wardex/v2/pkg/epss"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/ingestion"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/releasegate"
	"github.com/had-nu/wardex/v2/pkg/statestore"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/had-nu/wardex/v2/pkg/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	configPath     string
	gateFile       string
	gateMode       string
	epssEnrich     string
	outputFormat   string
	outFile        string
	profileName    string
	failAbove      float64
	strict         bool
	dryRun         bool
	gateLogPath    string
	art14OutputDir string // NEW in v2.0
	showTrend      bool   // NEW in v2.3 — show trend analysis

	// For testing
	exitFunc = os.Exit
	stderr   = os.Stderr
)

// EvaluateCmd is the explicit release gate evaluation subcommand.
// It validates the gate decision without performing gap analysis,
// making it suitable as a focused CI step after the policy files
// have already been validated with 'wardex policy validate'.
var EvaluateCmd = &cobra.Command{
	Use:   "evaluate [flags] <controls-file(s)>",
	Short: "Evaluate the release gate against a vulnerability file",
	Long: `Evaluate the release gate decision based on your policy controls and a
vulnerability evidence file. Exits with code 10 if the gate blocks the release.

This command is a focused alias for the gate evaluation portion of the root
wardex command, intended for use in CI steps where the gap analysis report
is not needed — only the gate decision.

Example:
  wardex evaluate \
    --config   ./wardex-config.yaml \
    --evidence ./wardex-vulns.yaml \
    ./frameworks/iso27001/*.yml

Exit codes:
   0 — Gate passed (ALLOW)
   3 — Seal integrity failure (revoked key, trust store drift, invalid sig)
       Also returned if --strict is used with an unsealed config.
  10 — Gate blocked (BLOCK)
  11 — Compliance gap exceeded --fail-above threshold
  12 — Active exploitation detected (hard stop)`,
	Args: cobra.MinimumNArgs(1),
	RunE: runEvaluate,
}

func init() {
	EvaluateCmd.Flags().StringVar(&configPath, "config", "./wardex-config.yaml", "Path to wardex-config.yaml or wardex.wexstate")
	EvaluateCmd.Flags().StringVar(&gateFile, "evidence", "", "Vulnerabilities file for release gate evaluation (required)")
	EvaluateCmd.Flags().StringVar(&gateMode, "gate-mode", "any", "Gate mode: any|aggregate")
	EvaluateCmd.Flags().StringVar(&epssEnrich, "epss-enrichment", "", "Path to a signed EPSS enrichment file")
	EvaluateCmd.Flags().StringVar(&outputFormat, "output", "markdown", "Output format: markdown|json|csv")
	EvaluateCmd.Flags().StringVar(&outFile, "out-file", "stdout", "Output file destination")
	EvaluateCmd.Flags().StringVar(&profileName, "profile", "", "RBAC threshold override profile")
	EvaluateCmd.Flags().Float64Var(&failAbove, "fail-above", 0.0, "Exit 11 if any gap score exceeds this value")
	EvaluateCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate inputs and show what would happen without writing any files or exiting with error codes")
	EvaluateCmd.Flags().BoolVar(&strict, "strict", false, "Exit 3 if an unsealed config (.yaml) is used or if evidence is not canonical")
	EvaluateCmd.Flags().StringVar(&gateLogPath, "gate-log", "", "Path to gate decision audit log (overrides config)")
	EvaluateCmd.Flags().StringVar(&art14OutputDir, "art14-output-dir", "", "Directory where Article 14 notification artefacts are written (overrides config)")
	EvaluateCmd.Flags().BoolVar(&showTrend, "trend", false, "Show risk trend analysis from state store (requires state_store.enabled)")
	_ = EvaluateCmd.MarkFlagRequired("evidence")

	// Allow the parent to inject the shared --config persistent flag.
	cli.AddCommands(EvaluateCmd, &configPath)
}

func runEvaluate(cmd *cobra.Command, args []string) error {
	cfg, err := loadEvalConfig(configPath, strict, profileName)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		exitFunc(exitcodes.IntegrityFailure)
		return nil
	}

	if !cfg.ReleaseGate.Enabled {
		fmt.Fprintf(stderr, "Warning: release_gate.enabled is false in config — gate will always ALLOW.\n")
	}

	if strict {
		if _, err := accept.ConfigHash(configPath); err != nil {
			fmt.Fprintf(stderr, "[STRICT ENFORCEMENT] config hash computation failed: %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}
	}

	// Load controls for context (needed for ingestion but gate is the primary output)
	_, err = ingestion.LoadMany(args)
	if err != nil {
		return fmt.Errorf("evaluate: load controls: %w", err)
	}

	gateModeVal := "any"
	if cfg.ReleaseGate.Mode != "" {
		gateModeVal = cfg.ReleaseGate.Mode
	}
	if gateMode != "any" {
		gateModeVal = gateMode
	}

	gate := releasegate.Gate{
		AssetContext:         cfg.ReleaseGate.AssetContext,
		CompensatingControls: cfg.ReleaseGate.CompensatingControls,
		RiskAppetite:         cfg.ReleaseGate.RiskAppetite,
		WarnAbove:            cfg.ReleaseGate.WarnAbove,
		AggregateLimit:       cfg.ReleaseGate.AggregateLimit,
		Mode:                 gateModeVal,
	}

	cwd, _ := os.Getwd()
	vulns, evidenceHash, err := loadEvidence(gateFile, cwd, strict)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	// CRA Article 14 Active Exploitation Hard Stop (Layer 4)
	var activelyExploited []model.Vulnerability
	for _, v := range vulns {
		if v.ActivelyExploited {
			activelyExploited = append(activelyExploited, v)
		}
	}

	if len(activelyExploited) > 0 {
		outDir := "."
		if cfg.CRA.Art14.OutputDir != "" {
			outDir = cfg.CRA.Art14.OutputDir
		}
		if art14OutputDir != "" {
			outDir = art14OutputDir
		}

		// Check for undispatched previous artefacts
		if previousArtefacts, err := art14.ListArtefacts(outDir); err == nil {
			for _, prev := range previousArtefacts {
				if !art14.IsDispatched(prev) {
					for _, cve := range prev.Notification.CVEIDs {
						for _, curr := range activelyExploited {
							if curr.CVEID == cve {
								fmt.Fprintf(stderr, "[WARN] Previously generated notification artefact for %s (ID: %s) has not been marked as dispatched.\n", cve, prev.ArtefactID)
								break
							}
						}
					}
				}
			}
		}

		var cves []string
		for _, v := range activelyExploited {
			cves = append(cves, v.CVEID)
		}

		if dryRun {
			fmt.Fprintf(stderr, "[DRY-RUN] Active exploitation detected for CVE(s): %s\n", strings.Join(cves, ", "))
			fmt.Fprintf(stderr, "[DRY-RUN] Article 14 notification artefact would be written to: %s\n", outDir)
			fmt.Fprintf(stderr, "[DRY-RUN] Gate would BLOCK with exit code %d (ActivelyExploited)\n", exitcodes.ActivelyExploited)
			exitFunc(exitcodes.OK)
			return nil
		}

		// Calculate awareness timestamp
		awarenessAt := time.Now().UTC()
		if cfg.CRA.Art14.AwarenessSource == "envelope" {
			var earliest time.Time
			for _, v := range activelyExploited {
				if !v.ActivelyExploitedSince.IsZero() {
					if earliest.IsZero() || v.ActivelyExploitedSince.Before(earliest) {
						earliest = v.ActivelyExploitedSince
					}
				}
			}
			if !earliest.IsZero() && earliest.Before(awarenessAt) {
				awarenessAt = earliest.UTC()
			}
		}

		art14Cfg := art14.Config{
			ProductName:    cfg.CRA.Art14.ProductName,
			ProductVersion: cfg.CRA.Art14.ProductVersion,
			GeneratedBy:    "wardex/v2.0.0",
			WardexActor:    os.Getenv("WARDEX_ACTOR"),
		}

		artefact, err := art14.GenerateArtefact(cves, awarenessAt, art14Cfg)
		if err != nil {
			return fmt.Errorf("evaluate: generate Article 14 notification artefact: %w", err)
		}

		key, err := accept.ResolveSecret(*cfg)
		if err != nil {
			return fmt.Errorf("evaluate: %w. Set WARDEX_ACCEPT_SECRET to generate a signed CRA Article 14 artefact", err)
		}
		if err := art14.SignArtefact(artefact, key); err != nil {
			return fmt.Errorf("evaluate: sign Article 14 notification artefact: %w", err)
		}

		artefactPath, err := art14.WriteArtefact(artefact, outDir)
		if err != nil {
			return fmt.Errorf("evaluate: write Article 14 notification artefact: %w", err)
		}

		earlyWarningDeadline := awarenessAt.Add(24 * time.Hour)
		notificationDeadline := awarenessAt.Add(72 * time.Hour)

		logPath := "wardex-gate-audit.log"
		if cfg.Reporting.GateLog.Path != "" {
			logPath = cfg.Reporting.GateLog.Path
		}
		if gateLogPath != "" {
			logPath = gateLogPath
		}

		configHash, _ := accept.ConfigHash(configPath)
		auditEntry := model.AuditEntry{
			Timestamp:                     time.Now().UTC(),
			Event:                         "active-exploit.detected",
			ConfigHash:                    configHash,
			CliOverrides:                  collectCLIOverrides(),
			EvidenceHash:                  evidenceHash,
			OverallDecision:               "block",
			Status:                        "block",
			Detail:                        fmt.Sprintf("Active exploitation detected for CVE(s): %s. Article 14 notification artefact generated.", strings.Join(cves, ", ")),
			ActivelyExploited:             cves,
			Art14DeadlineEarlyWarning:     earlyWarningDeadline,
			Art14DeadlineNotification:     notificationDeadline,
			Art14NotificationArtefactPath: artefactPath,
		}

		if err := accept.ChainedAuditLog(logPath, auditEntry); err != nil {
			fmt.Fprintf(stderr, "Warning: failed to write gate audit log: %v\n", err)
		} else {
			fmt.Fprintf(stderr, "[INFO] Gate decision logged (chained) → %s\n", logPath)
		}

		// Forwarding (G3) including ENISA stub
		if len(cfg.Reporting.GateLog.Forward) > 0 {
			var backends []accept.Forwarder
			for _, f := range cfg.Reporting.GateLog.Forward {
				if f == "syslog" {
					if b, err := accept.NewSyslogBackend("localhost:514", "udp", "local0"); err == nil {
						backends = append(backends, b)
					}
				} else if f == "enisa" {
					queuePath := "wardex-enisa-queue.jsonl"
					if cfg.Reporting.ENISAQueue.Path != "" {
						queuePath = cfg.Reporting.ENISAQueue.Path
					}
					fmt.Fprintf(stderr, "[INFO] ENISABackend is a stub. No data will be transmitted.\n"+
						"       Queue path: %s\n"+
						"       When the ENISA single reporting platform API is published,\n"+
						"       update Wardex and configure ENISABackend.endpoint.\n", queuePath)
					backends = append(backends, accept.NewENISABackend(queuePath))
				}
			}
			if len(backends) > 0 {
				mux := accept.NewForwardMultiplexer(backends, cfg.Reporting.GateLog.OnFail)
				if err := mux.Dispatch(auditEntry); err != nil {
					fmt.Fprintf(stderr, "Error: gate log forwarding failed: %v\n", err)
					if cfg.Reporting.GateLog.OnFail == "block" {
						exitFunc(exitcodes.IntegrityFailure)
						return nil
					}
				}
			}
		}

		// Print [BLOCK] message to stderr
		fmt.Fprintf(stderr, "\n[BLOCK] Active exploitation detected for CVE(s): %s\n", strings.Join(cves, ", "))
		fmt.Fprintf(stderr, "        Awareness Timestamp: %s\n", awarenessAt.Format(time.RFC3339))
		fmt.Fprintf(stderr, "        Article 14 Deadlines:\n")
		fmt.Fprintf(stderr, "          - Early Warning (+24h):  %s (remaining: %s)\n", earlyWarningDeadline.Format(time.RFC3339), formatDuration(time.Until(earlyWarningDeadline)))
		fmt.Fprintf(stderr, "          - Notification (+72h):   %s (remaining: %s)\n", notificationDeadline.Format(time.RFC3339), formatDuration(time.Until(notificationDeadline)))
		fmt.Fprintf(stderr, "          - Final Report (+14d):   14 days after corrective measures are available\n")
		fmt.Fprintf(stderr, "        Notification Artefact: %s\n\n", artefactPath)

		exitFunc(exitcodes.ActivelyExploited)
		return nil
	}

	// Filter accepted CVEs
	if key, err := accept.ResolveSecret(*cfg); err == nil {
		configHash, _ := accept.ConfigHash(configPath)
		if accs, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", configHash, stderr); err == nil {
			acceptedMap := make(map[string]bool)
			for _, a := range accs {
				if !a.Revoked {
					acceptedMap[a.CVE] = true
				}
			}
			var filtered []model.Vulnerability
			for _, v := range vulns {
				if !acceptedMap[v.CVEID] {
					filtered = append(filtered, v)
				} else {
					fmt.Fprintf(stderr, "[INFO] CVE %s covered by active risk acceptance — skipped.\n", v.CVEID)
				}
			}
			vulns = filtered
		}
	} else {
		fmt.Fprintf(stderr, "[WARN] Cannot load acceptances — WARDEX_ACCEPT_SECRET not set. All CVEs will be evaluated without acceptance filtering.\n")
	}

	// Apply EPSS enrichment
	if epssEnrich != "" {
		if key, err := accept.ResolveSecret(*cfg); err == nil {
			safeEnrichPath, err := utils.SafePath(cwd, epssEnrich)
			if err == nil {
				if edata, err := os.ReadFile(safeEnrichPath); err == nil { // #nosec G304
					var enrichFormat model.EPSSEnrichmentFile
					if err := yaml.Unmarshal(edata, &enrichFormat); err == nil {
						if err := epss.Verify(enrichFormat, key); err == nil {
							scoreMap := make(map[string]float64)
							for _, e := range enrichFormat.Enrichments {
								scoreMap[e.CVE] = e.Score
							}
							for i, v := range vulns {
								if s, ok := scoreMap[v.CVEID]; ok {
									vulns[i].EPSSScore = s
									fmt.Fprintf(stderr, "[INFO] Applied EPSS enrichment for %s: %.6f\n", v.CVEID, s)
								}
							}
						} else {
							fmt.Fprintf(stderr, "WARNING: EPSS enrichment signature invalid: %v\n", err)
						}
					}
				}
			}
		} else {
			fmt.Fprintf(stderr, "WARNING: Cannot verify EPSS enrichment without WARDEX_ACCEPT_SECRET.\n")
		}
	}

	// Mandatory EPSS enrichment check — CRA Art.14 compliance
	var missingEpss []string
	for _, v := range vulns {
		if v.EPSSScore == 0.0 {
			missingEpss = append(missingEpss, v.CVEID)
		}
	}
	if len(missingEpss) > 0 {
		fmt.Fprintf(stderr, "\n[BLOCK] %d vulnerabilities lack real EPSS probability scores.\n", len(missingEpss))
		fmt.Fprintf(stderr, "        CVEs: %s\n", strings.Join(missingEpss, ", "))
		fmt.Fprintf(stderr, "        CRA Article 14 requires accurate vulnerability assessment.\n")
		fmt.Fprintf(stderr, "        Run 'wardex enrich epss <evidence-file>' to fetch and sign scores,\n")
		fmt.Fprintf(stderr, "        then pass the enrichment file with --epss-enrichment.\n\n")
		exitFunc(exitcodes.ComplianceFail)
		return nil
	}

	gateReport := gate.Evaluate(vulns)

	// Emit gate decision table with colour and fixed-width
	w := cmd.OutOrStdout()

	suppressTable := outputFormat != "markdown" && outFile == "stdout"

	if !suppressTable {
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "## Release Gate — Evaluation")
		_, _ = fmt.Fprintln(w, "")
		riskApp := cfg.ReleaseGate.RiskAppetite
		warnAbove := cfg.ReleaseGate.WarnAbove

		t := ui.NewTable(
			[]string{"CVE ID", "Component", "Reachable", "CVSS", "EPSS", "Exposure", "Compensating", "Criticality", "Release Risk", "Decision"},
			[]int{18, 35, 9, 6, 8, 10, 14, 12, 12, 12},
		)

		for _, d := range gateReport.Decisions {
			var decFg string
			label := "ALLOW"
			switch d.Decision {
			case "block":
				decFg = ui.Red + ui.Bold
				label = "BLOCK"
			case "warn":
				decFg = ui.Yellow + ui.Bold
				label = "WARN"
			default:
				decFg = ui.Green + ui.Bold
			}
			riskColor := ui.Green
			if d.ReleaseRisk >= riskApp {
				riskColor = ui.Red
			} else if warnAbove > 0 && d.ReleaseRisk >= warnAbove {
				riskColor = ui.Yellow
			}

			reachStr := "no"
			if d.Vulnerability.Reachable {
				reachStr = "yes"
			}

			t.AddRowStyled(
				[]string{
					d.Vulnerability.CVEID,
					d.Vulnerability.Component,
					reachStr,
					fmt.Sprintf("%.1f", d.Vulnerability.CVSSBase),
					fmt.Sprintf("%.4f", d.Vulnerability.EPSSScore),
					fmt.Sprintf("%.2f", d.Breakdown.ExposureFactor),
					fmt.Sprintf("%.2f", d.Breakdown.CompensatingEffect),
					fmt.Sprintf("%.2f", d.Breakdown.AssetCriticality),
					fmt.Sprintf("%.1f", d.ReleaseRisk),
					label,
				},
				[]string{"", "", "", "", "", "", "", "", riskColor, decFg},
				nil,
			)
		}
		t.Render(w)
		_, _ = fmt.Fprintf(w, "\n%s  Gate Maturity: Level %d\n\n",
			ui.Colorize("Overall Decision: "+strings.ToUpper(gateReport.OverallDecision), ui.Bold),
			gateReport.GateMaturityLevel,
		)
	}

	if gateReport.OverallDecision == "warn" && !suppressTable {
		fmt.Fprintf(stderr, "WARNING: Risk threshold exceeded WarnAbove for %d vulnerability(ies).\n", gateReport.WarnCount)
	}

	// Decision Logging (G1) & Forwarding (G3)
	logPath := "wardex-gate-audit.log"
	if cfg.Reporting.GateLog.Path != "" {
		logPath = cfg.Reporting.GateLog.Path
	}
	if gateLogPath != "" {
		logPath = gateLogPath
	}

	cliOverrides := collectCLIOverrides()

	if dryRun {
		// Compute what exit code would be
		exitReason := "Gate passed (ALLOW) — exit 0"
		if gateReport.OverallDecision == "block" {
			exitReason = fmt.Sprintf("Gate would BLOCK with exit code %d (GateBlocked)", exitcodes.GateBlocked)
		} else if failAbove > 0 {
			for _, d := range gateReport.Decisions {
				if d.ReleaseRisk > failAbove {
					exitReason = fmt.Sprintf("Compliance fail with exit code %d (ComplianceFail) — risk score %.1f exceeds --fail-above %.1f", exitcodes.ComplianceFail, d.ReleaseRisk, failAbove)
					break
				}
			}
		}
		fmt.Fprintf(stderr, "[DRY-RUN] Gate decision: %s\n", gateReport.OverallDecision)
		fmt.Fprintf(stderr, "[DRY-RUN] Result: %s\n", exitReason)
		fmt.Fprintf(stderr, "[DRY-RUN] Audit log would be written to: %s\n", logPath)
		exitFunc(exitcodes.OK)
		return nil
	}

	if logPath != "/dev/null" {
		configHash, _ := accept.ConfigHash(configPath)
		entry := model.AuditEntry{
			Timestamp:       time.Now().UTC(),
			Event:           "gate.evaluated",
			ConfigHash:      configHash,
			CliOverrides:    cliOverrides,
			EvidenceHash:    evidenceHash,
			OverallDecision: gateReport.OverallDecision,
			Risk:            gateReport.HighestRisk,
			Status:          gateReport.OverallDecision,
			Detail:          fmt.Sprintf("%d vulnerabilities evaluated; %d blocked, %d warned", len(vulns), gateReport.BlockedCount, gateReport.WarnCount),
		}

		if err := accept.ChainedAuditLog(logPath, entry); err != nil {
			fmt.Fprintf(stderr, "Warning: failed to write gate audit log: %v\n", err)
		} else {
			fmt.Fprintf(stderr, "[INFO] Gate decision logged (chained) → %s\n", logPath)
		}

		// Forwarding (G3)
		if len(cfg.Reporting.GateLog.Forward) > 0 {
			var backends []accept.Forwarder
			for _, f := range cfg.Reporting.GateLog.Forward {
				if f == "syslog" {
					// Use defaults for now as per G3 "sem novo código"
					if b, err := accept.NewSyslogBackend("localhost:514", "udp", "local0"); err == nil {
						backends = append(backends, b)
					}
				} else if f == "enisa" {
					queuePath := "wardex-enisa-queue.jsonl"
					if cfg.Reporting.ENISAQueue.Path != "" {
						queuePath = cfg.Reporting.ENISAQueue.Path
					}
					fmt.Fprintf(stderr, "[INFO] ENISABackend is a stub. No data will be transmitted.\n"+
						"       Queue path: %s\n"+
						"       When the ENISA single reporting platform API is published,\n"+
						"       update Wardex and configure ENISABackend.endpoint.\n", queuePath)
					backends = append(backends, accept.NewENISABackend(queuePath))
				}
			}
			if len(backends) > 0 {
				mux := accept.NewForwardMultiplexer(backends, cfg.Reporting.GateLog.OnFail)
				if err := mux.Dispatch(entry); err != nil {
					fmt.Fprintf(stderr, "Error: gate log forwarding failed: %v\n", err)
					if cfg.Reporting.GateLog.OnFail == "block" {
						exitFunc(exitcodes.IntegrityFailure)
						return nil
					}
				}
			}
		}
	}

	// Record decision to persistent state store (if enabled)
	if cfg.StateStore.Enabled {
		stateDir := cfg.StateStore.Dir
		if stateDir == "" {
			stateDir = ".wardex"
		}
		store, err := statestore.New(stateDir)
		if err != nil {
			fmt.Fprintf(stderr, "[WARN] State store init failed: %v\n", err)
		} else {
			// Count blocked and warned decisions
			activeAccepts := 0
			for _, d := range gateReport.Decisions {
				if d.Decision == "block" || d.Decision == "warn" {
					activeAccepts++
				}
			}

			if err := store.RecordDecision(
				gateReport.OverallDecision,
				gateReport.HighestRisk,
				len(vulns),
				activeAccepts,
				nil,
			); err != nil {
				fmt.Fprintf(stderr, "[WARN] Failed to record decision to state store: %v\n", err)
			} else {
				fmt.Fprintf(stderr, "[INFO] Decision recorded to state store → %s\n", stateDir)
			}

			// Show trend if requested
			if showTrend {
				analysis, err := store.TrendAnalysis()
				if err == nil {
					history, _ := store.History(90)
					fmt.Fprintln(w, statestore.FormatTrend(analysis, history))
				}
			}
		}
	}

	// Structured output (--output json|csv)
	if outputFormat != "" && outputFormat != "markdown" {
		dest := os.Stdout
		if outFile != "stdout" {
			f, err := os.Create(outFile) // #nosec G304 — user-chosen output path via --out-file flag
			if err != nil {
				fmt.Fprintf(stderr, "Error: cannot create output file %s: %v\n", outFile, err)
				exitFunc(exitcodes.GenericError)
				return nil
			}
			defer func() { _ = f.Close() }()
			dest = f
		}

		switch outputFormat {
		case "json":
			enc := json.NewEncoder(dest)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{"Gate": gateReport}); err != nil {
				fmt.Fprintf(stderr, "Error: write JSON output: %v\n", err)
				exitFunc(exitcodes.GenericError)
				return nil
			}
		case "csv":
			wr := csv.NewWriter(dest)
			_ = wr.Write([]string{"cve_id", "component", "reachable", "cvss", "epss", "exposure", "compensating", "criticality", "release_risk", "decision"})
			for _, d := range gateReport.Decisions {
				reachStr := "no"
				if d.Vulnerability.Reachable {
					reachStr = "yes"
				}
				_ = wr.Write([]string{
					d.Vulnerability.CVEID,
					d.Vulnerability.Component,
					reachStr,
					fmt.Sprintf("%.1f", d.Vulnerability.CVSSBase),
					fmt.Sprintf("%.4f", d.Vulnerability.EPSSScore),
					fmt.Sprintf("%.2f", d.Breakdown.ExposureFactor),
					fmt.Sprintf("%.2f", d.Breakdown.CompensatingEffect),
					fmt.Sprintf("%.2f", d.Breakdown.AssetCriticality),
					fmt.Sprintf("%.1f", d.ReleaseRisk),
					d.Decision,
				})
			}
			wr.Flush()
			if err := wr.Error(); err != nil {
				fmt.Fprintf(stderr, "Error: write CSV output: %v\n", err)
				exitFunc(exitcodes.GenericError)
				return nil
			}
		}
	}

	// Check EPSS missing hint & early return for blocks
	if gateReport.OverallDecision == "block" {
		missingEpss := 0
		for _, v := range vulns {
			if v.EPSSScore == 0.0 {
				missingEpss++
			}
		}
		if missingEpss > 0 {
			fmt.Fprintf(stderr, "\n[HINT] %d vulnerabilities lacked EPSS and defaulted to worst-case (1.0).\n", missingEpss)
			fmt.Fprintf(stderr, "       Run 'wardex enrich epss %s' to fetch real probabilities.\n", gateFile)
		}
		exitFunc(exitcodes.GateBlocked)
		return nil
	}

	exitFunc(exitcodes.OK)
	return nil
}
