// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/accept"
	"github.com/had-nu/wardex/v2/pkg/accept/cli"
	"github.com/had-nu/wardex/v2/pkg/art14"
	pathguard "github.com/had-nu/wardex/v2/pkg/cli"
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
	art14OutputDir string
	showTrend      bool

	exitFunc = os.Exit
	stderr   = os.Stderr
)

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

	if _, err := ingestion.LoadMany(args); err != nil {
		return fmt.Errorf("evaluate: load controls: %w", err)
	}

	gateModeVal := resolveGateMode(cfg, gateMode)
	gate := releasegate.Gate{
		AssetContext:         cfg.ReleaseGate.AssetContext,
		CompensatingControls: cfg.ReleaseGate.CompensatingControls,
		RiskAppetite:         cfg.ReleaseGate.RiskAppetite,
		WarnAbove:            cfg.ReleaseGate.WarnAbove,
		AggregateLimit:       cfg.ReleaseGate.AggregateLimit,
		Mode:                 gateModeVal,
	}

	vulns, evidenceHash, err := loadEvidence(gateFile, strict)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	if exitCode := handleActiveExploitation(cfg, vulns, evidenceHash); exitCode >= 0 {
		exitFunc(exitCode)
		return nil
	}

	vulns = filterAccepted(vulns, cfg, configPath, stderr)
	vulns = applyEPSSEnrichment(vulns, cfg, epssEnrich, stderr)

	if missing := findMissingEPSS(vulns); len(missing) > 0 {
		fmt.Fprintf(stderr, "\n[BLOCK] %d vulnerabilities lack real EPSS probability scores.\n", len(missing))
		fmt.Fprintf(stderr, "        CVEs: %s\n", strings.Join(missing, ", "))
		fmt.Fprintf(stderr, "        CRA Article 14 requires accurate vulnerability assessment.\n")
		fmt.Fprintf(stderr, "        Run 'wardex enrich epss <evidence-file>' to fetch and sign scores,\n")
		fmt.Fprintf(stderr, "        then pass the enrichment file with --epss-enrichment.\n\n")
		exitFunc(exitcodes.ComplianceFail)
		return nil
	}

	gateReport := gate.Evaluate(vulns)
	w := cmd.OutOrStdout()
	suppressTable := outputFormat != "markdown" && outFile == "stdout"

	if !suppressTable {
		renderGateTable(w, gateReport, cfg.ReleaseGate.RiskAppetite, cfg.ReleaseGate.WarnAbove)
	}

	if gateReport.OverallDecision == "warn" && !suppressTable {
		fmt.Fprintf(stderr, "WARNING: Risk threshold exceeded WarnAbove for %d vulnerability(ies).\n", gateReport.WarnCount)
	}

	logPath := resolveLogPath(cfg, gateLogPath)

	if dryRun {
		handleDryRunGate(gateReport, logPath)
		return nil
	}

	if logPath != "/dev/null" {
		writeGateAuditLog(logPath, cfg, gateReport, evidenceHash, vulns)
	}

	recordStateStore(cfg, gateReport, len(vulns), w)

	writeStructuredOutput(gateReport)

	if gateReport.OverallDecision == "block" {
		hintMissingEPSS(vulns)
		exitFunc(exitcodes.GateBlocked)
		return nil
	}

	exitFunc(exitcodes.OK)
	return nil
}

// handleActiveExploitation checks for actively exploited CVEs and handles Article 14 notification.
// Returns the exit code to use (>= 0) or -1 if no active exploitation was found.
func handleActiveExploitation(cfg *config.Config, vulns []model.Vulnerability, evidenceHash string) int {
	var activelyExploited []model.Vulnerability
	for _, v := range vulns {
		if v.ActivelyExploited {
			activelyExploited = append(activelyExploited, v)
		}
	}

	if len(activelyExploited) == 0 {
		return -1
	}

	outDir := art14OutputDir
	if outDir == "" {
		outDir = cfg.CRA.Art14.OutputDir
	}
	if outDir == "" {
		outDir = "."
	}

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

	cves := make([]string, 0, len(activelyExploited))
	for _, v := range activelyExploited {
		cves = append(cves, v.CVEID)
	}

	if dryRun {
		fmt.Fprintf(stderr, "[DRY-RUN] Active exploitation detected for CVE(s): %s\n", strings.Join(cves, ", "))
		fmt.Fprintf(stderr, "[DRY-RUN] Article 14 notification artefact would be written to: %s\n", outDir)
		fmt.Fprintf(stderr, "[DRY-RUN] Gate would BLOCK with exit code %d (ActivelyExploited)\n", exitcodes.ActivelyExploited)
		exitFunc(exitcodes.OK)
		return -1
	}

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
		fmt.Fprintf(stderr, "Error: generate Article 14 notification artefact: %v\n", err)
		exitFunc(exitcodes.GenericError)
		return -1
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v. Set WARDEX_ACCEPT_SECRET to generate a signed CRA Article 14 artefact\n", err)
		exitFunc(exitcodes.IntegrityFailure)
		return -1
	}

	if err := art14.SignArtefact(artefact, key); err != nil {
		fmt.Fprintf(stderr, "Error: sign Article 14 notification artefact: %v\n", err)
		exitFunc(exitcodes.GenericError)
		return -1
	}

	artefactPath, err := art14.WriteArtefact(artefact, outDir)
	if err != nil {
		fmt.Fprintf(stderr, "Error: write Article 14 notification artefact: %v\n", err)
		exitFunc(exitcodes.GenericError)
		return -1
	}

	earlyWarningDeadline := awarenessAt.Add(24 * time.Hour)
	notificationDeadline := awarenessAt.Add(72 * time.Hour)

	logPath := resolveLogPath(cfg, gateLogPath)
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

	forwardAuditEntry(cfg, auditEntry, stderr)

	fmt.Fprintf(stderr, "\n[BLOCK] Active exploitation detected for CVE(s): %s\n", strings.Join(cves, ", "))
	fmt.Fprintf(stderr, "        Awareness Timestamp: %s\n", awarenessAt.Format(time.RFC3339))
	fmt.Fprintf(stderr, "        Article 14 Deadlines:\n")
	fmt.Fprintf(stderr, "          - Early Warning (+24h):  %s (remaining: %s)\n", earlyWarningDeadline.Format(time.RFC3339), formatDuration(time.Until(earlyWarningDeadline)))
	fmt.Fprintf(stderr, "          - Notification (+72h):   %s (remaining: %s)\n", notificationDeadline.Format(time.RFC3339), formatDuration(time.Until(notificationDeadline)))
	fmt.Fprintf(stderr, "          - Final Report (+14d):   14 days after corrective measures are available\n")
	fmt.Fprintf(stderr, "        Notification Artefact: %s\n\n", artefactPath)

	return exitcodes.ActivelyExploited
}

// findMissingEPSS returns CVE IDs that have no EPSS score.
func findMissingEPSS(vulns []model.Vulnerability) []string {
	var missing []string
	for _, v := range vulns {
		if v.EPSSScore == 0.0 {
			missing = append(missing, v.CVEID)
		}
	}
	return missing
}

// renderGateTable prints the formatted decision table to the given writer.
func renderGateTable(w io.Writer, report model.GateReport, riskApp, warnAbove float64) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "## Release Gate — Evaluation")
	fmt.Fprintln(w, "")

	t := ui.NewTable(
		[]string{"CVE ID", "Component", "Reachable", "CVSS", "EPSS", "Exposure", "Compensating", "Criticality", "Release Risk", "Decision"},
		[]int{18, 35, 9, 6, 8, 10, 14, 12, 12, 12},
	)

	for _, d := range report.Decisions {
		decFg, label := gateLabel(d.Decision)
		riskColor := riskColor(d.ReleaseRisk, riskApp, warnAbove)

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
	fmt.Fprintf(w, "\n%s  Gate Maturity: Level %d\n\n",
		ui.Colorize("Overall Decision: "+strings.ToUpper(report.OverallDecision), ui.Bold),
		report.GateMaturityLevel,
	)
}

// gateLabel returns the ANSI color and label for a gate decision.
func gateLabel(decision string) (color, label string) {
	switch decision {
	case "block":
		return ui.Red + ui.Bold, "BLOCK"
	case "warn":
		return ui.Yellow + ui.Bold, "WARN"
	default:
		return ui.Green + ui.Bold, "ALLOW"
	}
}

// riskColor returns the ANSI color for a risk score relative to thresholds.
func riskColor(risk, riskApp, warnAbove float64) string {
	if risk >= riskApp {
		return ui.Red
	}
	if warnAbove > 0 && risk >= warnAbove {
		return ui.Yellow
	}
	return ui.Green
}

// handleDryRunGate prints what would happen without executing.
func handleDryRunGate(report model.GateReport, logPath string) {
	exitReason := "Gate passed (ALLOW) — exit 0"
	if report.OverallDecision == "block" {
		exitReason = fmt.Sprintf("Gate would BLOCK with exit code %d (GateBlocked)", exitcodes.GateBlocked)
	} else if failAbove > 0 {
		for _, d := range report.Decisions {
			if d.ReleaseRisk > failAbove {
				exitReason = fmt.Sprintf("Compliance fail with exit code %d (ComplianceFail) — risk score %.1f exceeds --fail-above %.1f", exitcodes.ComplianceFail, d.ReleaseRisk, failAbove)
				break
			}
		}
	}
	fmt.Fprintf(stderr, "[DRY-RUN] Gate decision: %s\n", report.OverallDecision)
	fmt.Fprintf(stderr, "[DRY-RUN] Result: %s\n", exitReason)
	fmt.Fprintf(stderr, "[DRY-RUN] Audit log would be written to: %s\n", logPath)
	exitFunc(exitcodes.OK)
}

// writeGateAuditLog writes the chained audit entry and forwards to configured backends.
func writeGateAuditLog(logPath string, cfg *config.Config, report model.GateReport, evidenceHash string, vulns []model.Vulnerability) {
	configHash, _ := accept.ConfigHash(configPath)
	entry := model.AuditEntry{
		Timestamp:       time.Now().UTC(),
		Event:           "gate.evaluated",
		ConfigHash:      configHash,
		CliOverrides:    collectCLIOverrides(),
		EvidenceHash:    evidenceHash,
		OverallDecision: report.OverallDecision,
		Risk:            report.HighestRisk,
		Status:          report.OverallDecision,
		Detail:          fmt.Sprintf("%d vulnerabilities evaluated; %d blocked, %d warned", len(vulns), report.BlockedCount, report.WarnCount),
	}

	if err := accept.ChainedAuditLog(logPath, entry); err != nil {
		fmt.Fprintf(stderr, "Warning: failed to write gate audit log: %v\n", err)
	} else {
		fmt.Fprintf(stderr, "[INFO] Gate decision logged (chained) → %s\n", logPath)
	}

	forwardAuditEntry(cfg, entry, stderr)
}

// recordStateStore records the decision to the persistent state store and optionally shows trend.
func recordStateStore(cfg *config.Config, report model.GateReport, vulnCount int, w io.Writer) {
	if !cfg.StateStore.Enabled {
		return
	}

	stateDir := cfg.StateStore.Dir
	if stateDir == "" {
		stateDir = ".wardex"
	}

	store, err := statestore.New(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] State store init failed: %v\n", err)
		return
	}

	activeAccepts := 0
	for _, d := range report.Decisions {
		if d.Decision == "block" || d.Decision == "warn" {
			activeAccepts++
		}
	}

	if err := store.RecordDecision(report.OverallDecision, report.HighestRisk, vulnCount, activeAccepts, nil); err != nil {
		fmt.Fprintf(stderr, "[WARN] Failed to record decision to state store: %v\n", err)
	} else {
		fmt.Fprintf(stderr, "[INFO] Decision recorded to state store → %s\n", stateDir)
	}

	if showTrend {
		analysis, err := store.TrendAnalysis()
		if err == nil {
			history, _ := store.History(90)
			fmt.Fprintln(w, statestore.FormatTrend(analysis, history))
		}
	}
}

// writeStructuredOutput writes JSON or CSV output if requested.
func writeStructuredOutput(report model.GateReport) {
	if outputFormat == "" || outputFormat == "markdown" {
		return
	}

	dest := os.Stdout
	if outFile != "stdout" {
		safeOutPath, err := pathguard.SafeOutputPath(outFile)
		if err != nil {
			fmt.Fprintf(stderr, "Error: --out-file: %v\n", err)
			exitFunc(exitcodes.GenericError)
			return
		}
		f, err := os.Create(safeOutPath) // #nosec G304
		if err != nil {
			fmt.Fprintf(stderr, "Error: cannot create output file %s: %v\n", outFile, err)
			exitFunc(exitcodes.GenericError)
			return
		}
		defer func() { _ = f.Close() }()
		dest = f
	}

	switch outputFormat {
	case "json":
		enc := json.NewEncoder(dest)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"Gate": report}); err != nil {
			fmt.Fprintf(stderr, "Error: write JSON output: %v\n", err)
			exitFunc(exitcodes.GenericError)
			return
		}
	case "csv":
		writeCSVOutput(dest, report)
	}
}

// writeCSVOutput writes the gate report as CSV.
func writeCSVOutput(dest io.Writer, report model.GateReport) {
	wr := csv.NewWriter(dest)
	_ = wr.Write([]string{"cve_id", "component", "reachable", "cvss", "epss", "exposure", "compensating", "criticality", "release_risk", "decision"})
	for _, d := range report.Decisions {
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
	}
}

// hintMissingEPSS prints a hint about missing EPSS scores when gate blocks.
func hintMissingEPSS(vulns []model.Vulnerability) {
	missing := 0
	for _, v := range vulns {
		if v.EPSSScore == 0.0 {
			missing++
		}
	}
	if missing > 0 {
		fmt.Fprintf(stderr, "\n[HINT] %d vulnerabilities lacked EPSS and defaulted to worst-case (1.0).\n", missing)
		fmt.Fprintf(stderr, "       Run 'wardex enrich epss %s' to fetch real probabilities.\n", gateFile)
	}
}

// loadEvidence reads and parses a vulnerability evidence file.
func loadEvidence(gateFile string, strict bool) ([]model.Vulnerability, string, error) {
	safeGatePath, err := pathguard.SafePath(gateFile)
	if err != nil {
		return nil, "", fmt.Errorf("evidence path: %w", err)
	}
	vdata, err := os.ReadFile(safeGatePath) // #nosec G304
	if err != nil {
		return nil, "", fmt.Errorf("read evidence file: %w", err)
	}

	evidenceHash := ""
	if h, err := utils.HashFile(safeGatePath); err == nil {
		evidenceHash = "sha256:" + h
	}

	var vulnsEnvelope model.VulnerabilityEnvelope
	if err := yaml.Unmarshal(vdata, &vulnsEnvelope); err != nil {
		return nil, "", fmt.Errorf("parse evidence file: %w", err)
	}

	if vulnsEnvelope.ConvertedBy == "" {
		if strict {
			return nil, "", fmt.Errorf("--strict requires canonicalised evidence. Run 'wardex convert' before evaluate")
		}
		fmt.Fprintf(stderr, "[WARN] Evidence file has no 'converted_by' field. Run 'wardex convert' to canonicalise scanner output. Proceeding with defaults (reachable=true, epss=1.0).\n")
	}

	return vulnsEnvelope.Vulnerabilities, evidenceHash, nil
}


