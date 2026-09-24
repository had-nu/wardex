// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package orchestrator

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/accept"
	"github.com/had-nu/wardex/v2/pkg/art14"
	pathguard "github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/gate"
	"github.com/had-nu/wardex/v2/pkg/ingestion"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/releasegate"
	"github.com/had-nu/wardex/v2/pkg/statestore"
	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/had-nu/wardex/v2/pkg/utils"
	"github.com/had-nu/wardex/v2/pkg/versionregistry"
	"gopkg.in/yaml.v3"
)

// GateOptions carries the `wardex evaluate` command's flag values into the
// gate evaluation pipeline.
type GateOptions struct {
	ConfigPath   string
	ProfileName  string
	Strict       bool
	DryRun       bool
	GateFile     string
	GateMode     string
	FailAbove    float64
	OutputFormat string
	OutFile      string
	GateLogPath  string
	EPSSEnrich   string
	Art14OutDir  string
	ShowTrend    bool
	Controls     []string
	Logger       *slog.Logger
	Stderr       io.Writer
	Stdout       io.Writer
	Progress     ui.ProgressReporter
	OnResult     func(model.GateReport)
	// ReleaseSeal (L4): when ReleaseVersion is set, the gate runs in
	// release-seal mode and PolicyRef is required.
	ReleaseVersion string
	PolicyRef      string
	// GateClass (L3): risk class pr|deploy|nightly. Empty selects deploy
	// (current behaviour); each class adjusts exam severities.
	GateClass string
	// ForcedUpgrade (L7) arms the regulatory-deadline gate via flag even when
	// the (sealed) config does not enable it.
	ForcedUpgrade bool
	// ForcedUpgradeState overrides the tripwire counter file path (default:
	// <state-store-dir>/forced_upgrade.json).
	ForcedUpgradeState string
}

// RunGate executes the release-gate evaluation flow previously owned by
// cmd/evaluate. It returns the process exit code to apply and an error for
// input failures that the caller should surface. It never calls os.Exit.
func RunGate(ctx context.Context, opts GateOptions) (int, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Progress == nil {
		opts.Progress = ui.NoopProgressReporter{}
	}
	reportProgress := func(number int, name, status, detail string) {
		opts.Progress.Report(ui.PhaseEvent{
			Number: number,
			Name:   name,
			Status: status,
			Detail: detail,
		})
	}

	reportProgress(1, "Loading gate configuration", "RUNNING", "")
	cfg, err := loadGateConfig(ctx, opts)
	if err != nil {
		reportProgress(1, "Loading gate configuration", "FAILED", err.Error())
		fmt.Fprintf(opts.Stderr, "Error: %v\n", err)
		return exitcodes.IntegrityFailure, nil
	}
	reportProgress(1, "Loading gate configuration", "DONE", "configuration loaded")

	reportProgress(2, "Resolving gate policy", "RUNNING", "")
	class, err := resolveClassProfile(opts.GateClass, cfg)
	if err != nil {
		reportProgress(2, "Resolving gate policy", "FAILED", err.Error())
		fmt.Fprintf(opts.Stderr, "Error: %v\n", err)
		return exitcodes.GenericError, nil
	}
	reportProgress(2, "Resolving gate policy", "DONE", class.name)
	if opts.GateClass != "" {
		fmt.Fprintf(opts.Stderr, "[INFO] Gate class: %s\n", opts.GateClass)
	}

	if !cfg.ReleaseGate.Enabled {
		fmt.Fprintf(opts.Stderr, "Warning: release_gate.enabled is false in config — gate will always ALLOW.\n")
	}

	if opts.Strict {
		if _, err := accept.ConfigHash(opts.ConfigPath); err != nil {
			msg := fmt.Sprintf("[STRICT ENFORCEMENT] config hash computation failed: %v\n", err)
			switch class.integrity {
			case severityBlock:
				fmt.Fprintf(opts.Stderr, "%s", msg)
				return exitcodes.IntegrityFailure, nil
			case severityAdvisory:
				fmt.Fprintf(opts.Stderr, "%s[ADVISORY] class %q tolerates integrity gaps; continuing.\n", msg, class.name)
			default:
				fmt.Fprintf(opts.Stderr, "[%s] integrity exam off; strict config hash gap reported.\n", class.name)
			}
		}
	}

	releaseSeal := opts.ReleaseVersion != ""
	if releaseSeal && opts.PolicyRef == "" {
		fmt.Fprintf(opts.Stderr, "Error: --policy-ref is required in release-seal mode (with --release-version)\n")
		return exitcodes.GenericError, nil
	}
	if !releaseSeal && opts.PolicyRef != "" {
		fmt.Fprintf(opts.Stderr, "Error: --release-version is required when --policy-ref is set\n")
		return exitcodes.GenericError, nil
	}

	fu := newForcedUpgrade(ctx, opts, cfg)

	reportProgress(3, "Loading evidence", "RUNNING", "")
	if _, err := ingestion.LoadMany(opts.Controls); err != nil {
		reportProgress(3, "Loading evidence", "FAILED", err.Error())
		return exitcodes.OK, fmt.Errorf("evaluate: load controls: %w", err)
	}

	rg := releasegate.Gate{
		AssetContext:         cfg.ReleaseGate.AssetContext,
		CompensatingControls: cfg.ReleaseGate.CompensatingControls,
		RiskAppetite:         cfg.ReleaseGate.RiskAppetite,
		WarnAbove:            cfg.ReleaseGate.WarnAbove,
		AggregateLimit:       cfg.ReleaseGate.AggregateLimit,
		Mode:                 gate.ResolveGateMode(cfg, opts.GateMode),
	}

	vulns, evidenceHash, err := loadEvidence(opts)
	if err != nil {
		reportProgress(3, "Loading evidence", "FAILED", err.Error())
		return exitcodes.OK, fmt.Errorf("evaluate: %w", err)
	}
	reportProgress(3, "Loading evidence", "DONE", fmt.Sprintf("%d vulnerability record(s)", len(vulns)))

	if code := handleActiveExploitation(ctx, opts, cfg, vulns, evidenceHash, class); code >= 0 {
		reportProgress(3, "Loading evidence", "DONE", "active exploitation policy applied")
		return code, nil
	}

	reportProgress(4, "Applying risk policy", "RUNNING", "")
	vulns = gate.FilterAccepted(vulns, cfg, opts.ConfigPath, opts.Stderr)
	vulns = gate.ApplyEPSSEnrichment(vulns, cfg, opts.EPSSEnrich, opts.Stderr)
	reportProgress(4, "Applying risk policy", "DONE", fmt.Sprintf("%d vulnerability record(s)", len(vulns)))

	freshnessAdvisory := false
	if missing := findMissingEPSS(vulns); len(missing) > 0 {
		if fu != nil {
			// L7: under forced_upgrade, missing EPSS means the release cannot be
			// attested — a hard block while armed. The tripwire disarms after N
			// consecutive refresh failures (P11): evidence absence never freezes
			// the pipeline forever, so we fall through to the class exam.
			if stillArmed := fu.failure(); stillArmed {
				fmt.Fprintf(opts.Stderr, "\n[BLOCK] forced_upgrade: %d vulnerabilities lack EPSS probability scores — the release cannot be attested.\n", len(missing))
				fmt.Fprintf(opts.Stderr, "        Run 'wardex enrich epss %s' and retry with --epss-enrichment.\n", opts.GateFile)
				fmt.Fprintf(opts.Stderr, "        Tripwire %d of %d: disarms after %d consecutive failures.\n\n",
					fu.consecutive, fu.tripwireN, fu.tripwireN)
				return exitcodes.GateBlocked, nil
			}
		}
		switch class.freshness {
		case severityBlock:
			fmt.Fprintf(opts.Stderr, "\n[BLOCK] %d vulnerabilities lack real EPSS probability scores.\n", len(missing))
			fmt.Fprintf(opts.Stderr, "        CVEs: %s\n", strings.Join(missing, ", "))
			fmt.Fprintf(opts.Stderr, "        CRA Article 14 requires accurate vulnerability assessment.\n")
			fmt.Fprintf(opts.Stderr, "        Run 'wardex enrich epss <evidence-file>' to fetch and sign scores,\n")
			fmt.Fprintf(opts.Stderr, "        then pass the enrichment file with --epss-enrichment.\n\n")
			return exitcodes.ComplianceFail, nil
		case severityAdvisory:
			freshnessAdvisory = true
			fmt.Fprintf(opts.Stderr, "\n[ADVISORY] %d vulnerabilities lack real EPSS probability scores (exit 6).\n", len(missing))
			fmt.Fprintf(opts.Stderr, "           CVEs: %s\n", strings.Join(missing, ", "))
			fmt.Fprintf(opts.Stderr, "           Class %q treats freshness as advisory; refresh evidence via 'wardex enrich epss'.\n\n", class.name)
		default:
			fmt.Fprintf(opts.Stderr, "[%s] freshness exam off; %d vulnerabilities lack EPSS scores (reported).\n", class.name, len(missing))
		}
	} else if fu != nil {
		fu.success()
	}

	reportProgress(5, "Evaluating release decisions", "RUNNING", "")
	gateReport := rg.Evaluate(vulns)
	reportProgress(5, "Evaluating release decisions", "DONE", strings.ToUpper(string(gateReport.OverallDecision)))
	suppressTable := opts.OnResult != nil || (opts.OutputFormat != "markdown" && opts.OutFile == "stdout")
	if !suppressTable {
		renderGateTable(opts.Stdout, gateReport, cfg.ReleaseGate.RiskAppetite, cfg.ReleaseGate.WarnAbove)
	}

	if gateReport.OverallDecision == model.DecisionWarn && !suppressTable {
		fmt.Fprintf(opts.Stderr, "WARNING: Risk threshold exceeded WarnAbove for %d vulnerability(ies).\n", gateReport.WarnCount)
	}
	if opts.OnResult != nil {
		opts.OnResult(gateReport)
	}

	logPath := gate.ResolveLogPath(cfg, opts.GateLogPath)

	if opts.DryRun {
		return dryRunGate(opts, gateReport, logPath), nil
	}

	if logPath != "/dev/null" {
		writeGateAuditLog(ctx, opts, logPath, cfg, gateReport, evidenceHash, vulns)
	}

	recordStateStore(opts, cfg, gateReport, len(vulns), opts.Stdout)

	if code := writeStructuredOutput(opts, gateReport); code != exitcodes.OK {
		return code, nil
	}

	if gateReport.OverallDecision == model.DecisionBlock {
		if class.policy == severityOff {
			fmt.Fprintf(opts.Stderr, "\n[%s] policy exam off — gate decision was BLOCK but class %q only reports.\n",
				strings.ToUpper(class.name), class.name)
			if freshnessAdvisory {
				return exitcodes.FreshnessAdvisory, nil
			}
			return exitcodes.OK, nil
		}
		hintMissingEPSS(opts, vulns)
		return exitcodes.GateBlocked, nil
	}

	if freshnessAdvisory {
		return exitcodes.FreshnessAdvisory, nil
	}

	return exitcodes.OK, nil
}

// loadGateConfig loads the evaluation configuration from a sealed (.wexstate)
// or legacy (.yaml) config file, applies optional RBAC profile overrides, and
// returns the resolved config.
func loadGateConfig(ctx context.Context, opts GateOptions) (*config.Config, error) {
	var cfg *config.Config

	if trust.IsWexStatePath(opts.ConfigPath) {
		state, err := trust.LoadWexState(opts.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("load sealed config: %w", err)
		}

		ref := trust.ResolveTrustStoreRef("", "")
		if state.TrustStoreRef != "" {
			ref = trust.ResolveTrustStoreRef("", state.TrustStoreRef)
		}
		storeData, err := trust.FetchTrustStore(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("fetch trust store: %w", err)
		}
		store, err := trust.LoadStoreFromBytes(storeData)
		if err != nil {
			return nil, fmt.Errorf("parse trust store: %w", err)
		}
		if err := trust.VerifySeal(state, store, storeData); err != nil {
			return nil, fmt.Errorf("seal integrity: %w", err)
		}

		fmt.Fprintf(opts.Stderr, "[INFO] Sealed config verified — signed by %s (%s) at %s\n",
			state.SealedBy, state.SealedByKeyID, state.SealedAt.Format("2006-01-02 15:04 UTC"))

		cfg = &config.Config{}
		if err := yaml.Unmarshal([]byte(state.Payload), cfg); err != nil {
			return nil, fmt.Errorf("parse sealed payload: %w", err)
		}
		if cfg.ReleaseGate.Mode == "" {
			cfg.ReleaseGate.Mode = "any"
		}
	} else {
		if opts.Strict {
			return nil, fmt.Errorf("[STRICT ENFORCEMENT] Unsealed configuration rejected. Use 'wardex config seal' to govern this policy")
		}
		if isCI() {
			fmt.Fprintf(opts.Stderr, "[WARN] Using unsealed config. In production, use 'wardex config seal' for non-repudiation.\n")
		}
		var err error
		cfg, err = config.Load(opts.ConfigPath)
		if err != nil {
			fmt.Fprintf(opts.Stderr, "Warning: failed to load config from %s: %v\n", opts.ConfigPath, err)
			cfg = &config.Config{}
		}
	}

	if msg := config.ApplyProfile(cfg, opts.ProfileName, opts.Stderr); msg != "" {
		fmt.Fprintf(opts.Stderr, "[INFO] %s\n", msg)
	}

	return cfg, nil
}

// isCI detects common CI environment variables.
func isCI() bool {
	ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI"}
	for _, v := range ciVars {
		if strings.TrimSpace(os.Getenv(v)) != "" {
			return true
		}
	}
	return false
}

// formatDuration structures durations for CLI output.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "passed"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h >= 24 {
		return fmt.Sprintf("%dd %dh", h/24, h%24)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

// collectCLIOverrides collects CLI flags that override config values.
// These are recorded in the audit log as cli_overrides for CPL provenance.
func collectCLIOverrides(opts GateOptions) map[string]string {
	overrides := make(map[string]string)
	if opts.GateMode != "" && opts.GateMode != "any" {
		overrides["gate-mode"] = opts.GateMode
	}
	if opts.FailAbove > 0 {
		overrides["fail-above"] = fmt.Sprintf("%.1f", opts.FailAbove)
	}
	if opts.EPSSEnrich != "" {
		overrides["epss-enrichment"] = opts.EPSSEnrich
	}
	if opts.ProfileName != "" {
		overrides["profile"] = opts.ProfileName
	}
	if opts.ForcedUpgrade {
		overrides["forced-upgrade"] = "true"
	}
	if opts.Strict {
		overrides["strict"] = "true"
	}
	if opts.DryRun {
		overrides["dry-run"] = "true"
	}
	return overrides
}

// loadEvidence reads and parses a vulnerability evidence file.
func loadEvidence(opts GateOptions) ([]model.Vulnerability, string, error) {
	vdata, err := pathguard.SafeReadFile(opts.GateFile)
	if err != nil {
		return nil, "", fmt.Errorf("read evidence file: %w", err)
	}

	evidenceHash := "sha256:" + utils.HashBytes(vdata)

	var vulnsEnvelope model.VulnerabilityEnvelope
	if err := yaml.Unmarshal(vdata, &vulnsEnvelope); err != nil {
		return nil, "", fmt.Errorf("parse evidence file: %w", err)
	}

	if vulnsEnvelope.ConvertedBy == "" {
		if opts.Strict {
			return nil, "", fmt.Errorf("--strict requires canonicalised evidence. Run 'wardex convert' before evaluate")
		}
		fmt.Fprintf(opts.Stderr, "[WARN] Evidence file has no 'converted_by' field. Run 'wardex convert' to canonicalise scanner output. Proceeding with defaults (reachable=true, epss=1.0).\n")
	}

	return vulnsEnvelope.Vulnerabilities, evidenceHash, nil
}

// handleActiveExploitation checks for actively exploited CVEs and handles
// Article 14 notification. Returns the exit code to use (>= 0) or -1 if no
// active exploitation was found and evaluation should continue.
func handleActiveExploitation(ctx context.Context, opts GateOptions, cfg *config.Config, vulns []model.Vulnerability, evidenceHash string, class classProfile) int {
	var activelyExploited []model.Vulnerability
	for _, v := range vulns {
		if v.ActivelyExploited {
			activelyExploited = append(activelyExploited, v)
		}
	}

	if len(activelyExploited) == 0 {
		return -1
	}

	cves := make([]string, 0, len(activelyExploited))
	for _, v := range activelyExploited {
		cves = append(cves, v.CVEID)
	}

	// Non-blocking classes (pr, nightly) report active exploitation but do not
	// treat it as a release-stopping event: no mandatory artefact, no exit 12.
	if class.activeExploit != severityBlock {
		fmt.Fprintf(opts.Stderr, "[%s] active exploitation reported for CVE(s): %s (no hard stop for class %q; Article 14 expects dedicated monitoring)\n",
			strings.ToUpper(class.name), strings.Join(cves, ", "), class.name)
		return -1
	}

	outDir := opts.Art14OutDir
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
							fmt.Fprintf(opts.Stderr, "[WARN] Previously generated notification artefact for %s (ID: %s) has not been marked as dispatched.\n", cve, prev.ArtefactID)
							break
						}
					}
				}
			}
		}
	}

	if opts.DryRun {
		fmt.Fprintf(opts.Stderr, "[DRY-RUN] Active exploitation detected for CVE(s): %s\n", strings.Join(cves, ", "))
		fmt.Fprintf(opts.Stderr, "[DRY-RUN] Article 14 notification artefact would be written to: %s\n", outDir)
		fmt.Fprintf(opts.Stderr, "[DRY-RUN] Gate would BLOCK with exit code %d (ActivelyExploited)\n", exitcodes.ActivelyExploited)
		return exitcodes.OK
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
		fmt.Fprintf(opts.Stderr, "Error: generate Article 14 notification artefact: %v\n", err)
		return exitcodes.GenericError
	}

	key, err := accept.ResolveSecret(*cfg)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "Error: %v. Set WARDEX_ACCEPT_SECRET to generate a signed CRA Article 14 artefact\n", err)
		return exitcodes.IntegrityFailure
	}

	if err := art14.SignArtefact(artefact, key); err != nil {
		fmt.Fprintf(opts.Stderr, "Error: sign Article 14 notification artefact: %v\n", err)
		return exitcodes.GenericError
	}

	artefactPath, err := art14.WriteArtefact(artefact, outDir)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "Error: write Article 14 notification artefact: %v\n", err)
		return exitcodes.GenericError
	}

	earlyWarningDeadline := awarenessAt.Add(24 * time.Hour)
	notificationDeadline := awarenessAt.Add(72 * time.Hour)

	logPath := gate.ResolveLogPath(cfg, opts.GateLogPath)
	configHash, _ := accept.ConfigHash(opts.ConfigPath)
	auditEntry := model.AuditEntry{
		Timestamp:                     time.Now().UTC(),
		Event:                         "active-exploit.detected",
		CplSchemaVersion:              config.CurrentConfigSchemaVersion,
		ConfigHash:                    configHash,
		CliOverrides:                  collectCLIOverrides(opts),
		EvidenceHash:                  evidenceHash,
		OverallDecision:               model.DecisionBlock,
		Status:                        "block",
		Detail:                        fmt.Sprintf("Active exploitation detected for CVE(s): %s. Article 14 notification artefact generated.", strings.Join(cves, ", ")),
		ActivelyExploited:             cves,
		Art14DeadlineEarlyWarning:     earlyWarningDeadline,
		Art14DeadlineNotification:     notificationDeadline,
		Art14NotificationArtefactPath: artefactPath,
		ReleaseVersion:                opts.ReleaseVersion,
		PolicyRef:                     opts.PolicyRef,
	}

	if err := accept.ChainedAuditLog(logPath, auditEntry); err != nil {
		fmt.Fprintf(opts.Stderr, "Warning: failed to write gate audit log: %v\n", err)
	} else {
		fmt.Fprintf(opts.Stderr, "[INFO] Gate decision logged (chained) → %s\n", logPath)
	}

	gate.ForwardAuditEntry(ctx, cfg, auditEntry, opts.Stderr)

	fmt.Fprintf(opts.Stderr, "\n[BLOCK] Active exploitation detected for CVE(s): %s\n", strings.Join(cves, ", "))
	fmt.Fprintf(opts.Stderr, "        Awareness Timestamp: %s\n", awarenessAt.Format(time.RFC3339))
	fmt.Fprintf(opts.Stderr, "        Article 14 Deadlines:\n")
	fmt.Fprintf(opts.Stderr, "          - Early Warning (+24h):  %s (remaining: %s)\n", earlyWarningDeadline.Format(time.RFC3339), formatDuration(time.Until(earlyWarningDeadline)))
	fmt.Fprintf(opts.Stderr, "          - Notification (+72h):   %s (remaining: %s)\n", notificationDeadline.Format(time.RFC3339), formatDuration(time.Until(notificationDeadline)))
	fmt.Fprintf(opts.Stderr, "          - Final Report (+14d):   14 days after corrective measures are available\n")
	fmt.Fprintf(opts.Stderr, "        Notification Artefact: %s\n\n", artefactPath)

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
	decision := "Overall Decision: " + strings.ToUpper(string(report.OverallDecision))
	if ui.IsTerminal(w) {
		decision = ui.Colorize(decision, ui.Bold)
	}
	fmt.Fprintf(w, "\n%s  Gate Maturity: Level %d\n\n", decision, report.GateMaturityLevel)
}

// gateLabel returns the ANSI color and label for a gate decision.
func gateLabel(decision model.Decision) (color, label string) {
	switch decision {
	case model.DecisionBlock:
		return ui.Red + ui.Bold, "BLOCK"
	case model.DecisionWarn:
		return ui.Yellow + ui.Bold, "WARN"
	case model.DecisionAllow:
		return ui.Green + ui.Bold, "ALLOW"
	}
	return ui.Green + ui.Bold, "ALLOW"
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

// dryRunGate reports what the gate would do without executing any writes.
func dryRunGate(opts GateOptions, report model.GateReport, logPath string) int {
	exitReason := "Gate passed (ALLOW) — exit 0"
	if report.OverallDecision == model.DecisionBlock {
		exitReason = fmt.Sprintf("Gate would BLOCK with exit code %d (GateBlocked)", exitcodes.GateBlocked)
	} else if opts.FailAbove > 0 {
		for _, d := range report.Decisions {
			if d.ReleaseRisk > opts.FailAbove {
				exitReason = fmt.Sprintf("Compliance fail with exit code %d (ComplianceFail) — risk score %.1f exceeds --fail-above %.1f", exitcodes.ComplianceFail, d.ReleaseRisk, opts.FailAbove)
				break
			}
		}
	}
	fmt.Fprintf(opts.Stderr, "[DRY-RUN] Gate decision: %s\n", report.OverallDecision)
	fmt.Fprintf(opts.Stderr, "[DRY-RUN] Result: %s\n", exitReason)
	fmt.Fprintf(opts.Stderr, "[DRY-RUN] Audit log would be written to: %s\n", logPath)
	return exitcodes.OK
}

// writeGateAuditLog writes the chained audit entry and forwards to configured backends.
func writeGateAuditLog(ctx context.Context, opts GateOptions, logPath string, cfg *config.Config, report model.GateReport, evidenceHash string, vulns []model.Vulnerability) {
	configHash, _ := accept.ConfigHash(opts.ConfigPath)
	entry := model.AuditEntry{
		Timestamp:        time.Now().UTC(),
		Event:            "gate.evaluated",
		CplSchemaVersion: config.CurrentConfigSchemaVersion,
		ConfigHash:       configHash,
		CliOverrides:     collectCLIOverrides(opts),
		EvidenceHash:     evidenceHash,
		OverallDecision:  report.OverallDecision,
		Risk:             report.HighestRisk,
		Status:           string(report.OverallDecision),
		Detail:           fmt.Sprintf("%d vulnerabilities evaluated; %d blocked, %d warned", len(vulns), report.BlockedCount, report.WarnCount),
		ReleaseVersion:   opts.ReleaseVersion,
		PolicyRef:        opts.PolicyRef,
	}

	if err := accept.ChainedAuditLog(logPath, entry); err != nil {
		fmt.Fprintf(opts.Stderr, "Warning: failed to write gate audit log: %v\n", err)
	} else {
		fmt.Fprintf(opts.Stderr, "[INFO] Gate decision logged (chained) → %s\n", logPath)
		recordReleaseSeal(opts, logPath, entry)
	}

	gate.ForwardAuditEntry(ctx, cfg, entry, opts.Stderr)
}

// recordReleaseSeal maintains the derived release-version registry when the
// gate runs in release-seal mode. The index is best-effort: a stale or missing
// index never blocks the seal — check-version rebuilds it from the chain.
func recordReleaseSeal(opts GateOptions, logPath string, entry model.AuditEntry) {
	if entry.ReleaseVersion == "" {
		return
	}
	reg, err := versionregistry.Load(logPath)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "Warning: version registry unreadable (%v); will rebuild from chain on check-version\n", err)
		reg = versionregistry.New()
	}
	lastHash, err := accept.LastEntryHash(logPath)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "Warning: cannot record release seal in registry: %v\n", err)
		return
	}
	reg.Add(versionregistry.ReleaseInfo{
		Version:   entry.ReleaseVersion,
		PolicyRef: entry.PolicyRef,
		SealedAt:  entry.Timestamp,
		EntryHash: lastHash,
	}, lastHash)
	if err := reg.Save(logPath); err != nil {
		fmt.Fprintf(opts.Stderr, "Warning: cannot save version registry: %v\n", err)
	}
}

// recordStateStore records the decision to the persistent state store and optionally shows trend.
func recordStateStore(opts GateOptions, cfg *config.Config, report model.GateReport, vulnCount int, w io.Writer) {
	if !cfg.StateStore.Enabled {
		return
	}

	stateDir := cfg.StateStore.Dir
	if stateDir == "" {
		stateDir = ".wardex"
	}

	store, err := statestore.New(stateDir)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "[WARN] State store init failed: %v\n", err)
		return
	}

	activeAccepts := 0
	for _, d := range report.Decisions {
		if d.Decision == model.DecisionBlock || d.Decision == model.DecisionWarn {
			activeAccepts++
		}
	}

	if err := store.RecordDecision(report.OverallDecision, report.HighestRisk, vulnCount, activeAccepts, nil); err != nil {
		fmt.Fprintf(opts.Stderr, "[WARN] Failed to record decision to state store: %v\n", err)
	} else {
		fmt.Fprintf(opts.Stderr, "[INFO] Decision recorded to state store → %s\n", stateDir)
	}

	if opts.ShowTrend {
		analysis, err := store.TrendAnalysis()
		if err == nil {
			history, _ := store.History(90)
			fmt.Fprintln(w, statestore.FormatTrend(analysis, history))
		}
	}
}

// writeStructuredOutput writes JSON or CSV output if requested.
// Returns the exit code to apply (exitcodes.OK on success).
func writeStructuredOutput(opts GateOptions, report model.GateReport) int {
	if opts.OutputFormat == "" || opts.OutputFormat == "markdown" {
		return exitcodes.OK
	}

	dest := os.Stdout
	if opts.OutFile != "stdout" {
		safeOutPath, err := pathguard.SafeOutputPath(opts.OutFile)
		if err != nil {
			fmt.Fprintf(opts.Stderr, "Error: --out-file: %v\n", err)
			return exitcodes.GenericError
		}
		f, err := os.Create(safeOutPath) // #nosec G304
		if err != nil {
			fmt.Fprintf(opts.Stderr, "Error: cannot create output file %s: %v\n", opts.OutFile, err)
			return exitcodes.GenericError
		}
		defer func() { _ = f.Close() }()
		dest = f
	}

	switch opts.OutputFormat {
	case "json":
		enc := json.NewEncoder(dest)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"Gate": report}); err != nil {
			fmt.Fprintf(opts.Stderr, "Error: write JSON output: %v\n", err)
			return exitcodes.GenericError
		}
	case "csv":
		if code := writeCSVOutput(dest, opts, report); code != exitcodes.OK {
			return code
		}
	}
	return exitcodes.OK
}

// writeCSVOutput writes the gate report as CSV.
func writeCSVOutput(dest io.Writer, opts GateOptions, report model.GateReport) int {
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
			string(d.Decision),
		})
	}
	wr.Flush()
	if err := wr.Error(); err != nil {
		fmt.Fprintf(opts.Stderr, "Error: write CSV output: %v\n", err)
		return exitcodes.GenericError
	}
	return exitcodes.OK
}

// hintMissingEPSS prints a hint about missing EPSS scores when gate blocks.
func hintMissingEPSS(opts GateOptions, vulns []model.Vulnerability) {
	missing := 0
	for _, v := range vulns {
		if v.EPSSScore == 0.0 {
			missing++
		}
	}
	if missing > 0 {
		fmt.Fprintf(opts.Stderr, "\n[HINT] %d vulnerabilities lacked EPSS and defaulted to worst-case (1.0).\n", missing)
		fmt.Fprintf(opts.Stderr, "       Run 'wardex enrich epss %s' to fetch real probabilities.\n", opts.GateFile)
	}
}
