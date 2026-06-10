// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/config"
	"github.com/had-nu/wardex/pkg/accept/cli"
	"github.com/had-nu/wardex/pkg/accept"
	"github.com/had-nu/wardex/pkg/art14"
	"github.com/had-nu/wardex/pkg/epss"
	"github.com/had-nu/wardex/pkg/exitcodes"
	"github.com/had-nu/wardex/pkg/ingestion"
	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
	"github.com/had-nu/wardex/pkg/trust"
	"github.com/had-nu/wardex/pkg/utils"
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
	gateLogPath    string
	art14OutputDir string // NEW in v2.0

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
	EvaluateCmd.Flags().BoolVar(&strict, "strict", false, "Exit 3 if an unsealed config (.yaml) is used or if evidence is not canonical")
	EvaluateCmd.Flags().StringVar(&gateLogPath, "gate-log", "", "Path to gate decision audit log (overrides config)")
	EvaluateCmd.Flags().StringVar(&art14OutputDir, "art14-output-dir", "", "Directory where Article 14 notification artefacts are written (overrides config)")
	_ = EvaluateCmd.MarkFlagRequired("evidence")

	// Allow the parent to inject the shared --config persistent flag.
	cli.AddCommands(EvaluateCmd, &configPath)
}

func runEvaluate(cmd *cobra.Command, args []string) error {
	var cfg *config.Config

	// --- Sealed config verification (wexstate) ---
	if trust.IsWexStatePath(configPath) {
		state, err := trust.LoadWexState(configPath)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}

		// Resolve and fetch trust store
		ref := trust.ResolveTrustStoreRef("", "")
		if state.TrustStoreRef != "" {
			ref = trust.ResolveTrustStoreRef("", state.TrustStoreRef)
		}
		storeData, err := trust.FetchTrustStore(ref)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}
		store, err := trust.LoadStoreFromBytes(storeData)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}

		// Verify seal integrity
		if err := trust.VerifySeal(state, store, storeData); err != nil {
			fmt.Fprintf(stderr, "[INTEGRITY FAILURE] %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}
		fmt.Fprintf(stderr, "[INFO] Sealed config verified — signed by %s (%s) at %s\n",
			state.SealedBy, state.SealedByKeyID, state.SealedAt.Format("2006-01-02 15:04 UTC"))

		// Deserialise the payload
		cfg = &config.Config{}
		if err := yaml.Unmarshal([]byte(state.Payload), cfg); err != nil {
			fmt.Fprintf(stderr, "Error: parse sealed payload: %v\n", err)
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}

		if cfg.ReleaseGate.Mode == "" {
			cfg.ReleaseGate.Mode = "any"
		}
	} else {
		// Legacy mode — load YAML directly
		if strict {
			fmt.Fprintf(stderr, "[STRICT ENFORCEMENT] Unsealed configuration rejected. Use 'wardex config seal' to govern this policy.\n")
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}

		if isCI() {
			fmt.Fprintf(stderr, "[WARN] Using unsealed config. In production, use 'wardex config seal' for non-repudiation.\n")
		}
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			fmt.Fprintf(stderr, "Warning: failed to load config from %s: %v\n", configPath, err)
			cfg = &config.Config{}
		}
	}

	// RBAC profile override
	if profileName != "" {
		if p, ok := cfg.Profiles[profileName]; ok {
			actor := os.Getenv("WARDEX_ACTOR")
			if actor == "" {
				actor = os.Getenv("GITHUB_ACTOR")
			}
			if actor == "" {
				actor = os.Getenv("USER")
			}
			allowed := len(p.AllowedActors) == 0
			for _, a := range p.AllowedActors {
				if a == "*" || a == actor {
					allowed = true
					break
				}
			}
			if !allowed {
				fmt.Fprintf(stderr, "[RBAC VIOLATION] Actor %q is not authorized for profile %q!\n[RBAC ENFORCEMENT] Override rejected. Falling back to strict baseline configuration.\n", actor, profileName)
			} else {
				cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
				cfg.ReleaseGate.WarnAbove = p.WarnAbove
				fmt.Fprintf(stderr, "[INFO] RBAC Verified. Profile %q loaded (RiskAppetite: %.2f)\n", profileName, p.RiskAppetite)
			}
		} else {
			fmt.Fprintf(stderr, "Warning: Profile %q not found. Using defaults.\n", profileName)
		}
	}

	if !cfg.ReleaseGate.Enabled {
		fmt.Fprintf(stderr, "Warning: release_gate.enabled is false in config — gate will always ALLOW.\n")
	}

	// Load controls for context (needed for ingestion but gate is the primary output)
	_, err := ingestion.LoadMany(args)
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
	safeGatePath, err := utils.SafePath(cwd, gateFile)
	if err != nil {
		return fmt.Errorf("evaluate: evidence path: %w", err)
	}
	vdata, err := os.ReadFile(safeGatePath) // #nosec G304
	if err != nil {
		return fmt.Errorf("evaluate: read evidence file: %w", err)
	}
	// Calculate Evidence Hash (G1)
	evidenceHash := ""
	if h, err := utils.HashFile(safeGatePath); err == nil {
		evidenceHash = "sha256:" + h
	}

	var vulnsEnvelope model.VulnerabilityEnvelope
	if err := yaml.Unmarshal(vdata, &vulnsEnvelope); err != nil {
		return fmt.Errorf("evaluate: parse evidence file: %w", err)
	}

	// Provenance Validation (G2)
	if vulnsEnvelope.ConvertedBy == "" {
		if strict {
			fmt.Fprintf(stderr, "[ERROR] --strict requires canonicalised evidence. Run 'wardex convert' before evaluate.\n")
			exitFunc(exitcodes.IntegrityFailure)
			return nil
		}
		fmt.Fprintf(stderr, "[WARN] Evidence file has no 'converted_by' field. Run 'wardex convert' to canonicalise scanner output. Proceeding with defaults (reachable=true, epss=1.0).\n")
	}

	vulns := vulnsEnvelope.Vulnerabilities

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
		if accs, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", configHash); err == nil {
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

	gateReport := gate.Evaluate(vulns)

	// Emit concise gate decision table to stdout
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "## Release Gate — Evaluation")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "| CVE | CVSS | EPSS | Release Risk | Decision |")
	_, _ = fmt.Fprintln(w, "|-----|------|------|--------------|----------|")
	for _, d := range gateReport.Decisions {
		icon := "[OK]"
		switch d.Decision {
		case "block":
			icon = "[BLOCK]"
		case "warn":
			icon = "[WARN]"
		}
		_, _ = fmt.Fprintf(w, "| %s | %.1f | %.2f | **%.1f** | %s %s |\n",
			d.Vulnerability.CVEID, d.Vulnerability.CVSSBase, d.Vulnerability.EPSSScore,
			d.ReleaseRisk, icon, d.Decision,
		)
	}
	_, _ = fmt.Fprintf(w, "\n**Overall Decision:** %s  |  Gate Maturity: Level %d\n\n",
		gateReport.OverallDecision, gateReport.GateMaturityLevel,
	)

	if gateReport.OverallDecision == "warn" {
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

	if logPath != "/dev/null" {
		configHash, _ := accept.ConfigHash(configPath)
		entry := model.AuditEntry{
			Timestamp:       time.Now().UTC(),
			Event:           "gate.evaluated",
			ConfigHash:      configHash,
			EvidenceHash:    evidenceHash,
			OverallDecision: gateReport.OverallDecision,
			Risk:            gateReport.HighestRisk,
			Status:          gateReport.OverallDecision,
			Detail:          fmt.Sprintf("%d vulnerabilities evaluated; %d blocked, %d warned", len(vulns), gateReport.BlockedCount, gateReport.WarnCount),
		}

		if err := accept.AuditLog(logPath, entry); err != nil {
			fmt.Fprintf(stderr, "Warning: failed to write gate audit log: %v\n", err)
		} else {
			fmt.Fprintf(stderr, "[INFO] Gate decision logged → %s\n", logPath)
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

// isCI detects common CI environments.
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
