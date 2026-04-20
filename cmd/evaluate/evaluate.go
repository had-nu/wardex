// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/config"
	"github.com/had-nu/wardex/pkg/accept/cli"
	"github.com/had-nu/wardex/pkg/accept/configaudit"
	"github.com/had-nu/wardex/pkg/accept/signer"
	"github.com/had-nu/wardex/pkg/accept/store"
	"github.com/had-nu/wardex/pkg/epss"
	"github.com/had-nu/wardex/pkg/exitcodes"
	"github.com/had-nu/wardex/pkg/ingestion"
	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
	"github.com/had-nu/wardex/pkg/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	configPath   string
	gateFile     string
	gateMode     string
	epssEnrich   string
	outputFormat string
	outFile      string
	profileName  string
	failAbove    float64
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
  10 — Gate blocked (BLOCK)
  11 — Compliance gap exceeded --fail-above threshold`,
	Args: cobra.MinimumNArgs(1),
	RunE: runEvaluate,
}

func init() {
	EvaluateCmd.Flags().StringVar(&configPath, "config", "./wardex-config.yaml", "Path to wardex-config.yaml")
	EvaluateCmd.Flags().StringVar(&gateFile, "evidence", "", "Vulnerabilities file for release gate evaluation (required)")
	EvaluateCmd.Flags().StringVar(&gateMode, "gate-mode", "any", "Gate mode: any|aggregate")
	EvaluateCmd.Flags().StringVar(&epssEnrich, "epss-enrichment", "", "Path to a signed EPSS enrichment file")
	EvaluateCmd.Flags().StringVar(&outputFormat, "output", "markdown", "Output format: markdown|json|csv")
	EvaluateCmd.Flags().StringVar(&outFile, "out-file", "stdout", "Output file destination")
	EvaluateCmd.Flags().StringVar(&profileName, "profile", "", "RBAC threshold override profile")
	EvaluateCmd.Flags().Float64Var(&failAbove, "fail-above", 0.0, "Exit 11 if any gap score exceeds this value")
	_ = EvaluateCmd.MarkFlagRequired("evidence")

	// Allow the parent to inject the shared --config persistent flag.
	cli.AddCommands(EvaluateCmd, &configPath)
}

func runEvaluate(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config from %s: %v\n", configPath, err)
		cfg = &config.Config{}
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
				fmt.Fprintf(os.Stderr, "[RBAC VIOLATION] Actor %q is not authorized for profile %q!\n[RBAC ENFORCEMENT] Override rejected. Falling back to strict baseline configuration.\n", actor, profileName)
			} else {
				cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
				cfg.ReleaseGate.WarnAbove = p.WarnAbove
				fmt.Fprintf(os.Stderr, "[INFO] RBAC Verified. Profile %q loaded (RiskAppetite: %.2f)\n", profileName, p.RiskAppetite)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Profile %q not found. Using defaults.\n", profileName)
		}
	}

	if !cfg.ReleaseGate.Enabled {
		fmt.Fprintf(os.Stderr, "Warning: release_gate.enabled is false in config — gate will always ALLOW.\n")
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
	safeGatePath, err := utils.SafePath(cwd, gateFile)
	if err != nil {
		return fmt.Errorf("evaluate: evidence path: %w", err)
	}
	vdata, err := os.ReadFile(safeGatePath) // #nosec G304
	if err != nil {
		return fmt.Errorf("evaluate: read evidence file: %w", err)
	}
	var vulnsEnvelope struct {
		Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
	}
	if err := yaml.Unmarshal(vdata, &vulnsEnvelope); err != nil {
		return fmt.Errorf("evaluate: parse evidence file: %w", err)
	}
	vulns := vulnsEnvelope.Vulnerabilities

	// Filter accepted CVEs
	if key, err := signer.ResolveSecret(*cfg); err == nil {
		configHash, _ := configaudit.Hash(configPath)
		if accs, err := store.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", configHash); err == nil {
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
					fmt.Fprintf(os.Stderr, "[INFO] CVE %s covered by active risk acceptance — skipped.\n", v.CVEID)
				}
			}
			vulns = filtered
		}
	}

	// Apply EPSS enrichment
	if epssEnrich != "" {
		if key, err := signer.ResolveSecret(*cfg); err == nil {
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
									fmt.Fprintf(os.Stderr, "[INFO] Applied EPSS enrichment for %s: %.6f\n", v.CVEID, s)
								}
							}
						} else {
							fmt.Fprintf(os.Stderr, "WARNING: EPSS enrichment signature invalid: %v\n", err)
						}
					}
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: Cannot verify EPSS enrichment without WARDEX_ACCEPT_SECRET.\n")
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

	// Check EPSS missing hint
	if gateReport.OverallDecision == "block" {
		missingEpss := 0
		for _, v := range vulns {
			if v.EPSSScore == 0.0 {
				missingEpss++
			}
		}
		if missingEpss > 0 {
			fmt.Fprintf(os.Stderr, "\n[HINT] %d vulnerabilities lacked EPSS and defaulted to worst-case (1.0).\n", missingEpss)
			fmt.Fprintf(os.Stderr, "       Run 'wardex enrich epss %s' to fetch real probabilities.\n", gateFile)
		}
		os.Exit(exitcodes.GateBlocked)
	}

	if gateReport.OverallDecision == "warn" {
		fmt.Fprintf(os.Stderr, "WARNING: Risk threshold exceeded WarnAbove for %d vulnerability(ies).\n", gateReport.WarnCount)
	}

	os.Exit(exitcodes.OK)
	return nil
}
