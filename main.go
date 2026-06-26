// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/v2/cmd/aggregate"
	"github.com/had-nu/wardex/v2/cmd/assess"
	"github.com/had-nu/wardex/v2/cmd/audit"
	"github.com/had-nu/wardex/v2/cmd/configseal"
	"github.com/had-nu/wardex/v2/cmd/convert"
	"github.com/had-nu/wardex/v2/cmd/evaluate"
	"github.com/had-nu/wardex/v2/cmd/keygen"
	"github.com/had-nu/wardex/v2/cmd/policy"
	"github.com/had-nu/wardex/v2/cmd/simulate"
	"github.com/had-nu/wardex/v2/cmd/state"
	trustcmd "github.com/had-nu/wardex/v2/cmd/trust"
	art14cmd "github.com/had-nu/wardex/v2/cmd/art14"
	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/accept/cli"
	"github.com/had-nu/wardex/v2/pkg/accept"
	"github.com/had-nu/wardex/v2/pkg/analyzer"
	"github.com/had-nu/wardex/v2/pkg/catalog"
	"github.com/had-nu/wardex/v2/pkg/correlator"
	enrichCli "github.com/had-nu/wardex/v2/pkg/enrich/cli"
	"github.com/had-nu/wardex/v2/pkg/epss"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/ingestion"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/releasegate"
	"github.com/had-nu/wardex/v2/pkg/report"
	"github.com/had-nu/wardex/v2/pkg/snapshot"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/had-nu/wardex/v2/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

var (
	Version       = "2.2.0"
	configPath    string
	outputFormat  string
	outFile       string
	gateFile      string
	gateMode      string
	failAbove     float64
	noSnapshot    bool
	minConfidence string
	verbose       bool
	roadmapLimit  int
	profileName   string
	snapshotFile  string
	frameworkName string
	epssEnrich    string

	// Core flags are shown first in --help; everything else is "advanced"
	coreFlagNames = map[string]bool{
		"config": true, "gate": true, "output": true, "framework": true,
		"fail-above": true,
	}
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert third-party vulnerability outputs into Wardex format",
}

var rootCmd = &cobra.Command{
	Use:     "wardex [flags] <input-file(s)>",
	Short:   "Wardex generates compliance gap analysis from implemented controls.",
	Version: Version,
	Args: func(cmd *cobra.Command, args []string) error {
		if v, _ := cmd.Flags().GetBool("version"); v {
			return nil
		}
		if len(args) < 1 {
			return fmt.Errorf("requires at least 1 arg(s), only received %d", len(args))
		}
		return nil
	},
	Run: runWardex,
}

// defaultHelpFunc stores the original cobra help function so we can delegate to it for subcommands.
var defaultHelpFunc func(*cobra.Command, []string)

func groupedHelpFunc(cmd *cobra.Command, args []string) {
	if cmd != rootCmd {
		defaultHelpFunc(cmd, args)
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Usage:\n  %s\n\n", cmd.UseLine())
	fmt.Fprint(cmd.OutOrStdout(), "Core Flags:\n")
	coreOut, advOut := "", ""
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		line := fmt.Sprintf("  --%-18s %s", f.Name, f.Usage)
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
			line += fmt.Sprintf(" (default %s)", f.DefValue)
		}
		line += "\n"
		if coreFlagNames[f.Name] {
			coreOut += line
		} else {
			advOut += line
		}
	})
	if cmd.HasPersistentFlags() {
		cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
			if f.Hidden || coreFlagNames[f.Name] {
				return
			}
			line := fmt.Sprintf("  --%-18s %s", f.Name, f.Usage)
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				line += fmt.Sprintf(" (default %s)", f.DefValue)
			}
			line += "\n"
			advOut += line
		})
	}
	fmt.Fprint(cmd.OutOrStdout(), coreOut)
	if advOut != "" {
		fmt.Fprint(cmd.OutOrStdout(), "\nAdvanced Flags:\n")
		fmt.Fprint(cmd.OutOrStdout(), advOut)
	}
	if cmd.HasAvailableSubCommands() {
		fmt.Fprint(cmd.OutOrStdout(), "\nAvailable Commands:\n")
		for _, sub := range cmd.Commands() {
			if sub.IsAvailableCommand() || sub.Name() == "help" {
				fmt.Fprintf(cmd.OutOrStdout(), "  %-30s %s\n", sub.Name(), sub.Short)
			}
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
}

func init() {
	defaultHelpFunc = rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(groupedHelpFunc)

	rootCmd.PersistentFlags().StringVar(&configPath, "config", "./wardex-config.yaml", "Path to wardex-config.yaml")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "markdown", "Output format: markdown|json|csv")
	rootCmd.Flags().StringVar(&outFile, "out-file", "stdout", "Output file destination")
	rootCmd.Flags().StringVar(&gateFile, "gate", "", "Vulnerabilities file for release gate")
	rootCmd.Flags().StringVar(&gateMode, "gate-mode", "any", "Gate mode: any|aggregate")
	rootCmd.Flags().Float64Var(&failAbove, "fail-above", 0.0, "Exit code 1 if gap with final_score above this value")
	rootCmd.Flags().BoolVar(&noSnapshot, "no-snapshot", false, "Do not read or write snapshot")
	rootCmd.Flags().StringVar(&snapshotFile, "snapshot-file", ".wardex_snapshot.json", "Path to snapshot file")
	rootCmd.Flags().StringVar(&minConfidence, "min-confidence", "low", "Minimum matching confidence: high|low")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")
	rootCmd.Flags().IntVar(&roadmapLimit, "roadmap-limit", 10, "Max roadmap items in report (0 for unlimited)")
	rootCmd.Flags().StringVar(&profileName, "profile", "", "RBAC threshold override (Warning: Identity is cryptographically trusted only in CI environments via WARDEX_ACTOR)")
	rootCmd.Flags().StringVar(&frameworkName, "framework", "iso27001", "Compliance framework: iso27001|soc2|nis2|dora")
	rootCmd.Flags().StringVar(&epssEnrich, "epss-enrichment", "", "Path to a cryptographically signed EPSS enrichment file")

	convertCmd.AddCommand(convert.GrypeCmd, convert.SbomCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(simulate.SimulateCmd)
	rootCmd.AddCommand(policy.PolicyCmd)
	rootCmd.AddCommand(evaluate.EvaluateCmd)
	rootCmd.AddCommand(aggregate.AggregateCmd)
	rootCmd.AddCommand(assess.AssessCmd)
	rootCmd.AddCommand(keygen.KeygenCmd)
	rootCmd.AddCommand(trustcmd.TrustCmd)
	rootCmd.AddCommand(configseal.ConfigCmd)
	cli.AddCommands(rootCmd, &configPath)
	enrichCli.AddCommands(rootCmd, &configPath)
	rootCmd.AddCommand(art14cmd.Art14Cmd)
	rootCmd.AddCommand(audit.AuditCmd)
	rootCmd.AddCommand(state.StateCmd)
}

func main() {
	ui.PrintBanner(Version)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runWardex(cmd *cobra.Command, args []string) {

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config from %s: %v\n", configPath, err)
		cfg = &config.Config{}
	}

	if profileName != "" {
		if p, ok := cfg.Profiles[profileName]; ok {
			actor := os.Getenv("WARDEX_ACTOR")
			if actor == "" {
				actor = os.Getenv("GITHUB_ACTOR")
			}
			if actor == "" {
				actor = os.Getenv("USER")
			}

			allowed := false
			if len(p.AllowedActors) == 0 {
				allowed = true // Fallback to open access for legacy configs
			} else {
				for _, a := range p.AllowedActors {
					if a == "*" || a == actor {
						allowed = true
						break
					}
				}
			}

			if !allowed {
				fmt.Fprintf(os.Stderr, "[RBAC VIOLATION] Actor '%s' is not authorized for profile '%s'!\n[RBAC ENFORCEMENT] Override rejected. Falling back to stict baseline configuration.\n", actor, profileName)
			} else {
				cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
				cfg.ReleaseGate.WarnAbove = p.WarnAbove
				fmt.Fprintf(os.Stderr, "[INFO] RBAC Verified. Loaded profile '%s' for actor '%s' (RiskAppetite: %.2f, WarnAbove: %.2f)\n", profileName, actor, p.RiskAppetite, p.WarnAbove)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Profile '%s' not found in config. Using defaults.\n", profileName)
		}
	}

	extControls, err := ingestion.LoadMany(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load controls: %v\n", err)
		os.Exit(1)
	}

	cat, err := catalog.Load(frameworkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erro: %v\n[HINT] Use --framework para especificar um framework válido.\n", err)
		os.Exit(1)
	}
	corr := correlator.New(cat)
	mappings, err := corr.Correlate(extControls)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Correlation failed: %v\n", err)
		os.Exit(1)
	}

	// Filter confidence if necessary (not fully required by spec, but added for robust coverage)
	var filtered []model.Mapping
	droppedLowConf := 0
	for _, m := range mappings {
		if minConfidence == "high" && m.Confidence == "low" {
			droppedLowConf++
			continue
		}
		filtered = append(filtered, m)
	}
	if droppedLowConf > 0 {
		fmt.Fprintf(os.Stderr, "[INFO] Filtered %d low-confidence mappings (--min-confidence high)\n", droppedLowConf)
	}

	an := analyzer.New(cat, filtered, extControls)
	findings, err := an.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Analysis failed: %v\n", err)
		os.Exit(1)
	}

	var sortedRoadmap []model.Finding
	for _, f := range findings {
		if f.Status != model.StatusCovered {
			sortedRoadmap = append(sortedRoadmap, f)
		}
	}
	// Sort highest risk first (simple bubble for ease since size is < 93)
	for i := 0; i < len(sortedRoadmap); i++ {
		for j := i + 1; j < len(sortedRoadmap); j++ {
			if sortedRoadmap[i].FinalScore < sortedRoadmap[j].FinalScore {
				sortedRoadmap[i], sortedRoadmap[j] = sortedRoadmap[j], sortedRoadmap[i]
			}
		}
	}

	rep := model.GapReport{
		Summary: model.ExecutiveSummary{
			GeneratedAt: time.Now(),
		},
		Findings: findings,
		Roadmap:  sortedRoadmap,
	}

	domainMap := make(map[string]*model.DomainSummary)
	for _, f := range findings {
		dom := f.Control.Domain
		if dom == "" {
			dom = "general"
		}
		ds, ok := domainMap[dom]
		if !ok {
			ds = &model.DomainSummary{Domain: dom}
			domainMap[dom] = ds
		}
		ds.TotalControls++
		switch f.Status {
		case model.StatusCovered:
			ds.CoveredCount++
		case model.StatusPartial:
			ds.PartialCount++
		default:
			ds.GapCount++
		}
		ds.MaturityScore += f.FinalScore
	}

	for _, ds := range domainMap {
		if ds.TotalControls > 0 {
			ds.MaturityScore = ds.MaturityScore / float64(ds.TotalControls)
		}
		rep.Summary.DomainSummaries = append(rep.Summary.DomainSummaries, *ds)
	}

	rep.Summary.TotalControls = len(cat)
	for _, f := range findings {
		switch f.Status {
		case model.StatusCovered:
			rep.Summary.CoveredCount++
		case model.StatusPartial:
			rep.Summary.PartialCount++
		default:
			rep.Summary.GapCount++
		}
	}
	rep.Summary.GlobalCoverage = float64(rep.Summary.CoveredCount) / float64(rep.Summary.TotalControls) * 100.0

	gateFailed := false
	if cfg.ReleaseGate.Enabled && gateFile != "" {
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
		safePathStr, err := utils.SafePath(cwd, gateFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		vdata, err := os.ReadFile(safePathStr) // #nosec G304
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read gate file: %v\n", err)
			os.Exit(1)
		}
		var vulnsFormat struct {
			Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
		}
		if err := yaml.Unmarshal(vdata, &vulnsFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse gate vulnerabilities: %v\n", err)
			os.Exit(1)
		}

		if key, err := accept.ResolveSecret(*cfg); err == nil {
			configHash, _ := accept.ConfigHash(configPath)
			if accs, err := accept.Load("wardex-acceptances.yaml", key, "wardex-accept-audit.log", "", configHash, os.Stderr); err == nil {
				acceptedMap := make(map[string]bool)
				for _, a := range accs {
					if !a.Revoked {
						acceptedMap[a.CVE] = true
					}
				}
				var filtered []model.Vulnerability
				for _, v := range vulnsFormat.Vulnerabilities {
					if !acceptedMap[v.CVEID] {
						filtered = append(filtered, v)
					} else {
						fmt.Fprintf(os.Stderr, "[INFO] CVE %s is covered by an active risk acceptance and will be ignored.\n", v.CVEID)
					}
				}
				vulnsFormat.Vulnerabilities = filtered
			}
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] Cannot load acceptances — WARDEX_ACCEPT_SECRET not set. All CVEs will be evaluated without acceptance filtering.\n")
		}

		if epssEnrich != "" {
			if key, err := accept.ResolveSecret(*cfg); err == nil {
				cwd, _ := os.Getwd()
				safePathStr, err := utils.SafePath(cwd, epssEnrich)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				edata, err := os.ReadFile(safePathStr) // #nosec G304
				if err == nil {
					var enrichFormat model.EPSSEnrichmentFile
					if err := yaml.Unmarshal(edata, &enrichFormat); err == nil {
						if err := epss.Verify(enrichFormat, key); err == nil {
							scoreMap := make(map[string]float64)
							for _, e := range enrichFormat.Enrichments {
								scoreMap[e.CVE] = e.Score
							}
							for i, v := range vulnsFormat.Vulnerabilities {
								if s, ok := scoreMap[v.CVEID]; ok {
									vulnsFormat.Vulnerabilities[i].EPSSScore = s
									fmt.Fprintf(os.Stderr, "[INFO] Applied signed EPSS Enrichment for %s: %.6f\n", v.CVEID, s)
								}
							}
						} else {
							fmt.Fprintf(os.Stderr, "WARNING: EPSS Enrichment signature invalid: %v\n", err)
						}
					}
				}
			} else {
				fmt.Fprintf(os.Stderr, "WARNING: Cannot verify EPSS Enrichment without WARDEX_ACCEPT_SECRET configured.\n")
			}
		}

		gateReport := gate.Evaluate(vulnsFormat.Vulnerabilities)
		rep.Gate = &gateReport
		switch gateReport.OverallDecision {
		case "block":
			gateFailed = true
			missingEpss := 0
			for _, v := range vulnsFormat.Vulnerabilities {
				if v.EPSSScore == 0.0 {
					missingEpss++
				}
			}
			if missingEpss > 0 {
				fmt.Fprintf(os.Stderr, "\n[HINT] %d vulnerabilities lacked EPSS scores and defaulted to worst-case (1.0).\n", missingEpss)
				fmt.Fprintf(os.Stderr, "       Run 'wardex enrich epss %s' to fetch real probabilities from FIRST.org and sign the enrichment.\n", gateFile)
			}
		case "warn":
			fmt.Fprintf(os.Stderr, "WARNING: Risk threshold exceeded WarnAbove for %d vulnerability(ies).\n", gateReport.WarnCount)
		}
	}

	if !noSnapshot {
		prev, _ := snapshot.Load(snapshotFile)
		if prev != nil {
			delta := snapshot.Diff(rep, *prev)
			rep.Delta = &delta
		}
		if err := snapshot.Save(snapshotFile, &rep); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save snapshot: %v\n", err)
		}
	}

	finalFormat := outputFormat
	if outputFormat == "markdown" && cfg.Reporting.Format != "" {
		finalFormat = cfg.Reporting.Format
	}
	finalOutFile := outFile
	if outFile == "stdout" && cfg.Reporting.Output != "" {
		finalOutFile = cfg.Reporting.Output
	}

	if err := report.Generate(rep, finalFormat, finalOutFile, roadmapLimit); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate report: %v\n", err)
		os.Exit(1)
	}

	if gateFailed {
		os.Exit(exitcodes.GateBlocked)
	}

	compFail := false
	if failAbove > 0 {
		for _, gap := range sortedRoadmap {
			if gap.FinalScore > failAbove {
				compFail = true
				break
			}
		}
	}

	if compFail {
		os.Exit(exitcodes.ComplianceFail)
	}
	os.Exit(exitcodes.OK)
}
