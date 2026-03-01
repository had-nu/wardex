package main

import (
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/cmd/convert"
	"github.com/had-nu/wardex/cmd/simulate"
	"github.com/had-nu/wardex/config"
	"github.com/had-nu/wardex/pkg/accept/cli"
	"github.com/had-nu/wardex/pkg/accept/configaudit"
	"github.com/had-nu/wardex/pkg/accept/signer"
	"github.com/had-nu/wardex/pkg/accept/store"
	"github.com/had-nu/wardex/pkg/analyzer"
	"github.com/had-nu/wardex/pkg/catalog"
	"github.com/had-nu/wardex/pkg/correlator"
	"github.com/had-nu/wardex/pkg/exitcodes"
	"github.com/had-nu/wardex/pkg/ingestion"
	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
	"github.com/had-nu/wardex/pkg/report"
	"github.com/had-nu/wardex/pkg/snapshot"
	"github.com/had-nu/wardex/pkg/ui"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	Version       = "dev"
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
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert third-party vulnerability outputs into Wardex format",
}

var rootCmd = &cobra.Command{
	Use:     "wardex [flags] <input-file(s)>",
	Short:   "Wardex generates compliance gap analysis from implemented controls.",
	Version: Version,
	Args:    cobra.MinimumNArgs(1),
	Run:     runWardex,
}

func init() {
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
	rootCmd.Flags().StringVar(&profileName, "profile", "", "Team or profile name for RBAC threshold overrides")
	rootCmd.Flags().StringVar(&frameworkName, "framework", "iso27001", "Compliance framework: iso27001|soc2|nis2|dora")

	convertCmd.AddCommand(convert.GrypeCmd, convert.SbomCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(simulate.SimulateCmd)
	cli.AddCommands(rootCmd, &configPath)
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
			cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
			cfg.ReleaseGate.WarnAbove = p.WarnAbove
			fmt.Fprintf(os.Stderr, "[INFO] Loaded RBAC profile '%s' (RiskAppetite: %.2f, WarnAbove: %.2f)\n", profileName, p.RiskAppetite, p.WarnAbove)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Profile '%s' not found in config. Using defaults.\n", profileName)
		}
	}

	extControls, err := ingestion.LoadMany(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load controls: %v\n", err)
		os.Exit(1)
	}

	cat := catalog.Load(frameworkName)
	corr := correlator.New(cat)
	mappings := corr.Correlate(extControls)

	// Filter confidence if necessary (not fully required by spec, but added for robust coverage)
	var filtered []model.Mapping
	for _, m := range mappings {
		if minConfidence == "high" && m.Confidence == "low" {
			continue
		}
		filtered = append(filtered, m)
	}

	an := analyzer.New(cat, filtered, extControls)
	findings := an.Analyze()

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
		if f.Status == model.StatusCovered {
			ds.CoveredCount++
		} else if f.Status == model.StatusPartial {
			ds.PartialCount++
		} else {
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
		if f.Status == model.StatusCovered {
			rep.Summary.CoveredCount++
		} else if f.Status == model.StatusPartial {
			rep.Summary.PartialCount++
		} else {
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
			Mode:                 gateModeVal,
		}

		vdata, err := os.ReadFile(gateFile)
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

		if cfg.AcceptanceConfig.SigningSecretFile != "" {
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
					for _, v := range vulnsFormat.Vulnerabilities {
						if !acceptedMap[v.CVEID] {
							filtered = append(filtered, v)
						} else {
							fmt.Fprintf(os.Stderr, "[INFO] CVE %s is covered by an active risk acceptance and will be ignored.\n", v.CVEID)
						}
					}
					vulnsFormat.Vulnerabilities = filtered
				}
			}
		}

		gateReport := gate.Evaluate(vulnsFormat.Vulnerabilities)
		rep.Gate = &gateReport
		if gateReport.OverallDecision == "block" {
			gateFailed = true
		} else if gateReport.OverallDecision == "warn" {
			fmt.Fprintf(os.Stderr, "WARNING: Risk threshold exceeded WarnAbove for %d vulnerability(ies).\n", gateReport.WarnCount)
		}
	}

	if !noSnapshot {
		prev, _ := snapshot.Load(snapshotFile)
		if prev != nil {
			delta := snapshot.Diff(rep, *prev)
			rep.Delta = &delta
		}
		_ = snapshot.Save(rep, snapshotFile)
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
