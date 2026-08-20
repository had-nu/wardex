// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/cmd/aggregate"
	art14cmd "github.com/had-nu/wardex/v2/cmd/art14"
	"github.com/had-nu/wardex/v2/cmd/assess"
	"github.com/had-nu/wardex/v2/cmd/assets"
	"github.com/had-nu/wardex/v2/cmd/audit"
	authcmd "github.com/had-nu/wardex/v2/cmd/auth"
	"github.com/had-nu/wardex/v2/cmd/chain"
	"github.com/had-nu/wardex/v2/cmd/configseal"
	"github.com/had-nu/wardex/v2/cmd/contract"
	"github.com/had-nu/wardex/v2/cmd/convert"
	"github.com/had-nu/wardex/v2/cmd/evaluate"
	hmaccmd "github.com/had-nu/wardex/v2/cmd/hmac"
	"github.com/had-nu/wardex/v2/cmd/keygen"
	"github.com/had-nu/wardex/v2/cmd/policy"
	provenancecmd "github.com/had-nu/wardex/v2/cmd/provenance"
	"github.com/had-nu/wardex/v2/cmd/simulate"
	"github.com/had-nu/wardex/v2/cmd/state"
	trustcmd "github.com/had-nu/wardex/v2/cmd/trust"
	"github.com/had-nu/wardex/v2/pkg/accept/cli"
	enrichCli "github.com/had-nu/wardex/v2/pkg/enrich/cli"
	"github.com/had-nu/wardex/v2/pkg/orchestrator"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	Version       = "2.5.0"
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
	rootCmd.Flags().StringVar(&frameworkName, "framework", "iso27001", "Compliance framework: iso27001|soc2|nis2|dora|nist_csf|eu_ai_act")
	rootCmd.Flags().StringVar(&epssEnrich, "epss-enrichment", "", "Path to a cryptographically signed EPSS enrichment file")

	convertCmd.AddCommand(convert.GrypeCmd, convert.SbomCmd, convert.KevCmd)
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
	rootCmd.AddCommand(authcmd.AuthCmd)
	rootCmd.AddCommand(contract.ContractCmd)
	rootCmd.AddCommand(chain.ChainCmd)
	rootCmd.AddCommand(hmaccmd.HMACCmd)
	rootCmd.AddCommand(assets.AssetsCmd)
	rootCmd.AddCommand(provenancecmd.ProvenanceCmd)
}

func main() {
	ui.PrintBanner(Version)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runWardex(cmd *cobra.Command, args []string) {
	opts := orchestrator.EvaluationOptions{
		ConfigPath:    configPath,
		ProfileName:   profileName,
		Inputs:        args,
		Framework:     frameworkName,
		MinConfidence: minConfidence,
		GateFile:      gateFile,
		GateMode:      gateMode,
		FailAbove:     failAbove,
		NoSnapshot:    noSnapshot,
		SnapshotFile:  snapshotFile,
		OutputFormat:  outputFormat,
		OutFile:       outFile,
		RoadmapLimit:  roadmapLimit,
		EPSSEnrich:    epssEnrich,
		Logger:        ui.Default().Logger,
		Stderr:        os.Stderr,
	}

	pipeline := orchestrator.NewEvaluationPipeline(opts)
	result, err := pipeline.Run(cmd.Context(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(result.ExitCode)
}
