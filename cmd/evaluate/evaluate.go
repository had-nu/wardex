// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package evaluate

import (
	"os"

	"github.com/had-nu/wardex/v2/pkg/accept/cli"
	"github.com/had-nu/wardex/v2/pkg/orchestrator"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
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
	code, err := orchestrator.RunGate(cmd.Context(), orchestrator.GateOptions{
		ConfigPath:   configPath,
		GateFile:     gateFile,
		GateMode:     gateMode,
		EPSSEnrich:   epssEnrich,
		OutputFormat: outputFormat,
		OutFile:      outFile,
		ProfileName:  profileName,
		FailAbove:    failAbove,
		Strict:       strict,
		DryRun:       dryRun,
		GateLogPath:  gateLogPath,
		Art14OutDir:  art14OutputDir,
		ShowTrend:    showTrend,
		Controls:     args,
		Logger:       ui.Default().Logger,
		Stderr:       stderr,
		Stdout:       cmd.OutOrStdout(),
	})
	if err != nil {
		return err
	}
	exitFunc(code)
	return nil
}
