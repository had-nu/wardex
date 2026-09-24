// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package aggregate

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var failOn string

// AggregateCmd reads multiple JSON gate reports and returns a combined decision.
// It is intended to be used after running `wardex evaluate` for multiple frameworks
// so that the pipeline can act on a unified signal.
var AggregateCmd = &cobra.Command{
	Use:   "aggregate <result1.json> [result2.json ...]",
	Short: "Aggregate multiple gate evaluation results into a single decision",
	Long: `Aggregate reads multiple wardex JSON output files (produced with --output json)
and combines their gate decisions into a single pipeline signal.

Use this when running separate evaluations per compliance framework and needing
one authoritative exit code for CI.

Examples:
  wardex aggregate iso-result.json nis2-result.json --fail-on any-block
  wardex aggregate iso-result.json nis2-result.json --fail-on all-block

--fail-on modes:
  any-block  (default) — exit 10 if ANY framework produced a BLOCK decision
  all-block            — exit 10 only if ALL frameworks produced a BLOCK decision

Exit codes:
   0 — Combined decision: ALLOW
  10 — Combined decision: BLOCK`,
	Args: cobra.MinimumNArgs(1),
	RunE: runAggregate,
}

func init() {
	AggregateCmd.Flags().StringVar(&failOn, "fail-on", "any-block",
		"When to block: any-block (default) | all-block")
}

// gateResult is the minimal subset of a wardex JSON report needed for aggregation.
// We only extract the Gate field to avoid depending on the full GapReport schema.
type gateResult struct {
	Gate *model.GateReport `json:"Gate"`
}

type fileResult struct {
	file     string
	decision string
	blocked  int
	allowed  int
	warned   int
}

func runAggregate(cmd *cobra.Command, args []string) error {
	if failOn != "any-block" && failOn != "all-block" {
		return fmt.Errorf("aggregate: --fail-on must be 'any-block' or 'all-block', got %q", failOn)
	}

	stderr := cmd.ErrOrStderr()
	session := buildAggregateSession(args)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(session)
	reportProgress := func(number int, name, status, detail string) {
		progress.Report(ui.PhaseEvent{
			Number: number,
			Name:   name,
			Status: status,
			Detail: detail,
		})
	}

	reportProgress(1, "Validating aggregation policy", "RUNNING", "")
	reportProgress(1, "Validating aggregation policy", "DONE", failOn)
	reportProgress(2, "Reading gate reports", "RUNNING", "")

	var results []fileResult
	for _, path := range args {
		data, err := cli.SafeReadFile(path)
		if err != nil {
			reportProgress(2, "Reading gate reports", "FAILED", err.Error())
			return fmt.Errorf("aggregate: read %q: %w", path, err)
		}
		var gr gateResult
		if err := json.Unmarshal(data, &gr); err != nil {
			reportProgress(2, "Reading gate reports", "FAILED", err.Error())
			return fmt.Errorf("aggregate: parse %q: %w", path, err)
		}
		if gr.Gate == nil {
			fmt.Fprintf(stderr, "[WARN] %q has no gate data (was --gate used?). Treating as ALLOW.\n", path)
			results = append(results, fileResult{file: path, decision: "allow"})
			continue
		}
		results = append(results, fileResult{
			file:     path,
			decision: string(gr.Gate.OverallDecision),
			blocked:  gr.Gate.BlockedCount,
			allowed:  gr.Gate.AllowedCount,
			warned:   gr.Gate.WarnCount,
		})
	}
	reportProgress(2, "Reading gate reports", "DONE", fmt.Sprintf("%d report(s)", len(results)))

	reportProgress(3, "Calculating combined decision", "RUNNING", "")
	combined, blockCount, blocked := aggregateDecision(results, failOn)
	reportProgress(3, "Calculating combined decision", "DONE", fmt.Sprintf("%d/%d blocked", blockCount, len(results)))

	if progress.Enabled() {
		renderAggregateResults(stderr, progress, session, results)
	} else {
		w := cmd.OutOrStdout()
		renderAggregateTable(w, results)
		if blocked {
			_, _ = fmt.Fprintf(w, "\n**Combined Decision:** [FAIL] %s (%s — %d/%d framework(s) blocked)\n\n",
				combined, failOn, blockCount, len(results),
			)
		} else {
			_, _ = fmt.Fprintf(w, "\n**Combined Decision:** [OK] %s\n\n", combined)
		}
	}

	if blocked {
		os.Exit(exitcodes.GateBlocked)
	}
	os.Exit(exitcodes.OK)
	return nil
}
