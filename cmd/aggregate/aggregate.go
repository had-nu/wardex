// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package aggregate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/had-nu/wardex/pkg/exitcodes"
	"github.com/had-nu/wardex/pkg/model"
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

func runAggregate(cmd *cobra.Command, args []string) error {
	if failOn != "any-block" && failOn != "all-block" {
		return fmt.Errorf("aggregate: --fail-on must be 'any-block' or 'all-block', got %q", failOn)
	}

	type fileResult struct {
		file     string
		decision string
		blocked  int
		allowed  int
		warned   int
	}

	var results []fileResult
	for _, path := range args {
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return fmt.Errorf("aggregate: read %q: %w", path, err)
		}
		var gr gateResult
		if err := json.Unmarshal(data, &gr); err != nil {
			return fmt.Errorf("aggregate: parse %q: %w", path, err)
		}
		if gr.Gate == nil {
			fmt.Fprintf(os.Stderr, "[WARN] %q has no gate data (was --gate used?). Treating as ALLOW.\n", path)
			results = append(results, fileResult{file: path, decision: "allow"})
			continue
		}
		results = append(results, fileResult{
			file:     path,
			decision: gr.Gate.OverallDecision,
			blocked:  gr.Gate.BlockedCount,
			allowed:  gr.Gate.AllowedCount,
			warned:   gr.Gate.WarnCount,
		})
	}

	// Emit summary table
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "## Wardex — Aggregate Gate Decision")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "| File | Decision | Blocked | Allowed | Warned |")
	_, _ = fmt.Fprintln(w, "|------|----------|---------|---------|--------|")
	for _, r := range results {
		icon := "[OK]"
		switch r.decision {
		case "block":
			icon = "[FAIL]"
		case "warn":
			icon = "[WARN]"
		}
		_, _ = fmt.Fprintf(w, "| %s | %s %s | %d | %d | %d |\n",
			r.file, icon, strings.ToUpper(r.decision),
			r.blocked, r.allowed, r.warned,
		)
	}

	// Determine combined decision
	blockCount := 0
	for _, r := range results {
		if r.decision == "block" {
			blockCount++
		}
	}

	var combined string
	blocked := false
	switch failOn {
	case "any-block":
		blocked = blockCount > 0
	case "all-block":
		blocked = blockCount == len(results)
	}

	if blocked {
		combined = "BLOCK"
		_, _ = fmt.Fprintf(w, "\n**Combined Decision:** [FAIL] %s (%s — %d/%d framework(s) blocked)\n\n",
			combined, failOn, blockCount, len(results),
		)
		os.Exit(exitcodes.GateBlocked)
	}

	combined = "ALLOW"
	_, _ = fmt.Fprintf(w, "\n**Combined Decision:** [OK] %s\n\n", combined)
	os.Exit(exitcodes.OK)
	return nil
}
