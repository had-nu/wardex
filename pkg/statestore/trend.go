// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package statestore

import (
	"fmt"
	"strings"
	"time"
)

// FormatTrend formats the trend analysis for CLI output.
func FormatTrend(analysis *TrendAnalysis, history []TrendPoint) string {
	var sb strings.Builder

	sb.WriteString("TREND ANALYSIS\n")
	sb.WriteString(strings.Repeat("=", 40) + "\n\n")

	// Direction
	fmt.Fprintf(&sb, "Direction:      %s\n", strings.ToUpper(string(analysis.Direction)))

	// Risk summary
	fmt.Fprintf(&sb, "Average Risk:   %.1f%%\n", analysis.AverageRisk*100)
	fmt.Fprintf(&sb, "Min Risk:       %.1f%%\n", analysis.MinRisk*100)
	fmt.Fprintf(&sb, "Max Risk:       %.1f%%\n", analysis.MaxRisk*100)
	fmt.Fprintf(&sb, "Risk Delta:     %+.1f%%\n", analysis.RiskDelta*100)

	// Run counts
	fmt.Fprintf(&sb, "\nTotal Runs:     %d\n", analysis.TotalRuns)
	fmt.Fprintf(&sb, "  Allow:        %d\n", analysis.AllowCount)
	fmt.Fprintf(&sb, "  Warn:         %d\n", analysis.WarnCount)
	fmt.Fprintf(&sb, "  Block:        %d\n", analysis.BlockCount)

	// Time range
	fmt.Fprintf(&sb, "\nPeriod:         %s → %s\n",
		analysis.OldestRun.Format("2006-01-02"),
		analysis.NewestRun.Format("2006-01-02"),
	)

	// Mini sparkline chart
	if len(history) > 1 {
		sb.WriteString("\nRISK TREND\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")

		// Show last 30 data points max
		start := 0
		if len(history) > 30 {
			start = len(history) - 30
		}
		recent := history[start:]

		for _, p := range recent {
			barLen := int(p.Risk * 40)
			if barLen == 0 && p.Risk > 0 {
				barLen = 1
			}

			indicator := " "
			switch p.Decision {
			case "block":
				indicator = "!"
			case "warn":
				indicator = "~"
			}

			fmt.Fprintf(&sb, "%s %s %5.1f%% %s\n",
				p.Date.Format("01-02"),
				indicator,
				p.Risk*100,
				strings.Repeat("#", barLen),
			)
		}
	}

	// Interpretation
	sb.WriteString("\nINTERPRETATION\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	switch analysis.Direction {
	case TrendImproving:
		sb.WriteString("Security posture is IMPROVING over time.\n")
		if analysis.RiskDelta < -0.20 {
			sb.WriteString("Significant risk reduction detected.\n")
		}
	case TrendWorsening:
		sb.WriteString("Security posture is WORSENING over time.\n")
		if analysis.RiskDelta > 0.20 {
			sb.WriteString("Significant risk increase detected — investigate.\n")
		}
	case TrendStable:
		sb.WriteString("Security posture is STABLE.\n")
	}

	return sb.String()
}

// FormatHistory formats history for CLI tabular output.
func FormatHistory(records []HistoryRecord) string {
	if len(records) == 0 {
		return "No history records found.\n"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "HISTORY (%d records)\n", len(records))
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	fmt.Fprintf(&sb, "%-20s %-8s %-8s %-10s %-8s\n",
		"DATE", "RISK", "DECISION", "VULNS", "ACCEPTS")
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, r := range records {
		fmt.Fprintf(&sb, "%-20s %-8s %-8s %-10d %-8d\n",
			r.Timestamp.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%.1f%%", r.State.LastRisk*100),
			strings.ToUpper(r.State.LastDecision),
			countTrendVulns(r.State.Trend),
			r.State.ActiveAccepts,
		)
	}

	return sb.String()
}

// countTrendVulns sums vulnerability counts from trend points.
func countTrendVulns(trend []TrendPoint) int {
	total := 0
	for _, p := range trend {
		total += p.VulnCount
	}
	return total
}

// FormatDashboard formats a comprehensive dashboard view.
func FormatDashboard(state *State, analysis *TrendAnalysis) string {
	var sb strings.Builder

	sb.WriteString("WARDEX STATE DASHBOARD\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	// Current state
	sb.WriteString("CURRENT STATE\n")
	sb.WriteString(strings.Repeat("-", 50) + "\n")
	fmt.Fprintf(&sb, "Version:        %s\n", state.Version)
	fmt.Fprintf(&sb, "Last Run:       %s\n", state.LastRun.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&sb, "Last Decision:  %s\n", strings.ToUpper(state.LastDecision))
	fmt.Fprintf(&sb, "Risk Score:     %.1f%%\n", state.LastRisk*100)
	fmt.Fprintf(&sb, "Total Runs:     %d\n", state.RunCount)
	fmt.Fprintf(&sb, "Active Accepts: %d\n", state.ActiveAccepts)

	if len(state.ExpiringSoon) > 0 {
		fmt.Fprintf(&sb, "Expiring Soon:  %s\n", strings.Join(state.ExpiringSoon, ", "))
	}

	// Trend
	if analysis != nil {
		sb.WriteString("\nTREND SUMMARY\n")
		sb.WriteString(strings.Repeat("-", 50) + "\n")
		fmt.Fprintf(&sb, "Direction:      %s\n", strings.ToUpper(string(analysis.Direction)))
		fmt.Fprintf(&sb, "Avg Risk:       %.1f%%\n", analysis.AverageRisk*100)
		fmt.Fprintf(&sb, "Risk Delta:     %+.1f%%\n", analysis.RiskDelta*100)
		fmt.Fprintf(&sb, "Runs (allow/warn/block): %d/%d/%d\n",
			analysis.AllowCount, analysis.WarnCount, analysis.BlockCount)
	}

	// Recent trend
	if len(state.Trend) > 0 {
		sb.WriteString("\nRECENT TREND (last 10)\n")
		sb.WriteString(strings.Repeat("-", 50) + "\n")

		start := 0
		if len(state.Trend) > 10 {
			start = len(state.Trend) - 10
		}
		recent := state.Trend[start:]

		for _, p := range recent {
			barLen := int(p.Risk * 30)
			if barLen == 0 && p.Risk > 0 {
				barLen = 1
			}
			fmt.Fprintf(&sb, "  %s  %5.1f%%  %-5s  %s\n",
				p.Date.Format("01-02"),
				p.Risk*100,
				strings.ToUpper(p.Decision),
				strings.Repeat("█", barLen),
			)
		}
	}

	// Footer
	fmt.Fprintf(&sb, "\nGenerated: %s\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	return sb.String()
}
