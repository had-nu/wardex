// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package state

import (
	"fmt"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/pkg/statestore"
	"github.com/spf13/cobra"
)

var stateDir string

// StateCmd is the parent command for state store operations.
var StateCmd = &cobra.Command{
	Use:   "state",
	Short: "Manage the persistent state store",
	Long: `Manage the Wardex persistent state store for cross-execution memory.

The state store tracks gate decisions, risk trends, and acceptance
lifecycles across multiple wardex evaluate runs. It uses BLAKE3
hash chaining for integrity and optional WORM protection.

Examples:
  wardex state status
  wardex state history --days 30
  wardex state trend
  wardex state dashboard
  wardex state verify
  wardex state cleanup --retention 90`,
}

func init() {
	StateCmd.PersistentFlags().StringVar(&stateDir, "state-dir", ".wardex", "Path to state store directory")
}

func getStore() (*statestore.Store, error) {
	return statestore.New(stateDir)
}

// StatusCmd shows the current state.
var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current state store status",
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginStateUI(cmd, "status", stateDir)
		u.report(1, "Opening state store", "RUNNING", stateDir)
		store, err := getStore()
		if err != nil {
			u.report(1, "Opening state store", "FAILED", err.Error())
			if u.dashboardEnabled() {
				u.render(buildStateUnavailableDashboard(stateDir))
				return nil
			}
			fmt.Fprintf(u.stderr, "No state store found at %s/\n\n", stateDir)
			fmt.Fprintf(u.stderr, "To enable persistent state tracking:\n")
			fmt.Fprintf(u.stderr, "  1. Add to wardex-config.yaml:\n")
			fmt.Fprintf(u.stderr, "     state_store:\n")
			fmt.Fprintf(u.stderr, "       enabled: true\n")
			fmt.Fprintf(u.stderr, "       dir: %s\n", stateDir)
			fmt.Fprintf(u.stderr, "  2. Run: wardex evaluate --config wardex-config.yaml ...\n")
			return nil
		}
		u.report(1, "Opening state store", "DONE", stateDir)

		state, err := store.LoadState()
		if err != nil {
			u.report(2, "Loading current state", "FAILED", err.Error())
			return fmt.Errorf("failed to load state: %w", err)
		}
		u.report(2, "Loading current state", "DONE", fmt.Sprintf("%d run(s)", state.RunCount))

		if state.LastRun.IsZero() {
			if u.dashboardEnabled() {
				u.render(buildStateStatusDashboard(stateDir, state, nil))
				return nil
			}
			fmt.Fprintln(u.output, "No state recorded yet. Run 'wardex evaluate' with state_store.enabled=true to start tracking.")
			return nil
		}

		chainErr := store.VerifyChain()
		if chainErr != nil {
			u.report(3, "Verifying state chain", "FAILED", chainErr.Error())
		} else {
			u.report(3, "Verifying state chain", "DONE", "chain intact")
		}
		if u.dashboardEnabled() {
			u.render(buildStateStatusDashboard(stateDir, state, chainErr))
			return nil
		}

		fmt.Fprintf(u.output, "WARDEX STATE STATUS\n")
		fmt.Fprintf(u.output, "==================\n\n")
		fmt.Fprintf(u.output, "Version:        %s\n", state.Version)
		fmt.Fprintf(u.output, "Last Run:       %s\n", state.LastRun.Format("2006-01-02 15:04:05 UTC"))
		fmt.Fprintf(u.output, "Last Decision:  %s\n", state.LastDecision)
		fmt.Fprintf(u.output, "Risk Score:     %.1f%%\n", state.LastRisk*100)
		fmt.Fprintf(u.output, "Total Runs:     %d\n", state.RunCount)
		fmt.Fprintf(u.output, "Active Accepts: %d\n", state.ActiveAccepts)

		if len(state.ExpiringSoon) > 0 {
			fmt.Fprintf(u.output, "Expiring Soon:  %s\n", joinStrings(state.ExpiringSoon, ", "))
		}

		// Chain status
		fmt.Fprintf(u.output, "\nCHAIN INTEGRITY\n")
		fmt.Fprintf(u.output, "==================\n")
		if chainErr != nil {
			fmt.Fprintf(u.output, "Status:         BROKEN - %v\n", chainErr)
		} else {
			fmt.Fprintf(u.output, "Status:         OK\n")
		}

		return nil
	},
}

// HistoryCmd shows decision history.
var HistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show decision history",
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginStateUI(cmd, "history", stateDir)
		u.report(1, "Opening state store", "RUNNING", stateDir)
		store, err := getStore()
		if err != nil {
			u.report(1, "Opening state store", "FAILED", err.Error())
			return fmt.Errorf("failed to open state store: %w", err)
		}
		u.report(1, "Opening state store", "DONE", stateDir)

		records, err := store.ListHistory()
		if err != nil {
			u.report(2, "Loading decision history", "FAILED", err.Error())
			return fmt.Errorf("failed to list history: %w", err)
		}
		u.report(2, "Loading decision history", "DONE", fmt.Sprintf("%d record(s)", len(records)))
		if u.dashboardEnabled() {
			u.render(buildStateHistoryDashboard(stateDir, records))
			return nil
		}

		fmt.Fprint(u.output, statestore.FormatHistory(records))
		return nil
	},
}

// TrendCmd shows risk trend analysis.
var TrendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Show risk trend analysis",
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginStateUI(cmd, "trend", stateDir)
		u.report(1, "Opening state store", "RUNNING", stateDir)
		store, err := getStore()
		if err != nil {
			u.report(1, "Opening state store", "FAILED", err.Error())
			return fmt.Errorf("failed to open state store: %w", err)
		}
		u.report(1, "Opening state store", "DONE", stateDir)

		analysis, err := store.TrendAnalysis()
		if err != nil {
			u.report(2, "Analyzing risk trend", "FAILED", err.Error())
			return fmt.Errorf("failed to analyze trend: %w", err)
		}
		u.report(2, "Analyzing risk trend", "DONE", string(analysis.Direction))

		history, err := store.History(90)
		if err != nil {
			u.report(3, "Loading trend history", "FAILED", err.Error())
			return fmt.Errorf("failed to load history: %w", err)
		}
		u.report(3, "Loading trend history", "DONE", fmt.Sprintf("%d point(s)", len(history)))
		if u.dashboardEnabled() {
			u.render(buildStateTrendDashboard(stateDir, analysis, history))
			return nil
		}

		fmt.Fprint(u.output, statestore.FormatTrend(analysis, history))
		return nil
	},
}

// DashboardCmd shows comprehensive dashboard.
var DashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Show state dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginStateUI(cmd, "dashboard", stateDir)
		u.report(1, "Opening state store", "RUNNING", stateDir)
		store, err := getStore()
		if err != nil {
			u.report(1, "Opening state store", "FAILED", err.Error())
			return fmt.Errorf("failed to open state store: %w", err)
		}
		u.report(1, "Opening state store", "DONE", stateDir)

		state, err := store.LoadState()
		if err != nil {
			u.report(2, "Loading state snapshot", "FAILED", err.Error())
			return fmt.Errorf("failed to load state: %w", err)
		}
		u.report(2, "Loading state snapshot", "DONE", fmt.Sprintf("%d run(s)", state.RunCount))

		analysis, err := store.TrendAnalysis()
		if err != nil {
			analysis = &statestore.TrendAnalysis{}
		}
		if u.dashboardEnabled() {
			u.render(buildStateDashboardDashboard(stateDir, state, analysis))
			return nil
		}

		fmt.Fprint(u.output, statestore.FormatDashboard(state, analysis))
		return nil
	},
}

// VerifyCmd verifies chain integrity.
var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify BLAKE3 chain integrity",
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginStateUI(cmd, "verify", stateDir)
		u.report(1, "Opening state store", "RUNNING", stateDir)
		store, err := getStore()
		if err != nil {
			u.report(1, "Opening state store", "FAILED", err.Error())
			if u.dashboardEnabled() {
				u.render(buildStateUnavailableDashboard(stateDir))
				return nil
			}
			fmt.Fprintf(u.stderr, "No state store found at %s/\n\n", stateDir)
			fmt.Fprintf(u.stderr, "To enable persistent state tracking:\n")
			fmt.Fprintf(u.stderr, "  1. Add to wardex-config.yaml:\n")
			fmt.Fprintf(u.stderr, "     state_store:\n")
			fmt.Fprintf(u.stderr, "       enabled: true\n")
			fmt.Fprintf(u.stderr, "       dir: %s\n", stateDir)
			fmt.Fprintf(u.stderr, "  2. Run: wardex evaluate --config wardex-config.yaml ...\n")
			return nil
		}
		u.report(1, "Opening state store", "DONE", stateDir)

		verifyErr := store.VerifyChain()
		if verifyErr != nil {
			u.report(2, "Verifying BLAKE3 chain", "FAILED", verifyErr.Error())
		} else {
			u.report(2, "Verifying BLAKE3 chain", "DONE", "chain intact")
		}

		chain, chainErr := statestore.LoadChain(store.ChainPath())
		entries := 0
		var first, last time.Time
		if chainErr == nil {
			entries = len(chain.Entries)
			if entries > 0 {
				first = chain.Entries[0].Timestamp
				last = chain.Entries[entries-1].Timestamp
			}
		}
		if u.dashboardEnabled() {
			u.render(buildStateVerifyDashboard(stateDir, entries, first, last, verifyErr))
			return verifyErr
		}

		if verifyErr != nil {
			fmt.Fprintf(u.stderr, "Chain integrity: BROKEN\n")
			fmt.Fprintf(u.stderr, "Error: %v\n", verifyErr)
			return verifyErr
		}

		fmt.Fprintln(u.output, "Chain integrity: OK")

		// Show chain stats
		if chainErr == nil {
			fmt.Fprintf(u.output, "Chain entries:   %d\n", len(chain.Entries))
			if len(chain.Entries) > 0 {
				fmt.Fprintf(u.output, "First entry:     %s\n", chain.Entries[0].Timestamp.Format("2006-01-02 15:04:05 UTC"))
				fmt.Fprintf(u.output, "Last entry:      %s\n", chain.Entries[len(chain.Entries)-1].Timestamp.Format("2006-01-02 15:04:05 UTC"))
			}
		}

		return nil
	},
}

// CleanupCmd removes old history.
var CleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove old history snapshots",
	RunE: func(cmd *cobra.Command, args []string) error {
		u := beginStateUI(cmd, "cleanup", stateDir)
		u.report(1, "Opening state store", "RUNNING", stateDir)
		store, err := getStore()
		if err != nil {
			u.report(1, "Opening state store", "FAILED", err.Error())
			return fmt.Errorf("failed to open state store: %w", err)
		}

		retentionDays := 90
		if cmd.Flags().Changed("retention") {
			val, _ := cmd.Flags().GetInt("retention")
			retentionDays = val
		}
		u.report(1, "Opening state store", "DONE", stateDir)
		u.report(2, "Removing old history", "RUNNING", fmt.Sprintf("%d day retention", retentionDays))
		if err := store.Cleanup(retentionDays); err != nil {
			u.report(2, "Removing old history", "FAILED", err.Error())
			return fmt.Errorf("cleanup failed: %w", err)
		}
		u.report(2, "Removing old history", "DONE", "cleanup complete")
		if u.dashboardEnabled() {
			u.render(buildStateCleanupDashboard(stateDir, retentionDays))
			return nil
		}

		fmt.Fprintf(u.output, "Cleanup completed (retention: %d days)\n", retentionDays)
		return nil
	},
}

func init() {
	HistoryCmd.Flags().Int("days", 30, "Show history for last N days")
	CleanupCmd.Flags().Int("retention", 90, "Retention period in days")

	StateCmd.AddCommand(StatusCmd)
	StateCmd.AddCommand(HistoryCmd)
	StateCmd.AddCommand(TrendCmd)
	StateCmd.AddCommand(DashboardCmd)
	StateCmd.AddCommand(VerifyCmd)
	StateCmd.AddCommand(CleanupCmd)
}

func joinStrings(strs []string, sep string) string {
	var result strings.Builder
	for i, s := range strs {
		if i > 0 {
			result.WriteString(sep)
		}
		result.WriteString(s)
	}
	return result.String()
}
