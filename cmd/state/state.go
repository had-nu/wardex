// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package state

import (
	"fmt"

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
		store, err := getStore()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "No state store found at %s/\n\n", stateDir)
			fmt.Fprintf(cmd.ErrOrStderr(), "To enable persistent state tracking:\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "  1. Add to wardex-config.yaml:\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "     state_store:\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "       enabled: true\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "       dir: %s\n", stateDir)
			fmt.Fprintf(cmd.ErrOrStderr(), "  2. Run: wardex evaluate --config wardex-config.yaml ...\n")
			return nil
		}

		state, err := store.LoadState()
		if err != nil {
			return fmt.Errorf("failed to load state: %w", err)
		}

		if state.LastRun.IsZero() {
			fmt.Fprintln(cmd.OutOrStdout(), "No state recorded yet. Run 'wardex evaluate' with state_store.enabled=true to start tracking.")
			return nil
		}

		fmt.Printf("WARDEX STATE STATUS\n")
		fmt.Printf("==================\n\n")
		fmt.Printf("Version:        %s\n", state.Version)
		fmt.Printf("Last Run:       %s\n", state.LastRun.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("Last Decision:  %s\n", state.LastDecision)
		fmt.Printf("Risk Score:     %.1f%%\n", state.LastRisk*100)
		fmt.Printf("Total Runs:     %d\n", state.RunCount)
		fmt.Printf("Active Accepts: %d\n", state.ActiveAccepts)

		if len(state.ExpiringSoon) > 0 {
			fmt.Printf("Expiring Soon:  %s\n", joinStrings(state.ExpiringSoon, ", "))
		}

		// Chain status
		fmt.Printf("\nCHAIN INTEGRITY\n")
		fmt.Printf("==================\n")
		if err := store.VerifyChain(); err != nil {
			fmt.Printf("Status:         BROKEN - %v\n", err)
		} else {
			fmt.Printf("Status:         OK\n")
		}

		return nil
	},
}

// HistoryCmd shows decision history.
var HistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show decision history",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := getStore()
		if err != nil {
			return fmt.Errorf("failed to open state store: %w", err)
		}

		records, err := store.ListHistory()
		if err != nil {
			return fmt.Errorf("failed to list history: %w", err)
		}

		fmt.Print(statestore.FormatHistory(records))
		return nil
	},
}

// TrendCmd shows risk trend analysis.
var TrendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Show risk trend analysis",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := getStore()
		if err != nil {
			return fmt.Errorf("failed to open state store: %w", err)
		}

		analysis, err := store.TrendAnalysis()
		if err != nil {
			return fmt.Errorf("failed to analyze trend: %w", err)
		}

		history, err := store.History(90)
		if err != nil {
			return fmt.Errorf("failed to load history: %w", err)
		}

		fmt.Print(statestore.FormatTrend(analysis, history))
		return nil
	},
}

// DashboardCmd shows comprehensive dashboard.
var DashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Show state dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := getStore()
		if err != nil {
			return fmt.Errorf("failed to open state store: %w", err)
		}

		state, err := store.LoadState()
		if err != nil {
			return fmt.Errorf("failed to load state: %w", err)
		}

		analysis, err := store.TrendAnalysis()
		if err != nil {
			analysis = &statestore.TrendAnalysis{}
		}

		fmt.Print(statestore.FormatDashboard(state, analysis))
		return nil
	},
}

// VerifyCmd verifies chain integrity.
var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify BLAKE3 chain integrity",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := getStore()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "No state store found at %s/\n\n", stateDir)
			fmt.Fprintf(cmd.ErrOrStderr(), "To enable persistent state tracking:\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "  1. Add to wardex-config.yaml:\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "     state_store:\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "       enabled: true\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "       dir: %s\n", stateDir)
			fmt.Fprintf(cmd.ErrOrStderr(), "  2. Run: wardex evaluate --config wardex-config.yaml ...\n")
			return nil
		}

		if err := store.VerifyChain(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Chain integrity: BROKEN\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Chain integrity: OK")

		// Show chain stats
		chain, err := statestore.LoadChain(store.ChainPath())
		if err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Chain entries:   %d\n", len(chain.Entries))
			if len(chain.Entries) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "First entry:     %s\n", chain.Entries[0].Timestamp.Format("2006-01-02 15:04:05 UTC"))
				fmt.Fprintf(cmd.OutOrStdout(), "Last entry:      %s\n", chain.Entries[len(chain.Entries)-1].Timestamp.Format("2006-01-02 15:04:05 UTC"))
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
		store, err := getStore()
		if err != nil {
			return fmt.Errorf("failed to open state store: %w", err)
		}

		retentionDays := 90
		if cmd.Flags().Changed("retention") {
			val, _ := cmd.Flags().GetInt("retention")
			retentionDays = val
		}

		if err := store.Cleanup(retentionDays); err != nil {
			return fmt.Errorf("cleanup failed: %w", err)
		}

		fmt.Printf("Cleanup completed (retention: %d days)\n", retentionDays)
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
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
