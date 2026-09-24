// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trustcmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	listOutput string
	showOutput string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys in the trust store",
	Long: `Display all keys in the trust store with their status (active/revoked).

Output formats: table (default), json, csv`,
	RunE: runTrustList,
}

var showCmd = &cobra.Command{
	Use:   "show <key-id>",
	Short: "Show details of a specific key entry",
	Args:  cobra.ExactArgs(1),
	RunE:  runTrustShow,
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify trust store root signature integrity",
	Long: `Verify that the trust store root signature is valid, confirming
that no entries have been tampered with since the store was last
modified by an authorised admin.`,
	RunE: runTrustVerify,
}

func init() {
	listCmd.Flags().StringVar(&trustPath, "trust", "./wardex-trust.yaml", "Path to wardex-trust.yaml")
	listCmd.Flags().StringVarP(&listOutput, "output", "o", "table", "Output format: table|json|csv")

	showCmd.Flags().StringVar(&trustPath, "trust", "./wardex-trust.yaml", "Path to wardex-trust.yaml")
	showCmd.Flags().StringVarP(&showOutput, "output", "o", "json", "Output format: json|table")

	verifyCmd.Flags().StringVar(&trustPath, "trust", "./wardex-trust.yaml", "Path to wardex-trust.yaml")

	TrustCmd.AddCommand(listCmd, showCmd, verifyCmd)
}

func runTrustList(cmd *cobra.Command, args []string) error {
	u := beginTrustUI(cmd, "list", trustPath)
	u.report(1, "Loading trust store", "RUNNING", trustPath)
	store, _, err := trust.LoadStore(trustPath)
	if err != nil {
		u.report(1, "Loading trust store", "FAILED", err.Error())
		return fmt.Errorf("trust list: %w", err)
	}
	u.report(1, "Loading trust store", "DONE", fmt.Sprintf("%d key(s)", len(store.Keys)))

	revoked := trust.RevokedKeySet(store)
	u.report(2, "Preparing trust store output", "RUNNING", "")
	if listOutput != "json" && listOutput != "csv" && u.dashboardEnabled() {
		u.report(2, "Preparing trust store output", "DONE", "table ready")
		u.render(buildTrustListDashboard(store, trustPath))
		return nil
	}
	u.report(2, "Preparing trust store output", "DONE", listOutput)

	switch listOutput {
	case "json":
		type keyInfo struct {
			ID      string `json:"id"`
			Actor   string `json:"actor"`
			Name    string `json:"name"`
			Role    string `json:"role"`
			Status  string `json:"status"`
			AddedAt string `json:"added_at"`
			AddedBy string `json:"added_by"`
		}
		var keys []keyInfo
		for _, k := range store.Keys {
			status := "active"
			if revoked[k.ID] {
				status = "revoked"
			}
			keys = append(keys, keyInfo{
				ID: k.ID, Actor: k.Actor, Name: k.Name,
				Role: string(k.Role), Status: status,
				AddedAt: k.AddedAt.Format("2006-01-02T15:04:05Z"), AddedBy: k.AddedBy,
			})
		}
		data, _ := json.MarshalIndent(keys, "", "  ")
		fmt.Fprintln(u.output, string(data))

	case "csv":
		fmt.Fprintln(u.output, "id,actor,name,role,status,added_at,added_by")
		for _, k := range store.Keys {
			status := "active"
			if revoked[k.ID] {
				status = "revoked"
			}
			fmt.Fprintf(u.output, "%s,%s,%s,%s,%s,%s,%s\n",
				k.ID, k.Actor, k.Name, k.Role, status,
				k.AddedAt.Format("2006-01-02T15:04:05Z"), k.AddedBy)
		}

	default: // table
		w := u.output
		hdr := func(s string, w2 int) string {
			if ui.IsTerminal(w) {
				return ui.PadANSI(ui.Colorize(s, ui.Cyan+ui.Bold), w2)
			}
			return ui.PadANSI(s, w2)
		}
		const (
			wID     = 16
			wActor  = 28
			wName   = 24
			wRole   = 10
			wStatus = 10
			wDate   = 22
		)
		lineChar := '─'
		if !ui.IsTerminal(w) {
			lineChar = '-'
		}
		fill := func(n int) string {
			return strings.Repeat(string(lineChar), n)
		}
		rule := func(value string) string {
			if ui.IsTerminal(w) {
				return ui.Colorize(value, ui.Gray)
			}
			return value
		}
		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
			hdr("Key ID", wID), hdr("Actor", wActor), hdr("Name", wName),
			hdr("Role", wRole), hdr("Status", wStatus), hdr("Added At", wDate))
		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
			rule(fill(wID)),
			rule(fill(wActor)),
			rule(fill(wName)),
			rule(fill(wRole)),
			rule(fill(wStatus)),
			rule(fill(wDate)))

		for _, k := range store.Keys {
			status := "active"
			sc := ui.Green
			if revoked[k.ID] {
				status = "revoked"
				sc = ui.Red
			}
			name := k.Name
			if len(name) > 22 {
				name = name[:19] + "..."
			}
			actor := k.Actor
			if len(actor) > 26 {
				actor = actor[:23] + "..."
			}
			statusValue := status
			if ui.IsTerminal(w) {
				statusValue = ui.Colorize(status, sc)
			}
			fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
				ui.PadANSI(k.ID, wID),
				ui.PadANSI(actor, wActor),
				ui.PadANSI(name, wName),
				ui.PadANSI(string(k.Role), wRole),
				ui.PadANSI(statusValue, wStatus),
				ui.PadANSI(k.AddedAt.Format("2006-01-02 15:04 UTC"), wDate))
		}
	}

	return nil
}

func runTrustShow(cmd *cobra.Command, args []string) error {
	u := beginTrustUI(cmd, "show", trustPath)
	u.report(1, "Loading trust store", "RUNNING", trustPath)
	store, _, err := trust.LoadStore(trustPath)
	if err != nil {
		u.report(1, "Loading trust store", "FAILED", err.Error())
		return fmt.Errorf("trust show: %w", err)
	}
	u.report(1, "Loading trust store", "DONE", fmt.Sprintf("%d key(s)", len(store.Keys)))
	u.report(2, "Locating key entry", "RUNNING", args[0])

	// Build revoked map
	revokedAt := make(map[string]string)
	for _, r := range store.Revocations {
		revokedAt[r.KeyID] = r.RevokedAt.Format("2006-01-02T15:04:05Z")
	}

	for _, k := range store.Keys {
		if k.ID == args[0] {
			status := "active"
			if t, ok := revokedAt[k.ID]; ok {
				status = "revoked"
				fmt.Fprintf(u.stderr, "[REVOKED at %s]\n", t)
			}
			u.report(2, "Locating key entry", "DONE", k.ID)
			u.report(3, "Preparing key details", "RUNNING", "")
			u.report(3, "Preparing key details", "DONE", "details ready")
			if showOutput == "table" && u.dashboardEnabled() {
				u.render(buildTrustDetailDashboard(k, status, trustPath))
				return nil
			}

			switch showOutput {
			case "json":
				type keyDetail struct {
					ID       string `json:"id"`
					Actor    string `json:"actor"`
					Name     string `json:"name"`
					Role     string `json:"role"`
					Status   string `json:"status"`
					AddedAt  string `json:"added_at"`
					AddedBy  string `json:"added_by"`
					AddedSig string `json:"added_sig,omitempty"`
				}
				d := keyDetail{
					ID: k.ID, Actor: k.Actor, Name: k.Name,
					Role: string(k.Role), Status: status,
					AddedAt: k.AddedAt.Format("2006-01-02T15:04:05Z"), AddedBy: k.AddedBy,
				}
				if showOutput == "json" {
					d.AddedSig = k.AddedSig
				}
				data, _ := json.MarshalIndent(d, "", "  ")
				fmt.Fprintln(u.output, string(data))

			default: // table
				w := u.output
				fmt.Fprintf(w, "Key ID:    %s\n", k.ID)
				fmt.Fprintf(w, "Actor:     %s\n", k.Actor)
				fmt.Fprintf(w, "Name:      %s\n", k.Name)
				fmt.Fprintf(w, "Role:      %s\n", k.Role)
				fmt.Fprintf(w, "Status:    %s\n", status)
				fmt.Fprintf(w, "Added At:  %s\n", k.AddedAt.Format("2006-01-02 15:04 UTC"))
				fmt.Fprintf(w, "Added By:  %s\n", k.AddedBy)
			}
			return nil
		}
	}

	err = fmt.Errorf("trust show: key %q not found", args[0])
	u.report(2, "Locating key entry", "FAILED", err.Error())
	return err
}

func runTrustVerify(cmd *cobra.Command, args []string) error {
	u := beginTrustUI(cmd, "verify", trustPath)
	u.report(1, "Loading trust store", "RUNNING", trustPath)
	store, _, err := trust.LoadStore(trustPath)
	if err != nil {
		u.report(1, "Loading trust store", "FAILED", err.Error())
		return fmt.Errorf("trust verify: %w", err)
	}
	activeCount, revokedCount, adminID := trust.KeyStats(store)
	u.report(1, "Loading trust store", "DONE", fmt.Sprintf("%d key(s)", len(store.Keys)))

	u.report(2, "Verifying root signature", "RUNNING", "")
	err = trust.VerifyRootSig(store)
	if err != nil {
		u.report(2, "Verifying root signature", "FAILED", err.Error())
		if u.dashboardEnabled() {
			u.render(buildTrustVerifyDashboard(trustPath, adminID, len(store.Keys), activeCount, revokedCount, false))
		} else {
			w := u.output
			status := "INVALID"
			if ui.IsTerminal(w) {
				status = ui.Colorize(status, ui.Red)
			}
			fmt.Fprintf(w, "Trust store: %s\n", trustPath)
			fmt.Fprintf(w, "Root signature: %s\n", status)
			fmt.Fprintf(w, "Error: %v\n", err)
		}
		return fmt.Errorf("trust verify: root signature invalid: %w", err)
	}
	u.report(2, "Verifying root signature", "DONE", "root signature valid")
	u.report(3, "Finalizing trust verification", "RUNNING", "")
	u.report(3, "Finalizing trust verification", "DONE", "verification complete")
	if u.dashboardEnabled() {
		u.render(buildTrustVerifyDashboard(trustPath, adminID, len(store.Keys), activeCount, revokedCount, true))
		return nil
	}

	w := u.output
	fmt.Fprintf(w, "Trust store: %s\n", trustPath)
	rootStatus := "VALID"
	if ui.IsTerminal(w) {
		rootStatus = ui.Colorize(rootStatus, ui.Green)
	}
	fmt.Fprintf(w, "Root signature: %s\n", rootStatus)
	fmt.Fprintf(w, "Admin key:      %s\n", adminID)
	fmt.Fprintf(w, "Total entries:  %d (%d active, %d revoked)\n", len(store.Keys), activeCount, revokedCount)

	return nil
}
