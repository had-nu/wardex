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
	store, _, err := trust.LoadStore(trustPath)
	if err != nil {
		return fmt.Errorf("trust list: %w", err)
	}

	// Build revoked set
	revoked := make(map[string]bool)
	for _, r := range store.Revocations {
		revoked[r.KeyID] = true
	}

	switch listOutput {
	case "json":
		type keyInfo struct {
			ID       string `json:"id"`
			Actor    string `json:"actor"`
			Name     string `json:"name"`
			Role     string `json:"role"`
			Status   string `json:"status"`
			AddedAt  string `json:"added_at"`
			AddedBy  string `json:"added_by"`
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
		fmt.Fprintln(cmd.OutOrStdout(), string(data))

	case "csv":
		fmt.Fprintln(cmd.OutOrStdout(), "id,actor,name,role,status,added_at,added_by")
		for _, k := range store.Keys {
			status := "active"
			if revoked[k.ID] {
				status = "revoked"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s,%s,%s,%s,%s,%s,%s\n",
				k.ID, k.Actor, k.Name, k.Role, status,
				k.AddedAt.Format("2006-01-02T15:04:05Z"), k.AddedBy)
		}

	default: // table
		w := cmd.OutOrStdout()
		hdr := func(s string, w2 int) string {
			return ui.PadANSI(ui.Colorize(s, ui.Cyan+ui.Bold), w2)
		}
		const (
			wID     = 16
			wActor  = 28
			wName   = 24
			wRole   = 10
			wStatus = 10
			wDate   = 22
		)
		fill := func(r rune, n int) string {
			return strings.Repeat(string(r), n)
		}
		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
			hdr("Key ID", wID), hdr("Actor", wActor), hdr("Name", wName),
			hdr("Role", wRole), hdr("Status", wStatus), hdr("Added At", wDate))
		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
			ui.Colorize(fill('─', wID), ui.Gray),
			ui.Colorize(fill('─', wActor), ui.Gray),
			ui.Colorize(fill('─', wName), ui.Gray),
			ui.Colorize(fill('─', wRole), ui.Gray),
			ui.Colorize(fill('─', wStatus), ui.Gray),
			ui.Colorize(fill('─', wDate), ui.Gray))

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
			fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s\n",
				ui.PadANSI(k.ID, wID),
				ui.PadANSI(actor, wActor),
				ui.PadANSI(name, wName),
				ui.PadANSI(string(k.Role), wRole),
				ui.PadANSI(ui.Colorize(status, sc), wStatus),
				ui.PadANSI(k.AddedAt.Format("2006-01-02 15:04 UTC"), wDate))
		}
	}

	return nil
}

func runTrustShow(cmd *cobra.Command, args []string) error {
	store, _, err := trust.LoadStore(trustPath)
	if err != nil {
		return fmt.Errorf("trust show: %w", err)
	}

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
				fmt.Fprintf(cmd.ErrOrStderr(), "[REVOKED at %s]\n", t)
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
				fmt.Fprintln(cmd.OutOrStdout(), string(data))

			default: // table
				w := cmd.OutOrStdout()
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

	return fmt.Errorf("trust show: key %q not found", args[0])
}

func runTrustVerify(cmd *cobra.Command, args []string) error {
	store, _, err := trust.LoadStore(trustPath)
	if err != nil {
		return fmt.Errorf("trust verify: %w", err)
	}

	// Count active/revoked
	revoked := make(map[string]bool)
	for _, r := range store.Revocations {
		revoked[r.KeyID] = true
	}
	var activeCount, revokedCount int
	var adminID string
	for _, k := range store.Keys {
		if revoked[k.ID] {
			revokedCount++
		} else {
			activeCount++
		}
		if k.Role == trust.RoleAdmin && adminID == "" {
			adminID = k.ID
		}
	}

	// Verify root signature
	err = trust.VerifyRootSig(store)

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Trust store: %s\n", trustPath)

	if err != nil {
		fmt.Fprintf(w, "Root signature: %s\n", ui.Colorize("INVALID", ui.Red))
		fmt.Fprintf(w, "Error: %v\n", err)
		return fmt.Errorf("trust verify: root signature invalid: %w", err)
	}

	fmt.Fprintf(w, "Root signature: %s\n", ui.Colorize("VALID", ui.Green))
	fmt.Fprintf(w, "Admin key:      %s\n", adminID)
	fmt.Fprintf(w, "Total entries:  %d (%d active, %d revoked)\n", len(store.Keys), activeCount, revokedCount)

	return nil
}
