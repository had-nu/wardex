// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package auth

import (
	"fmt"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var authTrustPath string

// AuthCmd is the parent command for trust store verification.
var AuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Verify trust store integrity and key status",
}

// StatusCmd shows trust store status.
var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show trust store status and integrity",
	RunE:  runAuthStatus,
}

// VerifyCmd verifies a specific actor's key.
var VerifyCmd = &cobra.Command{
	Use:   "verify --actor <email>",
	Short: "Verify an actor's key status and permissions",
	Args:  cobra.NoArgs,
	RunE:  runAuthVerify,
}

var authActor string

func init() {
	AuthCmd.PersistentFlags().StringVar(&authTrustPath, "trust", "./wardex-trust.yaml", "Path to wardex-trust.yaml")
	VerifyCmd.Flags().StringVar(&authActor, "actor", "", "Actor email to verify (required)")
	_ = VerifyCmd.MarkFlagRequired("actor")

	AuthCmd.AddCommand(StatusCmd, VerifyCmd)
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	store, _, err := trust.LoadStore(authTrustPath)
	if err != nil {
		return fmt.Errorf("auth status: %w", err)
	}

	// Count keys
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
		if k.Role == trust.RoleAdmin && adminID == "" && !revoked[k.ID] {
			adminID = k.ID
		}
	}

	// Verify root signature
	err = trust.VerifyRootSig(store)

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Trust store: %s\n", authTrustPath)

	if err != nil {
		fmt.Fprintf(w, "Status:      %s\n", ui.Colorize("INVALID", ui.Red))
		fmt.Fprintf(w, "Error:       %v\n", err)
		return nil
	}

	fmt.Fprintf(w, "Status:      %s\n", ui.Colorize("VALID", ui.Green))
	fmt.Fprintf(w, "Admin key:   %s\n", adminID)
	fmt.Fprintf(w, "Active keys: %d\n", activeCount)
	fmt.Fprintf(w, "Revoked:     %d\n", revokedCount)

	return nil
}

func runAuthVerify(cmd *cobra.Command, args []string) error {
	store, _, err := trust.LoadStore(authTrustPath)
	if err != nil {
		return fmt.Errorf("auth verify: %w", err)
	}

	// Find the actor
	var found *trust.KeyEntry
	for i, k := range store.Keys {
		if k.Actor == authActor {
			found = &store.Keys[i]
			break
		}
	}

	if found == nil {
		return fmt.Errorf("auth verify: actor %q not found in trust store", authActor)
	}

	// Check if revoked
	revoked := false
	for _, r := range store.Revocations {
		if r.KeyID == found.ID {
			revoked = true
			break
		}
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Actor:   %s\n", found.Actor)
	fmt.Fprintf(w, "Key:     %s\n", found.ID)
	fmt.Fprintf(w, "Name:    %s\n", found.Name)
	fmt.Fprintf(w, "Role:    %s\n", found.Role)

	if revoked {
		fmt.Fprintf(w, "Status:  %s\n", ui.Colorize("REVOKED", ui.Red))
	} else {
		fmt.Fprintf(w, "Status:  %s\n", ui.Colorize("ACTIVE", ui.Green))
	}

	// Show permissions
	perms := trust.RolePermissions[found.Role]
	if len(perms) > 0 {
		fmt.Fprintf(w, "Can perform:\n")
		for _, p := range perms {
			fmt.Fprintf(w, "  - %s\n", p)
		}
	}

	return nil
}
