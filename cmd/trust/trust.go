// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trustcmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	// Shared flags
	keyringPath string
	trustPath   string

	// trust init flags
	initActor string
	initName  string
	initOut   string

	// trust add flags
	addPubkey string
	addRole   string
	addActor  string
	addName   string

	// trust revoke flags
	revokeID     string
	revokeReason string
)

// TrustCmd is the parent command for trust store management.
var TrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage the Wardex trust store (keypairs, roles, revocations)",
	Long: `The trust store (wardex-trust.yaml) controls who can seal release gate
configurations. It uses ed25519 signatures for non-repudiation.

Use 'wardex trust init' to bootstrap a new trust store.
Use 'wardex trust add' to onboard new operators.
Use 'wardex trust revoke' to revoke compromised or rotated keys.`,
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Bootstrap a new trust store with the admin key",
	Long: `Create a new wardex-trust.yaml with the initial admin key.
This can only be run once — subsequent calls fail if the file exists.

After initialisation, configure branch protection on your repository
to prevent unauthorised modifications to the trust store.`,
	RunE: runTrustInit,
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new operator to the trust store",
	Long: `Add a new operator's public key to the trust store with a specific role.
Requires the signing key to have role 'admin'.

Roles:
  admin   — Can manage the trust store and seal configs
  ciso    — Can seal configs and approve acceptances
  analyst — Can evaluate and create acceptance requests`,
	RunE: runTrustAdd,
}

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a key from the trust store",
	Long: `Revoke an existing key in the trust store. The revocation is append-only —
the original key entry is never modified or deleted.

Any sealed configs signed by the revoked key will be rejected by
'wardex evaluate' until re-sealed by an active ciso or admin.`,
	RunE: runTrustRevoke,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultKeyring := filepath.Join(home, ".crypto", "trust", "root.key")

	// init
	initCmd.Flags().StringVar(&keyringPath, "keyring", defaultKeyring, "Path to admin private key")
	initCmd.Flags().StringVar(&initActor, "actor", "", "Email of the admin (required)")
	initCmd.Flags().StringVar(&initName, "name", "", "Full name of the admin (required)")
	initCmd.Flags().StringVar(&initOut, "out", "./wardex-trust.yaml", "Output path for the trust store")
	_ = initCmd.MarkFlagRequired("actor")
	_ = initCmd.MarkFlagRequired("name")

	// add
	addCmd.Flags().StringVar(&keyringPath, "keyring", defaultKeyring, "Path to admin private key (required)")
	addCmd.Flags().StringVar(&addPubkey, "pubkey", "", "Path to the new operator's .pub file (required)")
	addCmd.Flags().StringVar(&addRole, "role", "", "Role: analyst | ciso | admin (required)")
	addCmd.Flags().StringVar(&addActor, "actor", "", "Email of the new operator (required)")
	addCmd.Flags().StringVar(&addName, "name", "", "Full name of the new operator (required)")
	addCmd.Flags().StringVar(&trustPath, "trust", "./wardex-trust.yaml", "Path to wardex-trust.yaml")
	_ = addCmd.MarkFlagRequired("pubkey")
	_ = addCmd.MarkFlagRequired("role")
	_ = addCmd.MarkFlagRequired("actor")
	_ = addCmd.MarkFlagRequired("name")

	// revoke
	revokeCmd.Flags().StringVar(&keyringPath, "keyring", defaultKeyring, "Path to admin private key (required)")
	revokeCmd.Flags().StringVar(&revokeID, "id", "", "KeyEntry.ID to revoke (required)")
	revokeCmd.Flags().StringVar(&revokeReason, "reason", "", "Reason for revocation (required, min 10 chars)")
	revokeCmd.Flags().StringVar(&trustPath, "trust", "./wardex-trust.yaml", "Path to wardex-trust.yaml")
	_ = revokeCmd.MarkFlagRequired("id")
	_ = revokeCmd.MarkFlagRequired("reason")

	TrustCmd.AddCommand(initCmd, addCmd, revokeCmd)
}

func runTrustInit(cmd *cobra.Command, args []string) error {
	if err := trust.InitStore(keyringPath, initActor, initName, initOut); err != nil {
		return err
	}

	// Extract the generated key ID from the store for the output
	store, _, err := trust.LoadStore(initOut)
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Trust store initialised.")
	fmt.Fprintf(w, "  %s %s\n", ui.Colorize("File:", ui.Gray), initOut)
	fmt.Fprintf(w, "  %s %s\n", ui.Colorize("Admin:", ui.Gray), initActor)
	fmt.Fprintf(w, "  %s %s\n\n", ui.Colorize("Key ID:", ui.Gray), store.Keys[0].ID)
	fmt.Fprintf(w, "NEXT STEPS — do not skip:\n")
	fmt.Fprintf(w, "  1. git add %s\n", initOut)
	fmt.Fprintf(w, "  2. git commit -m \"chore: wardex trust bootstrap\"\n")
	fmt.Fprintf(w, "  3. Configure branch protection on this repository:\n")
	fmt.Fprintf(w, "       - Require pull request reviews before merging\n")
	fmt.Fprintf(w, "       - Restrict who can push to the default branch\n")
	fmt.Fprintf(w, "     Without branch protection, this file can be overwritten by any contributor.\n")

	if !isInsideGitRepo(initOut) {
		fmt.Fprintf(cmd.OutOrStdout(), "\nWarning: %s is not inside a Git repository.\n"+
			"         wardex-trust.yaml is only effective when version-controlled with branch protection.\n",
			filepath.Dir(initOut))
	}

	return nil
}

func isInsideGitRepo(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	dir := filepath.Dir(abs)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

func runTrustAdd(cmd *cobra.Command, args []string) error {
	role := trust.Role(addRole)
	if err := trust.AddKey(trustPath, keyringPath, addPubkey, role, addActor, addName); err != nil {
		return err
	}

	// Load updated store to get the new key ID
	store, _, err := trust.LoadStore(trustPath)
	if err != nil {
		return err
	}

	newEntry := store.Keys[len(store.Keys)-1]

	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Key added to trust store.")
	fmt.Fprintf(w, "  %s %s\n", ui.Colorize("Key ID:", ui.Gray), newEntry.ID)
	fmt.Fprintf(w, "  %s %s\n", ui.Colorize("Actor:", ui.Gray), addActor)
	fmt.Fprintf(w, "  %s %s\n", ui.Colorize("Role:", ui.Gray), addRole)
	fmt.Fprintf(w, "  %s verified admin\n\n", ui.Colorize("Added by:", ui.Gray))
	fmt.Fprintf(w, "Commit and merge via PR:\n")
	fmt.Fprintf(w, "  git add %s\n", trustPath)
	fmt.Fprintf(w, "  git commit -m \"chore: trust add — %s (%s)\"\n", addActor, addRole)

	return nil
}

func runTrustRevoke(cmd *cobra.Command, args []string) error {
	if err := trust.RevokeKey(trustPath, keyringPath, revokeID, revokeReason); err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Key revoked.")
	fmt.Fprintf(w, "  %s %s\n", ui.Colorize("Key ID:", ui.Gray), revokeID)
	fmt.Fprintf(w, "  %s %s\n\n", ui.Colorize("Reason:", ui.Gray), revokeReason)
	fmt.Fprintf(w, "WARNING: Any sealed configs referencing this key will be rejected\n")
	fmt.Fprintf(w, "         by wardex evaluate until re-sealed.\n\n")
	fmt.Fprintf(w, "%s updated. Commit and merge via PR.\n", trustPath)

	return nil
}
