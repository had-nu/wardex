// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package gatecmd

import (
	"fmt"
	"os"

	acceptaudit "github.com/had-nu/wardex/v2/pkg/accept/audit"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/versionregistry"
	"github.com/spf13/cobra"
)

var CheckVersionCmd = &cobra.Command{
	Use:   "check-version",
	Short: "Fail with exit 13 if a release version was already sealed",
	Long: `Verify that a release version has not been sealed in the audit chain.
Fails with exit code 13 (DuplicateRelease) if the version is already present,
so release jobs never seal the same version twice.

The version registry (<audit-log>.version-registry.json) is a derived index:
if it is missing, stale or corrupt it is rebuilt from the chain, which is the
source of truth. A missing index never blocks — only chain evidence decides.

Examples:
  wardex gate check-version --audit-log wardex-gate-audit.log --version 2.6.0

Exit codes:
   0 — version not sealed yet
  13 — version already sealed (DuplicateRelease)
   1 — operational error`,
	Args: cobra.NoArgs,
	RunE: runCheckVersion,
}

var (
	checkVersionAuditLog string
	checkVersionVersion  string
	exitFunc             = os.Exit
)

func init() {
	CheckVersionCmd.Flags().StringVar(&checkVersionAuditLog, "audit-log", "", "Path to the wardex gate audit log JSONL file (required)")
	CheckVersionCmd.Flags().StringVar(&checkVersionVersion, "version", "", "Release version to check (required)")
	_ = CheckVersionCmd.MarkFlagRequired("audit-log")
	_ = CheckVersionCmd.MarkFlagRequired("version")
}

func runCheckVersion(cmd *cobra.Command, _ []string) error {
	if _, err := os.Stat(checkVersionAuditLog); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: audit log: %v\n", err)
		exitFunc(exitcodes.GenericError)
		return nil
	}

	reg, err := versionregistry.Load(checkVersionAuditLog)
	fresh := err == nil && reg.LastHash != ""
	if fresh {
		lastHash, herr := acceptaudit.LastEntryHash(checkVersionAuditLog)
		fresh = herr == nil && lastHash == reg.LastHash
	}
	if !fresh {
		reg = versionregistry.New()
		if _, rerr := reg.Rebuild(checkVersionAuditLog); rerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: rebuild version registry from chain: %v\n", rerr)
			exitFunc(exitcodes.GenericError)
			return nil
		}
		if serr := reg.Save(checkVersionAuditLog); serr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: cannot refresh version registry: %v\n", serr)
		}
	}

	if info, ok := reg.Releases[checkVersionVersion]; ok {
		fmt.Fprintf(cmd.OutOrStdout(), "[DUPLICATE RELEASE] version %s was already sealed\n", checkVersionVersion)
		fmt.Fprintf(cmd.OutOrStdout(), "  policy_ref: %s\n  sealed_at:  %s\n  entry_hash: %s\n",
			info.PolicyRef, info.SealedAt.UTC().Format("2006-01-02T15:04:05Z"), info.EntryHash)
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: release version %s already sealed — refusing duplicate release\n", checkVersionVersion)
		exitFunc(exitcodes.DuplicateRelease)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "OK: version %s has not been sealed yet\n", checkVersionVersion)
	return nil
}
