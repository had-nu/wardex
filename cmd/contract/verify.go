// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package contract

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/spf13/cobra"
)

var (
	contractFile string
	contractHash string
)

// VerifyCmd verifies a contract file's integrity.
var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify contract file integrity via SHA-256 hash",
	Long: `Compute the SHA-256 hash of a contract file and display its metadata.
Optionally verify against an expected hash value.

This is useful for ensuring that a contract has not been modified
since it was last reviewed or signed.`,
	RunE: runContractVerify,
}

func init() {
	VerifyCmd.Flags().StringVar(&contractFile, "file", "", "Path to contract file (required)")
	VerifyCmd.Flags().StringVar(&contractHash, "hash", "", "Expected SHA-256 hash (optional — if provided, verifies match)")
	_ = VerifyCmd.MarkFlagRequired("file")
}

func runContractVerify(cmd *cobra.Command, args []string) error {
	safePath, err := cli.SafePath(contractFile)
	if err != nil {
		return fmt.Errorf("validating contract path: %w", err)
	}

	data, err := os.ReadFile(safePath) // #nosec G304
	if err != nil {
		return fmt.Errorf("reading contract file: %w", err)
	}

	info, err := os.Stat(safePath)
	if err != nil {
		return fmt.Errorf("stat contract file: %w", err)
	}

	hash := sha256.Sum256(data)
	hashStr := fmt.Sprintf("sha256:%x", hash)

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Contract: %s\n", contractFile)
	fmt.Fprintf(w, "  SHA-256:         %s\n", hashStr)
	fmt.Fprintf(w, "  Size:            %d bytes\n", len(data))
	fmt.Fprintf(w, "  Last modified:   %s\n", info.ModTime().UTC().Format(time.RFC3339))

	if contractHash != "" {
		if hashStr == contractHash || fmt.Sprintf("%x", hash) == contractHash {
			fmt.Fprintf(w, "  Status:          VERIFIED\n")
		} else {
			fmt.Fprintf(w, "  Status:          %s (expected: %s)\n", "MISMATCH", contractHash)
			return fmt.Errorf("contract hash mismatch: got %s, expected %s", hashStr, contractHash)
		}
	} else {
		fmt.Fprintf(w, "  Status:          COMPUTED (no expected hash provided)\n")
	}

	return nil
}
