// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/spf13/cobra"
)

var (
	hmacFile      string
	hmacSecretEnv string
	hmacOutput    string
)

// SignCmd computes an HMAC-SHA256 signature for a file.
var SignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Compute HMAC-SHA256 signature for a file",
	Long: `Compute an HMAC-SHA256 signature for a file using a secret key
from an environment variable. The signature is written to a .hmac file.

The secret must be at least 32 characters. If not set, the command
will fail with a clear error message.`,
	RunE: runHMACSign,
}

func init() {
	SignCmd.Flags().StringVar(&hmacFile, "file", "", "Path to file to sign (required)")
	SignCmd.Flags().StringVar(&hmacSecretEnv, "secret-env", "WARDEX_ACCEPT_SECRET", "Environment variable containing the HMAC secret")
	SignCmd.Flags().StringVar(&hmacOutput, "output", "", "Output file path (default: <file>.hmac)")
	_ = SignCmd.MarkFlagRequired("file")
}

func runHMACSign(cmd *cobra.Command, args []string) error {
	safePath, err := cli.SafePath(hmacFile)
	if err != nil {
		return fmt.Errorf("validating file path: %w", err)
	}

	data, err := os.ReadFile(safePath) // #nosec G304
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	secret := os.Getenv(hmacSecretEnv)
	if secret == "" {
		return fmt.Errorf("environment variable %s is not set.\n\nHINT: Generate a key with:\n  openssl rand -base64 32\n\nThen export:\n  export %s=\"$(openssl rand -base64 32)\"", hmacSecretEnv, hmacSecretEnv)
	}

	if len(secret) < 32 {
		return fmt.Errorf("HMAC secret must be at least 32 characters (got %d)", len(secret))
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))

	outPath := hmacOutput
	if outPath == "" {
		outPath = hmacFile + ".hmac"
	}

	safeOutPath, err := cli.SafeOutputPath(outPath)
	if err != nil {
		return fmt.Errorf("validating output path: %w", err)
	}

	sigData := []byte(fmt.Sprintf("HMAC-SHA256: %s\n", sig))
	if err := os.WriteFile(safeOutPath, sigData, 0600); err != nil { // #nosec G703 — safeOutPath validated by ValidateOutputPath
		return fmt.Errorf("writing signature: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "HMAC-SHA256 signature written to: %s\n", safeOutPath)
	fmt.Fprintf(cmd.OutOrStdout(), "  Algorithm:  HMAC-SHA256\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Payload:    %s (%d bytes)\n", hmacFile, len(data))
	fmt.Fprintf(cmd.OutOrStdout(), "  Signature:  %s\n", sig[:16]+"...")

	return nil
}
