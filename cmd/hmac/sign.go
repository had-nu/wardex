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
	u := beginHMACUI(cmd, hmacFile)
	u.report(1, "Reading payload", "RUNNING", hmacFile)
	data, err := cli.SafeReadFile(hmacFile)
	if err != nil {
		u.report(1, "Reading payload", "FAILED", err.Error())
		return fmt.Errorf("reading file: %w", err)
	}
	u.report(1, "Reading payload", "DONE", fmt.Sprintf("%d bytes", len(data)))

	u.report(2, "Resolving HMAC secret", "RUNNING", hmacSecretEnv)
	secret := os.Getenv(hmacSecretEnv)
	if secret == "" {
		err := fmt.Errorf("environment variable %s is not set.\n\nHINT: Generate a key with:\n  openssl rand -base64 32\n\nThen export:\n  export %s=\"$(openssl rand -base64 32)\"", hmacSecretEnv, hmacSecretEnv)
		u.report(2, "Resolving HMAC secret", "FAILED", err.Error())
		return err
	}
	if len(secret) < 32 {
		err := fmt.Errorf("HMAC secret must be at least 32 characters (got %d)", len(secret))
		u.report(2, "Resolving HMAC secret", "FAILED", err.Error())
		return err
	}
	u.report(2, "Resolving HMAC secret", "DONE", "secret available")

	u.report(3, "Computing signature", "RUNNING", "")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))
	u.report(3, "Computing signature", "DONE", sig[:16]+"...")

	outPath := hmacOutput
	if outPath == "" {
		outPath = hmacFile + ".hmac"
	}
	u.report(4, "Writing signature", "RUNNING", outPath)
	safeOutPath, err := cli.SafeOutputPath(outPath)
	if err != nil {
		u.report(4, "Writing signature", "FAILED", err.Error())
		return fmt.Errorf("validating output path: %w", err)
	}
	sigData := []byte(fmt.Sprintf("HMAC-SHA256: %s\n", sig))
	if err := os.WriteFile(safeOutPath, sigData, 0600); err != nil { // #nosec G703 — safeOutPath validated by ValidateOutputPath
		u.report(4, "Writing signature", "FAILED", err.Error())
		return fmt.Errorf("writing signature: %w", err)
	}
	u.report(4, "Writing signature", "DONE", safeOutPath)
	u.report(5, "Finalizing signature result", "RUNNING", "")
	u.report(5, "Finalizing signature result", "DONE", "signature ready")
	if u.dashboardEnabled() {
		u.render(safeOutPath, len(data), sig[:16])
		return nil
	}

	fmt.Fprintf(u.output, "HMAC-SHA256 signature written to: %s\n", safeOutPath)
	fmt.Fprintln(u.output, "  Algorithm:  HMAC-SHA256")
	fmt.Fprintf(u.output, "  Payload:    %s (%d bytes)\n", hmacFile, len(data))
	fmt.Fprintf(u.output, "  Signature:  %s\n", sig[:16]+"...")
	return nil
}
