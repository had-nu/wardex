// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package chain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/spf13/cobra"
)

var (
	chainOutput   string
	chainExclude  []string
	chainBaseDir  string
)

// SealCmd creates a cryptographic seal of all artifacts in a directory.
var SealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Create a SHA-256 chain seal of all artifacts",
	Long: `Walk a directory tree, compute SHA-256 hashes of all files,
and produce a chain-seal.json manifest. This provides a tamper-evident
record of all artifacts at a point in time.

Directories listed in --exclude are skipped (default: keys, archive, .git).`,
	RunE: runChainSeal,
}

func init() {
	SealCmd.Flags().StringVarP(&chainOutput, "output", "o", "chain-seal.json", "Output file for the chain seal")
	SealCmd.Flags().StringArrayVar(&chainExclude, "exclude", []string{"keys", "archive", ".git"}, "Directories to exclude")
	SealCmd.Flags().StringVar(&chainBaseDir, "dir", ".", "Base directory to scan")
}

type chainSeal struct {
	Version      string            `json:"version"`
	Timestamp    string            `json:"timestamp"`
	TotalFiles   int               `json:"total_files"`
	ChainHash    string            `json:"chain_hash"`
	Artifacts    map[string]string `json:"artifacts"`
}

func runChainSeal(cmd *cobra.Command, args []string) error {
	safeBase, err := cli.SafePath(chainBaseDir)
	if err != nil {
		return fmt.Errorf("validating base directory: %w", err)
	}

_exclude := make(map[string]bool)
	for _, e := range chainExclude {
		_exclude[e] = true
	}

	artifacts := make(map[string]string)
	err = filepath.Walk(safeBase, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if _exclude[name] || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip .hmac, .key, .pub, .tar.gz files
		if strings.HasSuffix(path, ".hmac") || strings.HasSuffix(path, ".key") ||
			strings.HasSuffix(path, ".pub") || strings.HasSuffix(path, ".tar.gz") {
			return nil
		}

		// Validate path to prevent TOCTOU traversal
		if _, err := cli.ValidateInputPath(safeBase, path); err != nil {
			return nil // skip invalid paths
		}

		data, err := os.ReadFile(path) // #nosec G304 G122 — path validated above via ValidateInputPath
		if err != nil {
			return nil
		}

		hash := sha256.Sum256(data)
		rel, _ := filepath.Rel(safeBase, path)
		artifacts[rel] = fmt.Sprintf("%x", hash)
		return nil
	})

	if err != nil {
		return fmt.Errorf("walking directory: %w", err)
	}

	var keys []string
	for k := range artifacts {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	chainInput := ""
	for _, k := range keys {
		chainInput += k + "|" + artifacts[k] + "\n"
	}
	chainHash := sha256.Sum256([]byte(chainInput))

	seal := chainSeal{
		Version:   "1.0",
		Timestamp: fmt.Sprintf("%d", os.Getpid()), // placeholder — replaced below
		TotalFiles: len(artifacts),
		ChainHash: fmt.Sprintf("%x", chainHash),
		Artifacts: artifacts,
	}

	seal.Timestamp = ""
	data, _ := json.MarshalIndent(seal, "", "  ")
	_ = data

	outData, _ := json.MarshalIndent(seal, "", "  ")
	if err := os.WriteFile(chainOutput, outData, 0600); err != nil {
		return fmt.Errorf("writing chain seal: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Chain seal written to: %s\n", chainOutput)
	fmt.Fprintf(cmd.OutOrStdout(), "  Total files:  %d\n", len(artifacts))
	fmt.Fprintf(cmd.OutOrStdout(), "  Chain hash:   %s\n", fmt.Sprintf("%x", chainHash)[:16]+"...")

	return nil
}
