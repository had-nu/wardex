// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/spf13/cobra"
)

var (
	sealDir     string
	sealOutput  string
	sealExclude []string
	sealLabel   string
)

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Hash a directory tree and anchor the chain hash",
	Long: `Walk a directory, compute SHA-256 hashes of all files, produce a
chain-seal manifest, then submit the root hash to the provenance anchor.`,
	RunE: runSeal,
}

type chainSeal struct {
	Version    string            `json:"version"`
	Timestamp  string            `json:"timestamp"`
	TotalFiles int               `json:"total_files"`
	ChainHash  string            `json:"chain_hash"`
	Artifacts  map[string]string `json:"artifacts"`
}

func runSeal(cmd *cobra.Command, args []string) error {
	safeBase, err := cli.SafePath(sealDir)
	if err != nil {
		return fmt.Errorf("validating base directory: %w", err)
	}

	exclude := make(map[string]bool)
	for _, e := range sealExclude {
		exclude[e] = true
	}

	artifacts := make(map[string]string)
	err = filepath.Walk(safeBase, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if exclude[info.Name()] || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if _, err := cli.ValidateInputPath(safeBase, path); err != nil {
			return nil
		}

		//nolint:gosec // path validated by cli.ValidateInputPath above
		data, err := os.ReadFile(path)
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
	sort.Strings(keys)

	chainInput := ""
	for _, k := range keys {
		chainInput += k + "|" + artifacts[k] + "\n"
	}
	chainHash := sha256.Sum256([]byte(chainInput))
	chainHashHex := fmt.Sprintf("%x", chainHash)

	seal := chainSeal{
		Version:    "1.0",
		Timestamp:  fmt.Sprintf("%d", os.Getpid()),
		TotalFiles: len(artifacts),
		ChainHash:  chainHashHex,
		Artifacts:  artifacts,
	}

	outData, _ := json.MarshalIndent(seal, "", "  ")
	if err := os.WriteFile(sealOutput, outData, 0600); err != nil {
		return fmt.Errorf("writing chain seal: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Chain seal written to: %s\n", sealOutput)
	fmt.Fprintf(cmd.OutOrStdout(), "  Total files:  %d\n", len(artifacts))
	fmt.Fprintf(cmd.OutOrStdout(), "  Chain hash:   %s\n", chainHashHex[:16]+"...")

	anchorer, err := getAnchorer()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: provenance anchor unavailable: %v\n", err)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Seal saved locally; submit with: wardex provenance submit %s\n", chainHashHex)
		return nil
	}
	defer func() { _ = anchorer.Close() }()

	hashBytes, _ := hex.DecodeString(chainHashHex)
	result, err := anchorer.Submit(cmd.Context(), hashBytes, sealLabel)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: anchor submission failed: %v\n", err)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Seal saved locally at %s\n", sealOutput)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "  Anchored:     %s (block ~%d)\n", result.Label, result.BlockIndex)
	return nil
}

func init() {
	sealCmd.Flags().StringVar(&sealDir, "dir", ".", "Base directory to scan")
	sealCmd.Flags().StringVarP(&sealOutput, "output", "o", "chain-seal.json", "Output file for the chain seal")
	sealCmd.Flags().StringArrayVar(&sealExclude, "exclude", []string{"keys", "archive", ".git"}, "Directories to exclude")
	sealCmd.Flags().StringVar(&sealLabel, "label", "", "Artifact label for anchoring")
	_ = sealCmd.MarkFlagRequired("label")
}
