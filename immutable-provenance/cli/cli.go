// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/had-nu/immutable-provenance/ethanchor"
	"github.com/had-nu/immutable-provenance/manifest"
	"github.com/had-nu/immutable-provenance/ots"
	"github.com/spf13/cobra"
)

var (
	manifestPath string
	otsPath      string
	dirPath      string
	outputPath   string
	excludeList  []string
	includeList  []string
	keyPath      string
	keyID        string
	trustPath    string

	manVersion   string
	manCommit    string
	manBranch    string
	authorName   string
	authorEmail  string
	authorGithub string
	authorPubkey string

	rpcURL       string
	contractAddr string
	ethKey       string
)

// RootCmd represents the base command.
var RootCmd = &cobra.Command{
	Use:   "immutable-provenance",
	Short: "Cryptographic, ledger-anchored source code provenance tool",
	Long: `immutable-provenance creates cryptographic seals of source trees
and anchors them into Bitcoin (via OpenTimestamps) and Ethereum/Polygon.`,
}

// SealCmd generates and signs a manifest.
var SealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Generate and sign a source provenance manifest",
	RunE: func(cmd *cobra.Command, args []string) error {
		if manCommit == "" {
			manCommit = "unknown"
		}
		if manBranch == "" {
			manBranch = "main"
		}

		author := manifest.AuthorIdentity{
			Name:   authorName,
			Email:  authorEmail,
			PubKey: authorPubkey,
			GitHub: authorGithub,
		}

		var privKey ed25519.PrivateKey
		if keyPath != "" {
			var err error
			privKey, err = loadEd25519PrivateKey(keyPath)
			if err != nil {
				return fmt.Errorf("loading private key: %w", err)
			}
			if author.PubKey == "" {
				pubBytes := privKey.Public().(ed25519.PublicKey)
				author.PubKey = "ed25519:" + base64.StdEncoding.EncodeToString(pubBytes)
			}
		}

		license := manifest.LicenseDecl{
			SPDX:            "AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial",
			CopyrightNotice: fmt.Sprintf("Copyright (c) %d %s", time.Now().Year(), authorName),
		}

		notice := fmt.Sprintf(`This source code is the original work of %s (GitHub: %s, Email: %s).
It is distributed under the AGPL-3.0-or-later license with a dual commercial licensing option.
Any reproduction or fork that removes this notice violates the license terms.`, authorName, authorGithub, authorEmail)

		m, err := manifest.GenerateManifest(dirPath, includeList, excludeList, manVersion, manCommit, manBranch, author, license, notice)
		if err != nil {
			return err
		}

		if len(privKey) > 0 {
			if keyID == "" {
				keyID = "author-key-01"
			}
			if err := m.Sign(privKey, keyID); err != nil {
				return fmt.Errorf("signing manifest: %w", err)
			}
		}

		if err := manifest.SaveManifest(outputPath, m); err != nil {
			return err
		}

		fmt.Printf("Provenance manifest successfully generated and written to: %s\n", outputPath)
		fmt.Printf("  Total files: %d\n", m.TotalFiles)
		fmt.Printf("  Root hash:   %s\n", m.RootHash)
		if m.Sig != "" {
			fmt.Printf("  Signature:   %s (VALID)\n", m.Sig[:20]+"...")
		} else {
			fmt.Println("  Warning: manifest is UNSIGNED. Provide --keyring to sign.")
		}

		return nil
	},
}

// VerifyCmd verifies the manifest.
var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a manifest signature and file integrity",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := manifest.LoadManifest(manifestPath)
		if err != nil {
			return err
		}

		fmt.Printf("Verifying provenance for version: %s\n", m.ManifestVersion)
		if err := m.Verify(dirPath); err != nil {
			fmt.Printf("Source provenance: TAMPERED\n")
			return err
		}

		fmt.Printf("Source provenance: VERIFIED\n")
		fmt.Printf("  Author:     %s (%s)\n", m.Author.Name, m.Author.GitHub)
		fmt.Printf("  License:    %s\n", m.License.SPDX)
		fmt.Printf("  Signed at:  %s\n", m.GeneratedAt.Format(time.RFC3339))
		fmt.Printf("  Git commit: %s\n", m.GitCommit)
		fmt.Printf("  Files:      %d verified (root hash matches)\n", m.TotalFiles)
		return nil
	},
}

// OTS commands
var OtsCmd = &cobra.Command{
	Use:   "ots",
	Short: "OpenTimestamps integration commands",
}

var OtsStampCmd = &cobra.Command{
	Use:   "stamp",
	Short: "Anchor the manifest to Bitcoin via OpenTimestamps",
	RunE: func(cmd *cobra.Command, args []string) error {
		if otsPath == "" {
			otsPath = manifestPath + ".ots"
		}
		fmt.Printf("Submitting manifest %s to OpenTimestamps calendars...\n", manifestPath)
		err := ots.Stamp(manifestPath, otsPath)
		if err != nil {
			return err
		}
		fmt.Printf("OpenTimestamps receipt written to: %s\n", otsPath)
		return nil
	},
}

var OtsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an OpenTimestamps receipt for the manifest",
	RunE: func(cmd *cobra.Command, args []string) error {
		if otsPath == "" {
			otsPath = manifestPath + ".ots"
		}
		t, err := ots.Verify(manifestPath, otsPath)
		if err != nil {
			fmt.Printf("OpenTimestamps Verification: FAILED\n")
			return err
		}
		fmt.Printf("OpenTimestamps Verification: SUCCESS\n")
		fmt.Printf("  Timestamp: %s\n", t.Format(time.RFC3339))
		return nil
	},
}

// EVM commands
var EthCmd = &cobra.Command{
	Use:   "eth",
	Short: "Ethereum/Polygon smart contract anchoring operations",
}

var EthAnchorCmd = &cobra.Command{
	Use:   "anchor",
	Short: "Anchor manifest root hash in the ProvenanceAnchor smart contract",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ethKey == "" {
			return fmt.Errorf("ethereum private key is required (--eth-key)")
		}
		if contractAddr == "" {
			return fmt.Errorf("contract address is required (--contract)")
		}

		m, err := manifest.LoadManifest(manifestPath)
		if err != nil {
			return err
		}

		client, err := ethanchor.NewClient(rpcURL, contractAddr)
		if err != nil {
			return err
		}

		fmt.Printf("Submitting root hash %s to ProvenanceAnchor at %s...\n", m.RootHash, contractAddr)
		txHash, err := client.Anchor(cmd.Context(), ethKey, m.RootHash)
		if err != nil {
			return err
		}

		fmt.Printf("Transaction submitted successfully!\n")
		fmt.Printf("  Tx Hash: %s\n", txHash)
		return nil
	},
}

var EthVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify manifest root hash on Ethereum/Polygon contract",
	RunE: func(cmd *cobra.Command, args []string) error {
		if contractAddr == "" {
			return fmt.Errorf("contract address is required (--contract)")
		}

		m, err := manifest.LoadManifest(manifestPath)
		if err != nil {
			return err
		}

		client, err := ethanchor.NewClient(rpcURL, contractAddr)
		if err != nil {
			return err
		}

		anchorTime, anchored, err := client.Verify(cmd.Context(), m.RootHash)
		if err != nil {
			return err
		}

		if !anchored {
			fmt.Printf("Ethereum/Polygon Verification: NOT ANCHORED\n")
			return fmt.Errorf("root hash has not been anchored in this contract")
		}

		fmt.Printf("Ethereum/Polygon Verification: ANCHORED\n")
		fmt.Printf("  Anchor Time: %s\n", anchorTime.Format(time.RFC3339))
		fmt.Printf("  Contract:    %s\n", contractAddr)
		return nil
	},
}

func init() {
	SealCmd.Flags().StringVar(&keyPath, "keyring", "", "Path to raw/base64 Ed25519 private key")
	SealCmd.Flags().StringVar(&keyID, "key-id", "author-key-01", "Key ID associated with the signer")
	SealCmd.Flags().StringVar(&dirPath, "dir", ".", "Source tree root directory")
	SealCmd.Flags().StringVar(&outputPath, "output", "provenance.yaml", "Path to save generated manifest")
	SealCmd.Flags().StringSliceVar(&includeList, "include", []string{"*.go", "LICENSE", "go.mod", "go.sum"}, "File glob patterns to seal")
	SealCmd.Flags().StringSliceVar(&excludeList, "exclude", []string{".git", "vendor", "testdata"}, "Subdirectories to skip")
	SealCmd.Flags().StringVar(&manVersion, "version", "v2.2.0", "Manifest release version")
	SealCmd.Flags().StringVar(&manCommit, "commit", "", "Git commit SHA")
	SealCmd.Flags().StringVar(&manBranch, "branch", "main", "Git branch name")
	SealCmd.Flags().StringVar(&authorName, "author-name", "André Gustavo Leão de Melo Ataíde", "Author full name")
	SealCmd.Flags().StringVar(&authorEmail, "author-email", "andre.ataide@proton.me", "Author contact email")
	SealCmd.Flags().StringVar(&authorGithub, "author-github", "had-nu", "Author GitHub username")
	SealCmd.Flags().StringVar(&authorPubkey, "author-pubkey", "", "Author public key base64 (computed from keyring if omitted)")

	VerifyCmd.Flags().StringVar(&manifestPath, "manifest", "provenance.yaml", "Path to manifest file")
	VerifyCmd.Flags().StringVar(&dirPath, "dir", ".", "Source tree root directory")

	OtsCmd.PersistentFlags().StringVar(&manifestPath, "manifest", "provenance.yaml", "Path to manifest file")
	OtsCmd.PersistentFlags().StringVar(&otsPath, "ots", "", "Path to save/load .ots file (defaults to manifest.ots)")
	OtsCmd.AddCommand(OtsStampCmd, OtsVerifyCmd)

	EthCmd.PersistentFlags().StringVar(&manifestPath, "manifest", "provenance.yaml", "Path to manifest file")
	EthCmd.PersistentFlags().StringVar(&rpcURL, "rpc", "https://polygon-rpc.com", "Ethereum/Polygon RPC endpoint")
	EthCmd.PersistentFlags().StringVar(&contractAddr, "contract", "", "ProvenanceAnchor smart contract address")
	EthAnchorCmd.Flags().StringVar(&ethKey, "eth-key", "", "Ethereum ECDSA private key hex")
	EthCmd.AddCommand(EthAnchorCmd, EthVerifyCmd)

	RootCmd.AddCommand(SealCmd, VerifyCmd, OtsCmd, EthCmd)
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	strData := strings.TrimSpace(string(data))
	decoded, err := base64.StdEncoding.DecodeString(strData)
	if err == nil && len(decoded) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(decoded), nil
	}

	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(data), nil
	}

	return nil, fmt.Errorf("invalid key file format: must be base64-encoded or raw 64 bytes")
}
