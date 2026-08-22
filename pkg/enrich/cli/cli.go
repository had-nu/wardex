// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/accept"
	pathguard "github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/epss"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	outputFile    string
	configPathPtr *string

	// Allow mocking in tests
	exitFunc = os.Exit
)

var enrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Fetch and sign missing data for Wardex analysis",
}

var epssCmd = &cobra.Command{
	Use:   "epss <vulns.yaml>",
	Short: "Fetch missing EPSS scores from api.first.org and sign the enrichment file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inFile := args[0]

		cfg, err := config.Load(*configPathPtr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config from %s: %v\n", *configPathPtr, err)
			exitFunc(1)
		}

		key, err := accept.ResolveSecret(*cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n[FAIL] Missing or invalid WARDEX_SECRET. Enrichment non-repudiation requires a valid signature key.\n%v\n", err)
			exitFunc(1)
		}

		safePathStr, err := pathguard.SafePath(inFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid input file path: %v\n", err)
			exitFunc(1)
		}
		vdata, err := os.ReadFile(safePathStr) // #nosec G304
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read vulnerability file: %v\n", err)
			exitFunc(1)
		}

		var vulnsFormat struct {
			Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
		}
		if err := yaml.Unmarshal(vdata, &vulnsFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse vulnerabilities: %v\n", err)
			exitFunc(1)
		}

		var cvesToFetch []string
		for _, v := range vulnsFormat.Vulnerabilities {
			if v.EPSSScore == 0.0 { // missing - 0.0 means not fetched
				cvesToFetch = append(cvesToFetch, v.CVEID)
			}
		}

		if len(cvesToFetch) == 0 {
			fmt.Println("[INFO] No missing EPSS scores found in the input file.")
			exitFunc(0)
		}

		fmt.Printf("[INFO] Fetching EPSS scores for %d vulnerabilities from api.first.org...\n", len(cvesToFetch))

		scores, provenance, err := epss.FetchScores(cvesToFetch, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[FAIL] First.org API query failed: %v\n", err)
			exitFunc(1)
		}

		fmt.Printf("[INFO] Received %d scores. Signing enrichment record...\n", len(scores))

		var enrichments []model.EPSSEnrichment
		for cve, score := range scores {
			enrichments = append(enrichments, model.EPSSEnrichment{
				CVE:   cve,
				Score: score,
			})
		}

		outFormat := model.EPSSEnrichmentFile{
			Enrichments: enrichments,
			Provenance:  provenance,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}

		sig, err := epss.Sign(outFormat, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to sign EPSS payload: %v\n", err)
			exitFunc(1)
		}
		outFormat.Signature = sig

		outData, err := yaml.Marshal(&outFormat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate yaml: %v\n", err)
			exitFunc(1)
		}

		if err := os.WriteFile(outputFile, outData, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", outputFile, err)
			exitFunc(1)
		}

		fmt.Printf("[PASS] Cryptographically signed enrichment written to %s.\n", outputFile)
	},
}

// AddCommands registers the enrich commands onto the root cobra.Command
func AddCommands(root *cobra.Command, cfgPtr *string) {
	configPathPtr = cfgPtr
	epssCmd.Flags().StringVarP(&outputFile, "output", "o", "wardex-epss-enrichment.yaml", "Path to save the signed EPSS overrides")
	enrichCmd.AddCommand(epssCmd)
	root.AddCommand(enrichCmd)
}
