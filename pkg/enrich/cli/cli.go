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
	"github.com/had-nu/wardex/v2/pkg/ui"
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
		u := beginEnrichUI(cmd, inFile, outputFile)
		u.report(1, "Loading configuration", "RUNNING", *configPathPtr)
		cfg, err := config.Load(*configPathPtr)
		if err != nil {
			u.report(1, "Loading configuration", "FAILED", err.Error())
			ui.Errorf("Error loading config from %s: %v", *configPathPtr, err)
			exitFunc(1)
		}
		u.report(1, "Loading configuration", "DONE", "configuration loaded")

		u.report(2, "Resolving signing secret", "RUNNING", "")
		key, err := accept.ResolveSecret(*cfg)
		if err != nil {
			u.report(2, "Resolving signing secret", "FAILED", err.Error())
			ui.Errorf("Missing or invalid WARDEX_SECRET. Enrichment non-repudiation requires a valid signature key.\n%v", err)
			exitFunc(1)
		}
		u.report(2, "Resolving signing secret", "DONE", "secret available")

		u.report(3, "Reading vulnerability file", "RUNNING", inFile)
		vdata, err := pathguard.SafeReadFile(inFile)
		if err != nil {
			u.report(3, "Reading vulnerability file", "FAILED", err.Error())
			ui.Errorf("Failed to read vulnerability file: %v", err)
			exitFunc(1)
		}
		var vulnsFormat struct {
			Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
		}
		if err := yaml.Unmarshal(vdata, &vulnsFormat); err != nil {
			u.report(3, "Reading vulnerability file", "FAILED", err.Error())
			ui.Errorf("Failed to parse vulnerabilities: %v", err)
			exitFunc(1)
		}
		u.report(3, "Reading vulnerability file", "DONE", fmt.Sprintf("%d records", len(vulnsFormat.Vulnerabilities)))

		var cvesToFetch []string
		for _, v := range vulnsFormat.Vulnerabilities {
			if v.EPSSScore == 0.0 { // missing - 0.0 means not fetched
				cvesToFetch = append(cvesToFetch, v.CVEID)
			}
		}
		if len(cvesToFetch) == 0 {
			u.report(4, "Checking EPSS coverage", "DONE", "no missing scores")
			if u.progress.Enabled() {
				u.render(0)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "[INFO] No missing EPSS scores found in the input file.")
			}
			exitFunc(0)
		}

		u.report(4, "Fetching EPSS scores", "RUNNING", fmt.Sprintf("%d CVE(s)", len(cvesToFetch)))
		scores, provenance, err := epss.FetchScores(cmd.Context(), cvesToFetch)
		if err != nil {
			u.report(4, "Fetching EPSS scores", "FAILED", err.Error())
			ui.Errorf("First.org API query failed: %v", err)
			exitFunc(1)
		}
		u.report(4, "Fetching EPSS scores", "DONE", fmt.Sprintf("%d score(s)", len(scores)))

		u.report(5, "Signing enrichment record", "RUNNING", "")
		var enrichments []model.EPSSEnrichment
		for cve, score := range scores {
			enrichments = append(enrichments, model.EPSSEnrichment{CVE: cve, Score: score})
		}
		outFormat := model.EPSSEnrichmentFile{
			Enrichments: enrichments,
			Provenance:  provenance,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}
		sig, err := epss.Sign(outFormat, key)
		if err != nil {
			u.report(5, "Signing enrichment record", "FAILED", err.Error())
			ui.Errorf("Failed to sign EPSS payload: %v", err)
			exitFunc(1)
		}
		outFormat.Signature = sig
		u.report(5, "Signing enrichment record", "DONE", "signature ready")

		u.report(6, "Writing enrichment file", "RUNNING", outputFile)
		outData, err := yaml.Marshal(&outFormat)
		if err != nil {
			u.report(6, "Writing enrichment file", "FAILED", err.Error())
			ui.Errorf("Failed to generate yaml: %v", err)
			exitFunc(1)
		}
		if err := os.WriteFile(outputFile, outData, 0600); err != nil {
			u.report(6, "Writing enrichment file", "FAILED", err.Error())
			ui.Errorf("Failed to write %s: %v", outputFile, err)
			exitFunc(1)
		}
		u.report(6, "Writing enrichment file", "DONE", outputFile)
		if u.progress.Enabled() {
			u.render(len(scores))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "[PASS] Cryptographically signed enrichment written to %s.\n", outputFile)
		}
	},
}

// AddCommands registers the enrich commands onto the root cobra.Command
func AddCommands(root *cobra.Command, cfgPtr *string) {
	configPathPtr = cfgPtr
	epssCmd.Flags().StringVarP(&outputFile, "output", "o", "wardex-epss-enrichment.yaml", "Path to save the signed EPSS overrides")
	enrichCmd.AddCommand(epssCmd)
	root.AddCommand(enrichCmd)
}
