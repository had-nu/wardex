// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package convert

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/pkg/attest"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type GrypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			CVSS     []struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
		} `json:"vulnerability"`
		Artifact struct {
			Name string `json:"name"`
		} `json:"artifact"`
	} `json:"matches"`
}

var grypeOutFile string
var defaultEpss float64
var kevCataloguePath string
var attestKeyPath string

var GrypeCmd = &cobra.Command{
	Use:   "grype <input.json>",
	Short: "Convert Grype JSON output to Wardex Vulnerabilities YAML",
	Args:  cobra.MinimumNArgs(1),
	Run:   runConvertGrype,
}

func init() {
	GrypeCmd.Flags().StringVarP(&grypeOutFile, "output", "o", "wardex-vulns.yaml", "Output file for Wardex YAML")
	GrypeCmd.Flags().Float64Var(&defaultEpss, "default-epss", 0.0, "Default EPSS score (0.0 = unknown, gate assumes worst-case 1.0). Use 'wardex enrich epss' to fetch real scores.")
	GrypeCmd.Flags().StringVar(&kevCataloguePath, "kev", "", "Path to a downloaded CISA KEV catalogue JSON snapshot. Download with:\n  curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev-catalogue.json")
	GrypeCmd.Flags().StringVar(&attestKeyPath, "attest", "", "Path to Ed25519 private key for 3CP tool attestation signing")
}

func runConvertGrype(cmd *cobra.Command, args []string) {
	inFile := args[0]

	safePathStr, err := cli.SafePath(inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving safe path for input file: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(safePathStr) // #nosec G304
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening Grype JSON file: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading Grype JSON: %v\n", err)
		os.Exit(1)
	}

	var report GrypeReport
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing Grype JSON: %v\n", err)
		os.Exit(1)
	}

	out := model.VulnerabilityEnvelope{
		ConvertedBy:     "wardex-convert/grype",
		Vulnerabilities: make([]model.Vulnerability, 0, len(report.Matches)),
	}

	seen := make(map[string]bool)
	var skippedEmpty, skippedDuplicate int

	for _, match := range report.Matches {
		vulnID := match.Vulnerability.ID
		comp := match.Artifact.Name
		key := vulnID + "|" + comp

		if vulnID == "" {
			skippedEmpty++
			continue
		}
		if seen[key] {
			skippedDuplicate++
			continue
		}
		seen[key] = true

		var bestScore float64
		for _, cvss := range match.Vulnerability.CVSS {
			if cvss.Metrics.BaseScore > bestScore {
				bestScore = cvss.Metrics.BaseScore
			}
		}

		if bestScore == 0 {
			switch match.Vulnerability.Severity {
			case "Critical":
				bestScore = 9.5
			case "High":
				bestScore = 7.5
			case "Medium":
				bestScore = 5.5
			case "Low":
				bestScore = 3.0
			default:
				bestScore = 0.0
			}
		}

		out.Vulnerabilities = append(out.Vulnerabilities, model.Vulnerability{
			CVEID:     vulnID,
			CVSSBase:  bestScore,
			EPSSScore: defaultEpss,
			Component: comp,
			Reachable: true,
		})
	}

	// KEV correlation — enrich with active exploitation data if catalogue provided
	if kevCataloguePath != "" {
		// Check catalogue staleness
		if warn := CheckKEVAge(kevCataloguePath, KEVMaxAgeDays); warn != "" {
			fmt.Fprintln(os.Stderr, warn)
		}

		catalogue, err := LoadKEVCatalogue(kevCataloguePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Failed to load KEV catalogue: %v. Proceeding without KEV correlation.\n", err)
		} else {
			out.Vulnerabilities = CorrelateKEV(out.Vulnerabilities, catalogue)
			var exploited int
			for _, v := range out.Vulnerabilities {
				if v.ActivelyExploited {
					exploited++
				}
			}
			if exploited > 0 {
				fmt.Fprintf(os.Stderr, "[WARN] %d CVE(s) found in CISA KEV catalogue and marked actively_exploited=true.\n", exploited)
			}
		}
	} else {
		fmt.Fprintf(os.Stderr,
			"[INFO] No KEV catalogue provided. To correlate against CISA Known Exploited Vulnerabilities, download it with:\n"+
				"       curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev-catalogue.json\n"+
				"       Then re-run with: wardex convert grype %s --kev kev-catalogue.json\n", inFile)
	}

	if skippedEmpty > 0 || skippedDuplicate > 0 {
		fmt.Fprintf(os.Stderr, "[INFO] Skipped %d CVEs (empty ID: %d, duplicate: %d)\n", skippedEmpty+skippedDuplicate, skippedEmpty, skippedDuplicate)
	}

	outputPath := grypeOutFile
	yamlData, err := yaml.Marshal(&out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding YAML: %v\n", err)
		os.Exit(1)
	}

	if outputPath == "stdout" || outputPath == "-" {
		fmt.Print(string(yamlData))
	} else {
		if err := os.WriteFile(outputPath, yamlData, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully converted %d vulnerabilities to %s\n", len(out.Vulnerabilities), outputPath)
	}

	if attestKeyPath != "" && outputPath != "stdout" && outputPath != "-" {
		if err := attestOutput("wardex-convert/grype", inFile, outputPath, attestKeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Attestation failed: %v\n", err)
		}
	}
}

func attestOutput(toolName, inputFile, outputFile, keyPath string) error {
	inHash, err := attest.FileHash(inputFile)
	if err != nil {
		return fmt.Errorf("hash input: %w", err)
	}

	outHash, err := attest.FileHash(outputFile)
	if err != nil {
		return fmt.Errorf("hash output: %w", err)
	}

	a := attest.New(toolName, "2.3.0").
		SetInputHash(inHash).
		SetOutputHash(outHash).
		SetConvertedBy(toolName)

	signer := func(msg []byte) ([]byte, error) {
		sig, _, err := attest.SignWithEd25519(keyPath, msg)
		return sig, err
	}

	_, keyID, err := attest.SignWithEd25519(keyPath, []byte("probe"))
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	signed, err := a.Sign(signer, keyID)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	attestPath := outputFile + ".attest"
	out, err := yaml.Marshal(signed)
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}
	if err := os.WriteFile(attestPath, out, 0600); err != nil {
		return fmt.Errorf("write attestation: %w", err)
	}

	cfgHash, err := cpl.ComputeConfigHash(outHash, cpl.AlgoSHA256)
	if err == nil {
		a.SetConfigHash(cfgHash)
	}

	fmt.Fprintf(os.Stderr, "[PROVENANCE] Signed attestation written to %s\n", attestPath)
	return nil
}
