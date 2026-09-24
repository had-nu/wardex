// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package convert

import (
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/pkg/attest"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var kevOutFile string
var kevAttestKey string

// KevCmd converts a CISA KEV catalogue JSON to Wardex YAML format.
var KevCmd = &cobra.Command{
	Use:   "kev <kev-catalogue.json>",
	Short: "Convert a CISA KEV catalogue JSON to Wardex YAML format",
	Long: `Load a CISA Known Exploited Vulnerabilities (KEV) catalogue and
convert it to a Wardex-compatible YAML file for correlation with
vulnerability evidence.
	
Download the catalogue with:
  curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev-catalogue.json`,
	Args: cobra.ExactArgs(1),
	RunE: runConvertKEV,
}

func init() {
	KevCmd.Flags().StringVarP(&kevOutFile, "output", "o", "wardex-kev.yaml", "Output file for Wardex YAML")
	KevCmd.Flags().StringVar(&kevAttestKey, "attest", "", "Path to Ed25519 private key for 3CP tool attestation signing")
}

func runConvertKEV(cmd *cobra.Command, args []string) error {
	inFile := args[0]
	u := beginConvertUI(cmd, "kev", inFile, kevOutFile)
	u.report(1, "Resolving KEV catalogue", "RUNNING", inFile)
	safePath, err := cli.SafePath(inFile)
	if err != nil {
		u.report(1, "Resolving KEV catalogue", "FAILED", err.Error())
		return fmt.Errorf("validating input path: %w", err)
	}
	u.report(1, "Resolving KEV catalogue", "DONE", safePath)

	if warn := CheckKEVAge(safePath, KEVMaxAgeDays); warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}

	u.report(2, "Loading KEV catalogue", "RUNNING", safePath)
	catalogue, err := LoadKEVCatalogue(safePath)
	if err != nil {
		u.report(2, "Loading KEV catalogue", "FAILED", err.Error())
		return fmt.Errorf("loading KEV catalogue: %w", err)
	}
	u.report(2, "Loading KEV catalogue", "DONE", fmt.Sprintf("%d entries", catalogue.Count))

	type kevYAML struct {
		ConvertedBy     string                `yaml:"converted_by"`
		CatalogVersion  string                `yaml:"catalog_version"`
		DateReleased    string                `yaml:"date_released"`
		Count           int                   `yaml:"count"`
		Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
	}

	out := kevYAML{
		ConvertedBy:     "wardex-convert/kev",
		CatalogVersion:  catalogue.CatalogVersion,
		DateReleased:    catalogue.DateReleased,
		Count:           catalogue.Count,
		Vulnerabilities: make([]model.Vulnerability, 0, len(catalogue.Vulnerabilities)),
	}

	for _, entry := range catalogue.Vulnerabilities {
		v := model.Vulnerability{
			CVEID:             entry.CveID,
			Component:         entry.Product,
			ActivelyExploited: true,
			ExploitedSource:   "cisa-kev",
		}

		if t, err := time.Parse("2006-01-02", entry.DateAdded); err == nil {
			v.ActivelyExploitedSince = t.UTC()
		}

		out.Vulnerabilities = append(out.Vulnerabilities, v)
	}

	u.report(3, "Writing converted output", "RUNNING", kevOutFile)
	yamlData, err := yaml.Marshal(&out)
	if err != nil {
		u.report(3, "Writing converted output", "FAILED", err.Error())
		return fmt.Errorf("encoding YAML: %w", err)
	}

	if kevOutFile == "stdout" || kevOutFile == "-" {
		fmt.Fprint(commandOutput(cmd), string(yamlData))
	} else {
		if err := cli.SafeWriteFile(kevOutFile, yamlData); err != nil {
			u.report(3, "Writing converted output", "FAILED", err.Error())
			return fmt.Errorf("writing output: %w", err)
		}
		if !u.progress.Enabled() {
			fmt.Fprintf(commandOutput(cmd), "Converted %d KEV entries to %s\n", len(out.Vulnerabilities), kevOutFile)
		}
	}
	u.report(3, "Writing converted output", "DONE", kevOutFile)

	if kevAttestKey != "" && kevOutFile != "stdout" && kevOutFile != "-" {
		u.report(4, "Writing tool attestation", "RUNNING", kevAttestKey)
		if err := attestKEV(inFile, kevOutFile, kevAttestKey); err != nil {
			u.report(4, "Writing tool attestation", "FAILED", err.Error())
			fmt.Fprintf(os.Stderr, "[WARN] Attestation failed: %v\n", err)
		} else {
			u.report(4, "Writing tool attestation", "DONE", kevOutFile+".attest")
		}
	} else {
		u.report(4, "Writing tool attestation", "SKIPPED", "not requested")
	}
	if u.progress.Enabled() {
		u.render("kev", kevOutFile, len(out.Vulnerabilities), 0, len(out.Vulnerabilities), kevAttestKey != "")
	}
	return nil
}

func attestKEV(inputFile, outputFile, keyPath string) error {
	inHash, err := attest.FileHash(inputFile)
	if err != nil {
		return fmt.Errorf("hash input: %w", err)
	}
	outHash, err := attest.FileHash(outputFile)
	if err != nil {
		return fmt.Errorf("hash output: %w", err)
	}

	a := attest.New("wardex-convert/kev", "2.3.0").
		SetInputHash(inHash).
		SetOutputHash(outHash).
		SetConvertedBy("wardex-convert/kev")

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
	if err := cli.SafeWriteFile(attestPath, out); err != nil {
		return fmt.Errorf("write attestation: %w", err)
	}

	cfgHash, err := cpl.ComputeConfigHash(outHash, cpl.AlgoSHA256)
	if err == nil {
		a.SetConfigHash(cfgHash)
	}

	fmt.Fprintf(os.Stderr, "[PROVENANCE] Signed attestation written to %s\n", attestPath)
	return nil
}
