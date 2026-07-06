// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package convert

import (
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var kevOutFile string

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
}

func runConvertKEV(cmd *cobra.Command, args []string) error {
	inFile := args[0]

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	safePath, err := cli.ValidateInputPath(cwd, inFile)
	if err != nil {
		return fmt.Errorf("validating input path: %w", err)
	}

	if warn := CheckKEVAge(safePath, KEVMaxAgeDays); warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}

	catalogue, err := LoadKEVCatalogue(safePath)
	if err != nil {
		return fmt.Errorf("loading KEV catalogue: %w", err)
	}

	type kevYAML struct {
		ConvertedBy     string               `yaml:"converted_by"`
		CatalogVersion  string               `yaml:"catalog_version"`
		DateReleased    string               `yaml:"date_released"`
		Count           int                  `yaml:"count"`
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

	yamlData, err := yaml.Marshal(&out)
	if err != nil {
		return fmt.Errorf("encoding YAML: %w", err)
	}

	if kevOutFile == "stdout" || kevOutFile == "-" {
		fmt.Fprint(cmd.OutOrStdout(), string(yamlData))
	} else {
		if err := os.WriteFile(kevOutFile, yamlData, 0600); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Converted %d KEV entries to %s\n", len(out.Vulnerabilities), kevOutFile)
	}

	return nil
}
