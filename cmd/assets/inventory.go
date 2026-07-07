// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package assets

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var assetsFile string
var assetsFormat string

// InventoryCmd displays the ICT asset inventory.
var InventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Display the ICT asset inventory from an assets YAML file",
	Long: `Load and display the ICT asset inventory defined in an assets YAML file.
Shows asset ID, name, type, criticality, exposure, and associated controls.

Output formats: table (default), json, csv`,
	RunE: runAssetsInventory,
}

func init() {
	InventoryCmd.Flags().StringVar(&assetsFile, "assets", "", "Path to assets YAML file (required)")
	InventoryCmd.Flags().StringVarP(&assetsFormat, "format", "f", "table", "Output format: table|json|csv")
	_ = InventoryCmd.MarkFlagRequired("assets")
}

type assetEntry struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Type        string   `yaml:"type" json:"type"`
	Criticality float64  `yaml:"criticality" json:"criticality"`
	Scope       []string `yaml:"scope" json:"scope,omitempty"`
	Controls    []string `yaml:"controls" json:"controls,omitempty"`
	Exposure    struct {
		InternetFacing    bool   `yaml:"internet_facing" json:"internet_facing"`
		NetworkZone       string `yaml:"network_zone" json:"network_zone"`
		DataClassification string `yaml:"data_classification" json:"data_classification"`
	} `yaml:"exposure" json:"exposure"`
	Owner            string `yaml:"owner" json:"owner"`
	BusinessProcess  string `yaml:"business_process" json:"business_process"`
	RegulatoryImpact string `yaml:"regulatory_impact" json:"regulatory_impact"`
}

func runAssetsInventory(cmd *cobra.Command, args []string) error {
	safePath, err := cli.SafePath(assetsFile)
	if err != nil {
		return fmt.Errorf("validating assets path: %w", err)
	}

	data, err := os.ReadFile(safePath) // #nosec G304
	if err != nil {
		return fmt.Errorf("reading assets file: %w", err)
	}

	var assets []assetEntry
	if err := yaml.Unmarshal(data, &assets); err != nil {
		return fmt.Errorf("parsing assets file: %w", err)
	}

	switch assetsFormat {
	case "json":
		out, _ := json.MarshalIndent(assets, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))

	case "csv":
		fmt.Fprintln(cmd.OutOrStdout(), "id,name,type,criticality,internet_facing,zone,owner,controls")
		for _, a := range assets {
			fmt.Fprintf(cmd.OutOrStdout(), "%s,%s,%s,%.2f,%t,%s,%s,\"%s\"\n",
				a.ID, a.Name, a.Type, a.Criticality,
				a.Exposure.InternetFacing, a.Exposure.NetworkZone,
				a.Owner, strings.Join(a.Controls, ";"))
		}

	default: // table
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%-18s %-35s %-14s %-12s %-8s %-10s %-18s\n",
			"Asset ID", "Name", "Type", "Criticality", "Internet", "Zone", "Owner")
		fmt.Fprintf(w, "%-18s %-35s %-14s %-12s %-8s %-10s %-18s\n",
			"──────────────────", "──────────────────────────────────", "──────────────", "────────────", "────────", "──────────", "──────────────────")
		for _, a := range assets {
			name := a.Name
			if len(name) > 33 {
				name = name[:30] + "..."
			}
			owner := a.Owner
			if len(owner) > 16 {
				owner = owner[:13] + "..."
			}
			fmt.Fprintf(w, "%-18s %-35s %-14s %-12.2f %-8t %-10s %-18s\n",
				a.ID, name, a.Type, a.Criticality,
				a.Exposure.InternetFacing, a.Exposure.NetworkZone, owner)
		}
	}

	return nil
}
