// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package sboms

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/utils"
)

// OpenVEXDocument partial schema based on https://openvex.dev
type OpenVEXDocument struct {
	Context    string             `json:"@context"`
	Statements []OpenVEXStatement `json:"statements"`
}

type OpenVEXStatement struct {
	Vulnerability string   `json:"vulnerability"`
	Status        string   `json:"status"`   // not_affected, false_positive, affected, under_investigation
	Products      []string `json:"products"` // Usually purls or URIs
}

// ParseOpenVEX attempts to parse a standalone OpenVEX JSON document.
// It returns a slice of Wardex Vulnerabilities. When status is not_affected
// or false_positive, it marks Reachable=false so the Release Gate suppresses them.
func ParseOpenVEX(filePath string) ([]model.Vulnerability, error) {
	cwd, _ := os.Getwd()
	safePathStr, err := utils.SafePath(cwd, filePath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(safePathStr) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read openvex file: %w", err)
	}

	var vex OpenVEXDocument
	if err := json.Unmarshal(data, &vex); err != nil {
		return nil, fmt.Errorf("failed to parse openvex JSON: %w", err)
	}

	if vex.Context != "https://openvex.dev/ns/v0.2.0" && vex.Context != "https://openvex.dev/ns" {
		return nil, fmt.Errorf("not an openvex document (invalid @context)")
	}

	var vulns []model.Vulnerability
	var skippedStates int

	for _, stmt := range vex.Statements {
		var reachable bool
		switch stmt.Status {
		case "not_affected", "false_positive":
			reachable = false // Suppress in Wardex
		case "under_investigation", "affected":
			reachable = true
		default:
			skippedStates++
			continue
		}

		compStr := "unknown-product"
		if len(stmt.Products) > 0 {
			compStr = stmt.Products[0]
		}

		vulns = append(vulns, model.Vulnerability{
			CVEID:     stmt.Vulnerability,
			CVSSBase:  0.0, // OpenVEX rarely carries CVSS metrics directly
			EPSSScore: 0.05,
			Component: compStr,
			Reachable: reachable,
		})
	}

	if skippedStates > 0 {
		fmt.Fprintf(os.Stderr, "[WARN] %d OpenVEX statement(s) skipped — unrecognized state\n", skippedStates)
	}

	return vulns, nil
}
