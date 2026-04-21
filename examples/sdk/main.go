// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// This is an example of using the Wardex SDK programmatically.
// Run with: go run examples/sdk/main.go
package main

import (
	"fmt"
	"log"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/sdk"
)

func main() {
	fmt.Println("=== Wardex SDK Example ===")
	fmt.Println()

	// Load controls from file or create programmatically
	controls, err := sdk.LoadControls("./examples/sdk/controls.yaml")
	if err != nil {
		log.Fatalf("Failed to load controls: %v", err)
	}
	fmt.Printf("Loaded %d controls\n", len(controls))

	// Also demonstrate creating controls programmatically
	programmaticControls := []model.ExistingControl{
		{
			ID:          "AWS-IAM-001",
			Name:        "IAM Password Policy",
			Description: "Enforces strong passwords",
			Maturity:    4,
			Domains:     []string{"access_control", "authentication"},
		},
		{
			ID:          "AWS-KMS-001",
			Name:        "KMS Key Management",
			Description: "AWS managed encryption keys",
			Maturity:    3,
			Domains:     []string{"cryptography"},
		},
	}
	controls = append(controls, programmaticControls...)

	// Run ISO 27001 assessment
	result, err := sdk.Analyze(controls, "iso27001")
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	// Print results
	fmt.Printf("\n## Assessment Results: ISO 27001\n")
	fmt.Printf("Coverage: %.1f%%\n", result.Summary.GlobalCoverage)
	fmt.Printf("Controls: %d covered / %d partial / %d gaps\n",
		result.Summary.CoveredCount,
		result.Summary.PartialCount,
		result.Summary.GapCount)

	// Print top gaps
	if len(result.Roadmap) > 0 {
		fmt.Println("\n## Top Priority Gaps:")
		for i, f := range result.Roadmap[:min(5, len(result.Roadmap))] {
			fmt.Printf("  %d. [%s] %s - %s (%.1f)\n",
				i+1, f.Control.ID, f.Control.Name, f.Status, f.FinalScore)
		}
	}

	// Generate reports in different formats
	fmt.Println("\n## Generating reports...")

	if err := sdk.Report(result, "markdown", "report.md", 10); err != nil {
		log.Printf("Warning: failed to generate markdown: %v", err)
	} else {
		fmt.Println("  - Markdown: report.md")
	}

	if err := sdk.Report(result, "json", "report.json", 0); err != nil {
		log.Printf("Warning: failed to generate json: %v", err)
	} else {
		fmt.Println("  - JSON: report.json")
	}

	if err := sdk.Report(result, "csv", "report.csv", 0); err != nil {
		log.Printf("Warning: failed to generate csv: %v", err)
	} else {
		fmt.Println("  - CSV: report.csv")
	}

	fmt.Println("\nDone!")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
