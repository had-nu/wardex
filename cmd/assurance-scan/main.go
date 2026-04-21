// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package main

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/had-nu/wardex/pkg/analyzer"
	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/sdk"
)

/*
   Junior Software Assurance Analyst Script (V2 - SDK Driven)
   Task: Generate a Security Posture Intelligence Assessment for ISO 27001
   Note: This script now uses the native Wardex SDK Posture Engine for 
   metrics aggregation, ensuring a standard intelligence-driven assessment.
*/

func main() {
	fmt.Println("[*] Junior Analyst - Starting Assurance Scan...")

	// 1. Define our actual security context
	existingControls := []model.ExistingControl{
		{ID: "FW-001", Name: "Corporate Firewall", Maturity: 3},
		{ID: "IAM-001", Name: "Okta MFA", Maturity: 4},
		{ID: "SIEM-001", Name: "Splunk Cloud", Maturity: 2},
		{ID: "BCP-001", Name: "Backup Procedure", Maturity: 3},
	}

	// 2. Run ISO 27001 Assessment using the SDK
	result, err := sdk.Analyze(existingControls, "iso27001")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Critical failure during analysis: %v\n", err)
		os.Exit(1)
	}

	// 3. Generate the Intelligence Assessment Report using SDK Posture Metrics
	generateIntelligenceReport(result.Posture, result.Summary.TotalControls)
}

func generateIntelligenceReport(p analyzer.PostureReport, totalFrameworkControls int) {
	fmt.Println("[*] Consuming SDK intelligence metrics...")

	// Sorting domains by gap density for intelligence focus
	type domainStat struct {
		name string
		gaps int
	}
	var stats []domainStat
	for d, g := range p.DomainConcentration {
		stats = append(stats, domainStat{d, g})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].gaps > stats[j].gaps
	})

	// Print Markdown Report
	fmt.Println("\n---")
	fmt.Printf("# Security Posture Intelligence Assessment: ISO 27001 Annex A\n")
	fmt.Printf("Date: %s\n", time.Now().Format("2006-01-02"))
	fmt.Printf("Analyst: Junior Software Assurance Analyst (Agentic AI Instance)\n")
	fmt.Printf("Tooling: Wardex SDK v1.7.2 (Posture Engine Enabled)\n\n")

	fmt.Println("## Executive Summary")
	fmt.Printf("Current Posture Index: **%.1f/100.0**\n", p.GlobalIndex)
	fmt.Printf("The assessment identified **%.1f** units of Risk Exposure across %d framework controls.\n", p.RiskExposure, totalFrameworkControls)
	fmt.Println("While basic compliance is partially addressed, the intelligence analysis shows significant risk concentration in high-impact domains.\n")

	fmt.Println("## Risk Concentration Analysis")
	fmt.Println("The following domains represent the highest exposure areas (Intelligence focus):")
	for i, s := range stats {
		if i >= 3 {
			break
		}
		fmt.Printf("- **%s**: %d identified gaps (Criticality Focus)\n", s.name, s.gaps)
	}
	fmt.Println("")

	fmt.Println("## Top Intelligence Findings (High Impact Gaps)")
	fmt.Println("| ID | Control Name | Criticality | Gap Reasoning |")
	fmt.Println("|----|--------------|-------------|---------------|")
	
	for i, f := range p.CriticalGaps {
		fmt.Printf("| %s | %s | %.1f | %s |\n", f.Control.ID, f.Control.Name, f.Control.BaseScore, f.GapReasons[0])
		if i >= 4 {
			break
		}
	}
	fmt.Println("")

	fmt.Println("## Analyst Recommendations")
	fmt.Println("1. **Domain Prioritization**: Focus on top identified domains in the Concentration Analysis.")
	fmt.Println("2. **Strategic Upgrade**: Address Critical Gaps listed above to reduce the Risk Exposure index immediately.")
	fmt.Println("3. **Compliance Delta**: Move towards closing gaps in high-criticality controls to improve the Global Posture Index.")
	fmt.Println("---")
}
