// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package assess

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/analyzer"
	"github.com/had-nu/wardex/v2/pkg/catalog"
	"github.com/had-nu/wardex/v2/pkg/correlator"
	"github.com/had-nu/wardex/v2/pkg/ingestion"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/report"
	"github.com/had-nu/wardex/v2/pkg/scorer"
	"github.com/had-nu/wardex/v2/pkg/snapshot"
	"github.com/spf13/cobra"
)

var (
	configPath   string
	assetsFile   string
	framework    string
	snapshotPath string
	outputFormat string
	outFile      string
)

// AssessCmd performs a comprehensive risk and compliance assessment.
var AssessCmd = &cobra.Command{
	Use:   "assess [flags] <controls-file(s)>",
	Short: "Comprehensive compliance assessment with asset mapping and layer delta",
	Long: `Analyze your organization's security controls against a framework catalog,
mapping them to specific assets and identifying gaps between documented and
implemented security layers (Paper vs. Code).

Example:
  wardex assess --assets ./data/assets.yaml ./policy/controls.yml
`,
	Args: cobra.MinimumNArgs(1),
	RunE: runAssess,
}

func init() {
	AssessCmd.Flags().StringVar(&configPath, "config", "./wardex-config.yaml", "Path to wardex-config.yaml")
	AssessCmd.Flags().StringVar(&assetsFile, "assets", "", "Path to assets definition file")
	AssessCmd.Flags().StringVar(&framework, "framework", "iso27001", "Target framework name")
	AssessCmd.Flags().StringVar(&snapshotPath, "snapshot", "", "Path to previous report for delta analysis")
	AssessCmd.Flags().StringVar(&outputFormat, "output", "markdown", "Output format: markdown|json|csv")
	AssessCmd.Flags().StringVar(&outFile, "out-file", "stdout", "Output file destination")
}

func runAssess(cmd *cobra.Command, args []string) error {
	_, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to load config: %v. Using defaults.\n", err)
	}

	// 1. Load Controls from provided files
	extControls, err := ingestion.LoadMany(args)
	if err != nil {
		return fmt.Errorf("assess: load controls: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[INFO] Loaded %d controls from input files.\n", len(extControls))

	// 2. Load Framework Catalog
	cat, err := catalog.Load(framework)
	if err != nil {
		return fmt.Errorf("assess: %w\n[HINT] Use --framework para especificar um framework válido: iso27001, soc2, nis2, dora, nist_csf, eu_ai_act", err)
	}
	fmt.Fprintf(os.Stderr, "[INFO] Using framework: %s (%d controls in catalog).\n", framework, len(cat))

	// 3. Correlate mappings
	corr := correlator.New(cat)
	mappings, err := corr.Correlate(extControls)
	if err != nil {
		return fmt.Errorf("assess: correlation failed: %w", err)
	}

	// 4. Perform Analysis
	an := analyzer.New(cat, mappings, extControls)
	findings, err := an.Analyze()
	if err != nil {
		return fmt.Errorf("assess: analysis failed: %w", err)
	}

	// 5. Layer Delta Analysis (Paper vs Code)
	layerDelta := an.ComputeLayerDelta()

	// 6. Asset-Level Compliance (if provided)
	var assetCompliance []model.AssetCompliance
	if assetsFile != "" {
		assets, err := ingestion.LoadAssets(assetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Asset loading failed: %v\n", err)
		} else {
			assetCompliance = analyzer.AssessAssets(assets, extControls, cat, mappings)
			fmt.Fprintf(os.Stderr, "[INFO] Performed compliance assessment for %d assets.\n", len(assets))
		}
	}

	// 7. Calculate Summary and Roadmap
	summary := scorer.Summarize(findings)
	summary.DomainSummaries = scorer.MaturityByDomain(findings)
	roadmap := scorer.Roadmap(findings)

	finalReport := model.GapReport{
		Summary:         summary,
		Findings:        findings,
		Roadmap:         roadmap,
		LayerDelta:      &layerDelta,
		AssetCompliance: assetCompliance,
	}

	// 8. Delta Analysis (Snapshot comparison)
	if snapshotPath != "" {
		prev, err := snapshot.Load(snapshotPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Failed to load snapshot from %s: %v\n", snapshotPath, err)
		} else {
			delta := snapshot.Diff(finalReport, *prev)
			finalReport.Delta = &delta
			fmt.Fprintf(os.Stderr, "[INFO] Delta analysis complete (Coverage change: %.1f%%).\n", delta.CoverageChange)
		}
	}

	// 9. Generate Report
	if err := report.Generate(finalReport, outputFormat, outFile, 0); err != nil {
		return fmt.Errorf("assess: report generation failed: %w", err)
	}

	if outFile != "stdout" {
		fmt.Fprintf(os.Stderr, "[PASS] Assessment complete. Report written to %s\n", outFile)
	}

	return nil
}
