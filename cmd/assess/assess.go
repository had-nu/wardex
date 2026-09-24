// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package assess

import (
	"fmt"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/analyzer"
	"github.com/had-nu/wardex/v2/pkg/catalog"
	"github.com/had-nu/wardex/v2/pkg/correlator"
	"github.com/had-nu/wardex/v2/pkg/ingestion"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/report"
	"github.com/had-nu/wardex/v2/pkg/scorer"
	"github.com/had-nu/wardex/v2/pkg/snapshot"
	"github.com/had-nu/wardex/v2/pkg/ui"
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
	stderr := cmd.ErrOrStderr()
	session := buildAssessSession(args)
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(session)
	reportProgress := func(number int, name, status, detail string) {
		progress.Report(ui.PhaseEvent{
			Number: number,
			Name:   name,
			Status: status,
			Detail: detail,
		})
	}

	// 1. Load configuration (lenient: warn and continue with defaults).
	reportProgress(1, "Loading configuration", "RUNNING", "")
	_, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] Failed to load config: %v. Using defaults.\n", err)
		reportProgress(1, "Loading configuration", "DONE", "using defaults")
	} else {
		reportProgress(1, "Loading configuration", "DONE", "configuration loaded")
	}

	// 2. Load controls.
	reportProgress(2, "Loading controls", "RUNNING", "")
	extControls, err := ingestion.LoadMany(args)
	if err != nil {
		reportProgress(2, "Loading controls", "FAILED", err.Error())
		return fmt.Errorf("assess: load controls: %w", err)
	}
	fmt.Fprintf(stderr, "[INFO] Loaded %d controls from input files.\n", len(extControls))
	reportProgress(2, "Loading controls", "DONE", fmt.Sprintf("%d controls", len(extControls)))

	// 3. Load framework catalog.
	reportProgress(3, "Loading framework catalog", "RUNNING", "")
	cat, err := catalog.Load(framework)
	if err != nil {
		reportProgress(3, "Loading framework catalog", "FAILED", err.Error())
		return fmt.Errorf("assess: %w\n[HINT] Use --framework para especificar um framework válido: iso27001, soc2, nis2, dora, nist_csf, eu_ai_act", err)
	}
	fmt.Fprintf(stderr, "[INFO] Using framework: %s (%d controls in catalog).\n", framework, len(cat))
	reportProgress(3, "Loading framework catalog", "DONE", fmt.Sprintf("%d catalog controls", len(cat)))

	// 4. Correlate mappings.
	reportProgress(4, "Correlating controls", "RUNNING", "")
	corr := correlator.New(cat)
	mappings, err := corr.Correlate(extControls)
	if err != nil {
		reportProgress(4, "Correlating controls", "FAILED", err.Error())
		return fmt.Errorf("assess: correlation failed: %w", err)
	}
	reportProgress(4, "Correlating controls", "DONE", fmt.Sprintf("%d mappings", len(mappings)))

	// 5. Perform analysis.
	reportProgress(5, "Computing compliance gaps", "RUNNING", "")
	an := analyzer.New(cat, mappings, extControls)
	findings, err := an.Analyze()
	if err != nil {
		reportProgress(5, "Computing compliance gaps", "FAILED", err.Error())
		return fmt.Errorf("assess: analysis failed: %w", err)
	}
	reportProgress(5, "Computing compliance gaps", "DONE", fmt.Sprintf("%d findings", len(findings)))

	// 6. Layer delta analysis (Paper vs Code).
	reportProgress(6, "Computing layer delta", "RUNNING", "")
	layerDelta := an.ComputeLayerDelta()
	reportProgress(6, "Computing layer delta", "DONE", fmt.Sprintf("%d documented · %d implemented", layerDelta.DocumentedCount, layerDelta.ImplementedCount))

	// 7. Asset-level compliance (if provided).
	var assetCompliance []model.AssetCompliance
	if assetsFile == "" {
		reportProgress(7, "Assessing assets", "SKIPPED", "not requested")
	} else {
		reportProgress(7, "Assessing assets", "RUNNING", "")
		assets, err := ingestion.LoadAssets(assetsFile)
		if err != nil {
			fmt.Fprintf(stderr, "[WARN] Asset loading failed: %v\n", err)
			reportProgress(7, "Assessing assets", "SKIPPED", "asset input unavailable")
		} else {
			assetCompliance = analyzer.AssessAssets(assets, extControls, cat, mappings)
			fmt.Fprintf(stderr, "[INFO] Performed compliance assessment for %d assets.\n", len(assets))
			reportProgress(7, "Assessing assets", "DONE", fmt.Sprintf("%d assets", len(assets)))
		}
	}

	// 8. Calculate summary and roadmap.
	reportProgress(8, "Building assessment summary", "RUNNING", "")
	summary := scorer.Summarize(findings)
	summary.DomainSummaries = scorer.MaturityByDomain(findings)
	roadmap := scorer.Roadmap(findings)
	reportProgress(8, "Building assessment summary", "DONE", fmt.Sprintf("%d roadmap item(s)", len(roadmap)))

	finalReport := model.GapReport{
		Summary:         summary,
		Findings:        findings,
		Roadmap:         roadmap,
		LayerDelta:      &layerDelta,
		AssetCompliance: assetCompliance,
	}

	// 9. Delta analysis (snapshot comparison).
	reportProgress(9, "Comparing snapshot", "RUNNING", "")
	if snapshotPath == "" {
		reportProgress(9, "Comparing snapshot", "SKIPPED", "not requested")
	} else {
		prev, err := snapshot.Load(snapshotPath)
		if err != nil {
			fmt.Fprintf(stderr, "[WARN] Failed to load snapshot from %s: %v\n", snapshotPath, err)
			reportProgress(9, "Comparing snapshot", "SKIPPED", "snapshot unavailable")
		} else {
			delta := snapshot.Diff(finalReport, *prev)
			finalReport.Delta = &delta
			fmt.Fprintf(stderr, "[INFO] Delta analysis complete (Coverage change: %.1f%%).\n", delta.CoverageChange)
			reportProgress(9, "Comparing snapshot", "DONE", fmt.Sprintf("coverage change %.1f%%", delta.CoverageChange))
		}
	}

	// 10. Generate report.
	reportProgress(10, "Generating report", "RUNNING", "")
	if err := report.Generate(finalReport, outputFormat, outFile, 0); err != nil {
		reportProgress(10, "Generating report", "FAILED", err.Error())
		return fmt.Errorf("assess: report generation failed: %w", err)
	}
	reportProgress(10, "Generating report", "DONE", outputFormat)

	if outFile != "stdout" {
		fmt.Fprintf(stderr, "[PASS] Assessment complete. Report written to %s\n", outFile)
	}
	reportProgress(11, "Completing assessment", "RUNNING", "")
	reportProgress(11, "Completing assessment", "DONE", "assessment complete")
	renderAssessResults(stderr, progress, session, finalReport)
	return nil
}
