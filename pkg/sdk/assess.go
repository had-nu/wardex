// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package sdk provides a programmatic API for running compliance gap analysis
// and release gate evaluations without using the command-line interface.
//
// This package is designed for security engineers who want to integrate Wardex
// into their own tools, CI/CD pipelines, or custom workflows.
//
// # Usage
//
//	import "github.com/had-nu/wardex/pkg/sdk"
//
//	func main() {
//	    // Load controls from files or other sources
//	    controls, err := sdk.LoadControls("./controls.yaml")
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Run ISO 27001 assessment
//	    result, err := sdk.Analyze(controls, "iso27001")
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    fmt.Printf("Coverage: %.1f%%\n", result.Summary.GlobalCoverage)
//	    fmt.Printf("Gaps: %d\n", result.Summary.GapCount)
//	}
package sdk

import (
	"fmt"

	"github.com/had-nu/wardex/pkg/analyzer"
	"github.com/had-nu/wardex/pkg/catalog"
	"github.com/had-nu/wardex/pkg/correlator"
	"github.com/had-nu/wardex/pkg/ingestion"
	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/report"
	"github.com/had-nu/wardex/pkg/snapshot"
)

// AssessmentResult contains the complete results of a compliance assessment.
type AssessmentResult struct {
	Summary  model.ExecutiveSummary
	Findings []model.Finding
	Roadmap  []model.Finding
	Posture  analyzer.PostureReport
	Gate     *model.GateReport
	Delta    *model.Delta
}

// Analyze runs a complete compliance gap analysis for the given controls against a framework.
// Returns an AssessmentResult with all findings, coverage metrics, and optional roadmap.
func Analyze(controls []model.ExistingControl, framework string) (*AssessmentResult, error) {
	if len(controls) == 0 {
		return nil, fmt.Errorf("sdk: no controls provided")
	}

	cat, err := catalog.Load(framework)
	if err != nil {
		return nil, fmt.Errorf("sdk: %w", err)
	}
	corr := correlator.New(cat)
	mappings, err := corr.Correlate(controls)
	if err != nil {
		return nil, fmt.Errorf("sdk: correlation failed: %w", err)
	}

	an := analyzer.New(cat, mappings, controls)
	findings, err := an.Analyze()
	if err != nil {
		return nil, fmt.Errorf("sdk: analysis failed: %w", err)
	}

	var sortedRoadmap []model.Finding
	for _, f := range findings {
		if f.Status != model.StatusCovered {
			sortedRoadmap = append(sortedRoadmap, f)
		}
	}
	for i := 0; i < len(sortedRoadmap); i++ {
		for j := i + 1; j < len(sortedRoadmap); j++ {
			if sortedRoadmap[i].FinalScore < sortedRoadmap[j].FinalScore {
				sortedRoadmap[i], sortedRoadmap[j] = sortedRoadmap[j], sortedRoadmap[i]
			}
		}
	}

	summary := buildSummary(cat, findings)
	posture := an.AssessPosture(findings)

	return &AssessmentResult{
		Summary:  summary,
		Findings: findings,
		Roadmap:  sortedRoadmap,
		Posture:  posture,
	}, nil
}

// AnalyzeWithConfig runs assessment with custom configuration.
func AnalyzeWithConfig(controls []model.ExistingControl, framework string, opts *AnalyzeOptions) (*AssessmentResult, error) {
	if opts == nil {
		opts = &AnalyzeOptions{}
	}
	opts.setDefaults()

	cat, err := catalog.Load(framework)
	if err != nil {
		return nil, fmt.Errorf("sdk: %w", err)
	}
	corr := correlator.New(cat)
	var mappings []model.Mapping

	if opts.MinConfidence == "high" {
		mappings, err = corr.CorrelateWithConfidence(controls, "high")
	} else {
		mappings, err = corr.Correlate(controls)
	}
	if err != nil {
		return nil, fmt.Errorf("sdk: correlation failed: %w", err)
	}

	an := analyzer.New(cat, mappings, controls)
	var findings []model.Finding
	if opts.FilterLowConfidence {
		findings, err = an.AnalyzeWithConfig(&analyzer.AnalyzerOptions{
			FilterLowConfidence: true,
		})
	} else {
		findings, err = an.Analyze()
	}
	if err != nil {
		return nil, fmt.Errorf("sdk: analysis failed: %w", err)
	}

	var sortedRoadmap []model.Finding
	for _, f := range findings {
		if f.Status != model.StatusCovered {
			sortedRoadmap = append(sortedRoadmap, f)
		}
	}

	summary := buildSummary(cat, findings)
	posture := an.AssessPosture(findings)

	return &AssessmentResult{
		Summary:  summary,
		Findings: findings,
		Roadmap:  sortedRoadmap,
		Posture:  posture,
	}, nil
}

// AnalyzeOptions provides configuration for AnalyzeWithConfig.
type AnalyzeOptions struct {
	MinConfidence        string
	FilterLowConfidence  bool
	PreviousSnapshotFile string
}

func (o *AnalyzeOptions) setDefaults() {
	if o == nil {
		*o = AnalyzeOptions{}
	}
	if o.MinConfidence == "" {
		o.MinConfidence = "low"
	}
}

// LoadControls loads controls from one or more files.
// Supports YAML, JSON, and CSV formats.
func LoadControls(paths ...string) ([]model.ExistingControl, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("sdk: no paths provided")
	}
	return ingestion.LoadMany(paths)
}

// LoadFramework returns the control catalog for a given framework.
func LoadFramework(name string) ([]model.CatalogControl, error) {
	return catalog.Load(name)
}

// Report generates a report from AssessmentResult in the specified format.
// Supported formats: "markdown", "json", "csv".
func Report(result *AssessmentResult, format, outputFile string, roadmapLimit int) error {
	gapReport := model.GapReport{
		Summary:  result.Summary,
		Findings: result.Findings,
		Roadmap:  result.Roadmap,
		Gate:     result.Gate,
		Delta:    result.Delta,
	}
	return report.Generate(gapReport, format, outputFile, roadmapLimit)
}

// SnapshotSave saves the current assessment result to a snapshot file.
func SnapshotSave(filename string, result *AssessmentResult) error {
	gapReport := model.GapReport{
		Summary:  result.Summary,
		Findings: result.Findings,
		Roadmap:  result.Roadmap,
		Gate:     result.Gate,
	}
	return snapshot.Save(filename, &gapReport)
}

// SnapshotLoad loads a previous assessment result from a snapshot file.
func SnapshotLoad(filename string) (*AssessmentResult, error) {
	prev, err := snapshot.Load(filename)
	if err != nil {
		return nil, fmt.Errorf("sdk: failed to load snapshot: %w", err)
	}
	if prev == nil {
		return nil, nil
	}
	return &AssessmentResult{
		Summary:  prev.Summary,
		Findings: prev.Findings,
		Roadmap:  prev.Roadmap,
		Gate:     prev.Gate,
		Delta:    prev.Delta,
	}, nil
}

// SnapshotDiff computes the delta between two assessments.
func SnapshotDiff(current, previous *AssessmentResult) model.Delta {
	currentGap := model.GapReport{Summary: current.Summary}
	previousGap := model.GapReport{Summary: previous.Summary}
	return snapshot.Diff(currentGap, previousGap)
}

func buildSummary(cat []model.CatalogControl, findings []model.Finding) model.ExecutiveSummary {
	domainMap := make(map[string]*model.DomainSummary)
	for _, f := range findings {
		dom := f.Control.Domain
		if dom == "" {
			dom = "general"
		}
		ds, ok := domainMap[dom]
		if !ok {
			ds = &model.DomainSummary{Domain: dom}
			domainMap[dom] = ds
		}
		ds.TotalControls++
		switch f.Status {
		case model.StatusCovered:
			ds.CoveredCount++
		case model.StatusPartial:
			ds.PartialCount++
		default:
			ds.GapCount++
		}
		ds.MaturityScore += f.FinalScore
	}

	var domainSummaries []model.DomainSummary
	for _, ds := range domainMap {
		if ds.TotalControls > 0 {
			ds.MaturityScore = ds.MaturityScore / float64(ds.TotalControls)
		}
		domainSummaries = append(domainSummaries, *ds)
	}

	totalControls := len(cat)
	covered := 0
	partial := 0
	gap := 0
	for _, f := range findings {
		switch f.Status {
		case model.StatusCovered:
			covered++
		case model.StatusPartial:
			partial++
		default:
			gap++
		}
	}
	globalCoverage := float64(covered) / float64(totalControls) * 100.0

	return model.ExecutiveSummary{
		TotalControls:   totalControls,
		CoveredCount:    covered,
		PartialCount:    partial,
		GapCount:        gap,
		GlobalCoverage:  globalCoverage,
		DomainSummaries: domainSummaries,
	}
}
