// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package orchestrator extracts and owns the Wardex evaluation pipeline so
// that command entry points (main.go, cmd/evaluate) stay thin. The pipeline
// never calls os.Exit and never writes directly to os.Stderr: it returns an
// ExitCode for the caller to act on and logs through an injected *slog.Logger.
package orchestrator

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/analyzer"
	"github.com/had-nu/wardex/v2/pkg/catalog"
	pathguard "github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/correlator"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/gate"
	"github.com/had-nu/wardex/v2/pkg/ingestion"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/releasegate"
	"github.com/had-nu/wardex/v2/pkg/report"
	"github.com/had-nu/wardex/v2/pkg/snapshot"
	"gopkg.in/yaml.v3"
)

// ExitReason classifies the pipeline outcome for reporting.
type ExitReason string

const (
	ExitOK          ExitReason = "ok"
	ExitGateBlocked ExitReason = "gate_blocked"
	ExitCompliance  ExitReason = "compliance_fail"
)

// EvaluationOptions carries the evaluated command's flag values into the pipeline.
type EvaluationOptions struct {
	ConfigPath    string
	ProfileName   string
	Inputs        []string
	Framework     string
	MinConfidence string
	GateFile      string
	GateMode      string
	FailAbove     float64
	NoSnapshot    bool
	SnapshotFile  string
	OutputFormat  string
	OutFile       string
	RoadmapLimit  int
	EPSSEnrich    string
	Logger        *slog.Logger
	Stderr        io.Writer
}

// EvaluationResult is the pipeline's outcome. ExitCode is decided by the
// pipeline; the caller performs the actual os.Exit.
type EvaluationResult struct {
	Report     model.GapReport
	GateReport *model.GateReport
	ExitReason ExitReason
	ExitCode   int
}

// EvaluationPipeline runs the core Wardex evaluation flow: config load,
// correlation, gap analysis, optional release gate, snapshot, and report
// generation. It returns an error only for hard pipeline failures; gate and
// compliance decisions are expressed through EvaluationResult.ExitCode.
type EvaluationPipeline struct {
	Config *config.Config
	Logger *slog.Logger
	Stderr io.Writer
	opts   EvaluationOptions
}

// NewEvaluationPipeline builds the pipeline from the given options.
func NewEvaluationPipeline(opts EvaluationOptions) *EvaluationPipeline {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	return &EvaluationPipeline{Logger: opts.Logger, Stderr: opts.Stderr, opts: opts}
}

// Run executes the evaluation pipeline and returns the outcome.
func (p *EvaluationPipeline) Run(ctx context.Context, opts EvaluationOptions) (*EvaluationResult, error) {
	p.opts = opts
	if opts.Logger != nil {
		p.Logger = opts.Logger
	}
	if opts.Stderr != nil {
		p.Stderr = opts.Stderr
	}

	// 1. Load config (lenient: warn and continue on failure).
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		p.Logger.Warn("failed to load config; continuing with defaults", "path", opts.ConfigPath, "error", err)
		cfg = &config.Config{}
	}
	p.Config = cfg

	if msg := config.ApplyProfile(cfg, opts.ProfileName, p.Stderr); msg != "" {
		p.Logger.Info(msg)
	}

	// 2. Load external controls.
	extControls, err := ingestion.LoadMany(opts.Inputs)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}

	// 3. Load catalog + correlate.
	cat, err := catalog.Load(opts.Framework)
	if err != nil {
		p.Logger.Info("use --framework to select a supported compliance framework")
		return nil, fmt.Errorf("load framework catalog %q: %w", opts.Framework, err)
	}
	corr := correlator.New(cat)
	mappings, err := corr.Correlate(extControls)
	if err != nil {
		return nil, fmt.Errorf("correlation failed: %w", err)
	}

	// 4. Filter mappings by minimum confidence.
	var filtered []model.Mapping
	droppedLowConf := 0
	for _, m := range mappings {
		if opts.MinConfidence == "high" && m.Confidence == "low" {
			droppedLowConf++
			continue
		}
		filtered = append(filtered, m)
	}
	if droppedLowConf > 0 {
		p.Logger.Info("filtered low-confidence mappings", "count", droppedLowConf)
	}

	// 5. Gap analysis.
	an := analyzer.New(cat, filtered, extControls)
	findings, err := an.Analyze()
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	// 6. Roadmap: uncovered findings sorted by FinalScore descending.
	sortedRoadmap := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Status != model.StatusCovered {
			sortedRoadmap = append(sortedRoadmap, f)
		}
	}
	slices.SortFunc(sortedRoadmap, func(a, b model.Finding) int {
		return cmp.Compare(b.FinalScore, a.FinalScore) // descending
	})

	// 7. Report assembly + summary.
	rep := model.GapReport{
		Summary:  model.ExecutiveSummary{GeneratedAt: time.Now()},
		Findings: findings,
		Roadmap:  sortedRoadmap,
	}
	p.buildDomainSummaries(&rep, findings, cat)

	// 8. Release gate (optional).
	var gateReport *model.GateReport
	if cfg.ReleaseGate.Enabled && opts.GateFile != "" {
		gr, err := p.runGate(ctx, cfg, &rep, opts.GateFile, opts.GateMode, opts.EPSSEnrich)
		if err != nil {
			return nil, err
		}
		gateReport = gr
	}

	// 9. Snapshot load/diff/save.
	if !opts.NoSnapshot {
		if prev, _ := snapshot.Load(opts.SnapshotFile); prev != nil {
			delta := snapshot.Diff(rep, *prev)
			rep.Delta = &delta
		}
		if err := snapshot.Save(opts.SnapshotFile, &rep); err != nil {
			p.Logger.Warn("failed to save snapshot", "path", opts.SnapshotFile, "error", err)
		}
	}

	// 10. Report generation.
	finalFormat := opts.OutputFormat
	if finalFormat == "markdown" && cfg.Reporting.Format != "" {
		finalFormat = cfg.Reporting.Format
	}
	finalOutFile := opts.OutFile
	if finalOutFile == "stdout" && cfg.Reporting.Output != "" {
		finalOutFile = cfg.Reporting.Output
	}
	if err := report.Generate(rep, finalFormat, finalOutFile, opts.RoadmapLimit); err != nil {
		return nil, fmt.Errorf("generate report: %w", err)
	}

	// 11. Exit decision.
	result := &EvaluationResult{Report: rep, GateReport: gateReport, ExitCode: exitcodes.OK, ExitReason: ExitOK}
	if gateReport != nil && gateReport.OverallDecision == model.DecisionBlock {
		result.ExitCode = exitcodes.GateBlocked
		result.ExitReason = ExitGateBlocked
		return result, nil
	}
	if opts.FailAbove > 0 {
		for _, gap := range sortedRoadmap {
			if gap.FinalScore > opts.FailAbove {
				result.ExitCode = exitcodes.ComplianceFail
				result.ExitReason = ExitCompliance
				break
			}
		}
	}
	return result, nil
}

// runGate loads gate evidence, applies acceptance/EPSS enrichment, and evaluates.
func (p *EvaluationPipeline) runGate(ctx context.Context, cfg *config.Config, rep *model.GapReport, gateFile, gateMode, epssEnrich string) (*model.GateReport, error) {
	gateModeVal := gate.ResolveGateMode(cfg, gateMode)
	rg := releasegate.Gate{
		AssetContext:         cfg.ReleaseGate.AssetContext,
		CompensatingControls: cfg.ReleaseGate.CompensatingControls,
		RiskAppetite:         cfg.ReleaseGate.RiskAppetite,
		WarnAbove:            cfg.ReleaseGate.WarnAbove,
		AggregateLimit:       cfg.ReleaseGate.AggregateLimit,
		Mode:                 gateModeVal,
	}

	vdata, err := pathguard.SafeReadFile(gateFile)
	if err != nil {
		return nil, fmt.Errorf("read gate file: %w", err)
	}
	var vulnsFormat struct {
		Vulnerabilities []model.Vulnerability `yaml:"vulnerabilities"`
	}
	if err := yaml.Unmarshal(vdata, &vulnsFormat); err != nil {
		return nil, fmt.Errorf("parse gate vulnerabilities: %w", err)
	}

	vulns := gate.FilterAccepted(vulnsFormat.Vulnerabilities, cfg, p.opts.ConfigPath, p.Stderr)
	vulns = gate.ApplyEPSSEnrichment(vulns, cfg, epssEnrich, p.Stderr)

	gr := rg.Evaluate(vulns)
	rep.Gate = &gr
	switch gr.OverallDecision {
	case model.DecisionBlock:
		missingEpss := 0
		for _, v := range vulns {
			if v.EPSSScore == 0.0 {
				missingEpss++
			}
		}
		if missingEpss > 0 {
			p.Logger.Warn("vulnerabilities lacked EPSS scores and defaulted to worst-case (1.0)", "count", missingEpss)
			fmt.Fprintf(p.Stderr, "       Run 'wardex enrich epss %s' to fetch real probabilities from FIRST.org and sign the enrichment.\n", gateFile)
		}
	case model.DecisionWarn:
		p.Logger.Warn("risk threshold exceeded WarnAbove", "count", gr.WarnCount)
	case model.DecisionAllow:
	}
	return &gr, nil
}

// buildDomainSummaries aggregates per-domain coverage and maturity into rep.Summary.
func (p *EvaluationPipeline) buildDomainSummaries(rep *model.GapReport, findings []model.Finding, cat []model.CatalogControl) {
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

	for _, ds := range domainMap {
		if ds.TotalControls > 0 {
			ds.MaturityScore = ds.MaturityScore / float64(ds.TotalControls)
		}
		rep.Summary.DomainSummaries = append(rep.Summary.DomainSummaries, *ds)
	}

	rep.Summary.TotalControls = len(cat)
	for _, f := range findings {
		switch f.Status {
		case model.StatusCovered:
			rep.Summary.CoveredCount++
		case model.StatusPartial:
			rep.Summary.PartialCount++
		default:
			rep.Summary.GapCount++
		}
	}
	if rep.Summary.TotalControls > 0 {
		rep.Summary.GlobalCoverage = float64(rep.Summary.CoveredCount) / float64(rep.Summary.TotalControls) * 100.0
	}
}
