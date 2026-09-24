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
	"strings"
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
	"github.com/had-nu/wardex/v2/pkg/ui"
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
	Progress      ui.ProgressReporter
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
	Config   *config.Config
	Logger   *slog.Logger
	Stderr   io.Writer
	Progress ui.ProgressReporter
	opts     EvaluationOptions
}

// NewEvaluationPipeline builds the pipeline from the given options.
func NewEvaluationPipeline(opts EvaluationOptions) *EvaluationPipeline {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.Progress == nil {
		opts.Progress = ui.NoopProgressReporter{}
	}
	return &EvaluationPipeline{Logger: opts.Logger, Stderr: opts.Stderr, Progress: opts.Progress, opts: opts}
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
	p.Progress = opts.Progress
	if p.Progress == nil {
		p.Progress = ui.NoopProgressReporter{}
	}

	// 1. Load config (lenient: warn and continue on failure).
	p.report(1, "Loading configuration", "RUNNING", "")
	configDetail := "configuration loaded"
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		configDetail = "using defaults after load error"
		p.Logger.Warn("failed to load config; continuing with defaults", "path", opts.ConfigPath, "error", err)
		cfg = &config.Config{}
	}
	p.Config = cfg
	p.report(1, "Loading configuration", "DONE", configDetail)

	if msg := config.ApplyProfile(cfg, opts.ProfileName, p.Stderr); msg != "" {
		p.Logger.Info(msg)
	}

	// 2. Load external controls.
	p.report(2, "Loading controls", "RUNNING", "")
	extControls, err := ingestion.LoadMany(opts.Inputs)
	if err != nil {
		p.report(2, "Loading controls", "FAILED", err.Error())
		return nil, fmt.Errorf("load controls: %w", err)
	}
	p.report(2, "Loading controls", "DONE", fmt.Sprintf("%d input file(s)", len(opts.Inputs)))

	// 3. Load catalog + correlate.
	p.report(3, "Matching framework controls", "RUNNING", "")
	cat, err := catalog.Load(opts.Framework)
	if err != nil {
		p.report(3, "Matching framework controls", "FAILED", err.Error())
		p.Logger.Info("use --framework to select a supported compliance framework")
		return nil, fmt.Errorf("load framework catalog %q: %w", opts.Framework, err)
	}
	corr := correlator.New(cat)
	mappings, err := corr.Correlate(extControls)
	if err != nil {
		p.report(3, "Matching framework controls", "FAILED", err.Error())
		return nil, fmt.Errorf("correlation failed: %w", err)
	}
	p.report(3, "Matching framework controls", "DONE", fmt.Sprintf("%d mapping(s)", len(mappings)))

	// 4. Filter mappings and analyse control coverage.
	p.report(4, "Computing gaps and coverage", "RUNNING", "")
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
		p.report(4, "Computing gaps and coverage", "FAILED", err.Error())
		return nil, fmt.Errorf("analysis failed: %w", err)
	}
	p.report(4, "Computing gaps and coverage", "DONE", fmt.Sprintf("%d finding(s)", len(findings)))

	// 6. Roadmap: uncovered findings sorted by FinalScore descending.
	p.report(5, "Building roadmap and summary", "RUNNING", "")
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
	p.report(5, "Building roadmap and summary", "DONE", fmt.Sprintf("%d roadmap item(s)", len(sortedRoadmap)))

	// 8. Release gate (optional).
	var gateReport *model.GateReport
	p.report(6, "Evaluating release gate", "RUNNING", "")
	if cfg.ReleaseGate.Enabled && opts.GateFile != "" {
		gr, err := p.runGate(ctx, cfg, &rep, opts.GateFile, opts.GateMode, opts.EPSSEnrich)
		if err != nil {
			p.report(6, "Evaluating release gate", "FAILED", err.Error())
			return nil, err
		}
		gateReport = gr
		p.report(6, "Evaluating release gate", "DONE", strings.ToUpper(string(gr.OverallDecision)))
	} else {
		p.report(6, "Evaluating release gate", "SKIPPED", "not requested")
	}

	// 9. Snapshot load/diff/save.
	p.report(7, "Processing snapshot", "RUNNING", "")
	if !opts.NoSnapshot {
		if prev, _ := snapshot.Load(opts.SnapshotFile); prev != nil {
			delta := snapshot.Diff(rep, *prev)
			rep.Delta = &delta
		}
		if err := snapshot.Save(opts.SnapshotFile, &rep); err != nil {
			p.Logger.Warn("failed to save snapshot", "path", opts.SnapshotFile, "error", err)
		}
		p.report(7, "Processing snapshot", "DONE", "snapshot saved")
	} else {
		p.report(7, "Processing snapshot", "SKIPPED", "disabled")
	}

	// 10. Report generation.
	p.report(8, "Generating report", "RUNNING", "")
	finalFormat := opts.OutputFormat
	if finalFormat == "markdown" && cfg.Reporting.Format != "" {
		finalFormat = cfg.Reporting.Format
	}
	finalOutFile := opts.OutFile
	if finalOutFile == "stdout" && cfg.Reporting.Output != "" {
		finalOutFile = cfg.Reporting.Output
	}
	if err := report.Generate(rep, finalFormat, finalOutFile, opts.RoadmapLimit); err != nil {
		p.report(8, "Generating report", "FAILED", err.Error())
		return nil, fmt.Errorf("generate report: %w", err)
	}
	p.report(8, "Generating report", "DONE", finalFormat)

	// 11. Exit decision.
	p.report(9, "Determining release decision", "RUNNING", "")
	result := &EvaluationResult{Report: rep, GateReport: gateReport, ExitCode: exitcodes.OK, ExitReason: ExitOK}
	if gateReport != nil && gateReport.OverallDecision == model.DecisionBlock {
		result.ExitCode = exitcodes.GateBlocked
		result.ExitReason = ExitGateBlocked
	} else if opts.FailAbove > 0 {
		for _, gap := range sortedRoadmap {
			if gap.FinalScore > opts.FailAbove {
				result.ExitCode = exitcodes.ComplianceFail
				result.ExitReason = ExitCompliance
				break
			}
		}
	}
	decision := "PASS"
	if gateReport != nil {
		decision = strings.ToUpper(string(gateReport.OverallDecision))
	} else if result.ExitReason != ExitOK {
		decision = "FAIL"
	}
	p.report(9, "Determining release decision", "DONE", decision)
	return result, nil
}

func (p *EvaluationPipeline) report(number int, name, status, detail string) {
	if p.Progress == nil {
		return
	}
	p.Progress.Report(ui.PhaseEvent{
		Number: number,
		Name:   name,
		Status: status,
		Detail: detail,
	})
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
