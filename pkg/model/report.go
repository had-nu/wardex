// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

import "time"

// CoverageStatus represents the evaluation status of an Annex A control.
type CoverageStatus string

const (
	// StatusCovered indicates the control is fully met.
	StatusCovered CoverageStatus = "covered"
	// StatusPartial indicates the control is partially met but below the gate threshold.
	StatusPartial CoverageStatus = "partial"
	// StatusGap indicates the control is completely unmet.
	StatusGap CoverageStatus = "gap"
)

// GatePracticeStatus summarises the release-gate practice status for a control.
type GatePracticeStatus struct {
	PracticeID    string
	MaturityLevel int    // level inferred from the declared AssetContext
	MaturityLabel string // human-readable description of the level
	IsConfigured  bool
}

// Finding represents the analysis result for an Annex A control.
type Finding struct {
	Control           CatalogControl
	Status            CoverageStatus
	FinalScore        float64
	EffectiveMaturity float64 // Arithmetic mean of the covered controls (v1.8.0 fix)
	CoveredBy         []Mapping
	GapReasons        []string
	Recommendation    string
	GatePractice      *GatePracticeStatus // non-nil when the control has gate practices
}

// DomainSummary summarises the coverage and maturity of a domain.
type DomainSummary struct {
	Domain          string
	TotalControls   int
	CoveredCount    int
	PartialCount    int
	GapCount        int
	MaturityScore   float64
	CoveragePercent float64
}

// ExecutiveSummary is designed for management reviews.
type ExecutiveSummary struct {
	// Framework is the catalogue the run evaluated against, for example
	// "iso27001" or "nis2". Report generators use it for the document title.
	// An empty value means the run had no explicit framework, and generators
	// must say so rather than name a framework the run did not use.
	Framework string
	// FrameworkName is the human-readable catalogue name, for example
	// "ISO/IEC 27001:2022". Generators prefer it over Framework and fall back
	// to Framework when the caller did not supply a display name.
	FrameworkName string

	GeneratedAt     time.Time
	TotalControls   int
	CoveredCount    int
	PartialCount    int
	GapCount        int
	GlobalCoverage  float64
	DomainSummaries []DomainSummary
	TopCriticalGaps []Finding
	GateSummary     *GateReport // nil when --gate was not enabled
}

// Delta represents the change between the current run and the previous snapshot.
type Delta struct {
	SnapshotDate       time.Time
	CoverageChange     float64
	NewlyCovered       []string
	NewGaps            []string
	Unchanged          int
	GateMaturityChange int // change in the gate maturity level
}

// GapReport is the complete report.
type GapReport struct {
	Summary         ExecutiveSummary
	Findings        []Finding
	Roadmap         []Finding // Subset of gaps/partials, ordered by FinalScore descending
	Gate            *GateReport
	Delta           *Delta
	LayerDelta      *LayerDelta       `json:"layer_delta,omitempty"`
	AssetCompliance []AssetCompliance `json:"asset_compliance,omitempty"`
}
