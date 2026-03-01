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

// GatePracticeStatus resume o estado da prática de release gate para um controle.
type GatePracticeStatus struct {
	PracticeID    string
	MaturityLevel int    // nível inferido do AssetContext declarado
	MaturityLabel string // descrição humana do nível
	IsConfigured  bool
}

// Finding representa o resultado da análise de um controle da Annex A.
type Finding struct {
	Control        CatalogControl
	Status         CoverageStatus
	FinalScore     float64
	CoveredBy      []Mapping
	GapReasons     []string
	Recommendation string
	GatePractice   *GatePracticeStatus // não-nil se o controle tem práticas de gate
}

// DomainSummary resume a cobertura e maturidade de um domínio.
type DomainSummary struct {
	Domain          string
	TotalControls   int
	CoveredCount    int
	PartialCount    int
	GapCount        int
	MaturityScore   float64
	CoveragePercent float64
}

// ExecutiveSummary é desenhado para management reviews.
type ExecutiveSummary struct {
	GeneratedAt     time.Time
	TotalControls   int
	CoveredCount    int
	PartialCount    int
	GapCount        int
	GlobalCoverage  float64
	DomainSummaries []DomainSummary
	TopCriticalGaps []Finding
	GateSummary     *GateReport // nil se --gate não foi ativado
}

// Delta representa a variação entre a execução atual e o snapshot anterior.
type Delta struct {
	SnapshotDate       time.Time
	CoverageChange     float64
	NewlyCovered       []string
	NewGaps            []string
	Unchanged          int
	GateMaturityChange int // variação do nível de maturidade do gate
}

// GapReport é o relatório completo.
type GapReport struct {
	Summary  ExecutiveSummary
	Findings []Finding
	Roadmap  []Finding // Subset de gaps/partials, ordenado por FinalScore desc
	Gate     *GateReport
	Delta    *Delta
}
