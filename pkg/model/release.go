// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

import "time"

// Vulnerability represents a vulnerability to be evaluated by the release gate.
type Vulnerability struct {
	CVEID     string  `yaml:"cve_id"`
	CVSSBase  float64 `yaml:"cvss_base"`
	EPSSScore float64 `yaml:"epss_score"`
	Component string  `yaml:"component"`
	Reachable bool    `yaml:"reachable"`
	// NEW in v2.0 — CRA Article 14 active exploitation classification
	ActivelyExploited      bool      `yaml:"actively_exploited,omitempty"`
	ActivelyExploitedSince time.Time `yaml:"actively_exploited_since,omitempty"`
	ExploitedSource        string    `yaml:"exploited_source,omitempty"` // e.g. "cisa-kev", "manual"
}

// VulnerabilityEnvelope wraps vulnerabilities with provenance metadata.
type VulnerabilityEnvelope struct {
	ConvertedBy     string          `yaml:"converted_by,omitempty"`
	Vulnerabilities []Vulnerability `yaml:"vulnerabilities"`
	// NEW in v2.0 — timestamp of when the envelope was last evaluated
	EvaluatedAt time.Time `yaml:"evaluated_at,omitempty"`
}

// AssetContext describes the asset context.
// Each populated field raises the inferred gate maturity level.
type AssetContext struct {
	Criticality    float64 `yaml:"criticality"` // 0.0–1.0: business impact if compromised
	InternetFacing bool    `yaml:"internet_facing"`
	RequiresAuth   bool    `yaml:"requires_auth"` // Reduces exposure by 0.2 when true
	Environment    string  `yaml:"environment"`   // "production" | "staging" | "development"
}

// CompensatingControl represents a control that reduces exploitability.
type CompensatingControl struct {
	Type          string  `yaml:"type"`          // "waf" | "network_segmentation" | "runtime_protection" | "ids"
	Effectiveness float64 `yaml:"effectiveness"` // 0.0–0.8: risk reduction fraction applied
	Justification string  `yaml:"justification"`
}

// RiskBreakdown exposes each component of the calculation for traceability.
type RiskBreakdown struct {
	CVSSBase           float64
	EPSSFactor         float64
	AdjustedScore      float64
	AssetCriticality   float64
	ExposureFactor     float64
	CompensatingEffect float64 // Combined effectiveness, clamped at 0.8
	FinalReleaseRisk   float64
}

// Decision is the result of a gate evaluation.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionBlock Decision = "block"
	DecisionWarn  Decision = "warn"
)

// ReleaseDecision represents the result of a vulnerability evaluation.
type ReleaseDecision struct {
	Vulnerability Vulnerability
	ReleaseRisk   float64
	RiskAppetite  float64
	Decision      Decision
	Breakdown     RiskBreakdown
	AuditTrail    string // Human-readable text for auditing
}

// GateReport aggregates all decisions for a set of vulnerabilities.
type GateReport struct {
	OverallDecision   Decision
	GateMaturityLevel int // 1–5, inferred from the populated fields
	Decisions         []ReleaseDecision
	BlockedCount      int
	AllowedCount      int
	WarnCount         int
	HighestRisk       float64
}
