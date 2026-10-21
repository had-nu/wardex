// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

// ControlLayer distinguishes documented policies from implemented controls
// in the compliance gap analysis.
type ControlLayer string

const (
	// LayerDocumented identifies a control declared in security policies but
	// not yet confirmed as operationally implemented (paper security risk).
	LayerDocumented ControlLayer = "documented"
	// LayerImplemented identifies a control that is confirmed as operationally
	// active, regardless of whether a formal policy exists.
	LayerImplemented ControlLayer = "implemented"
)

// ExistingControl represents a control already implemented in the organisation.
type ExistingControl struct {
	ID                  string       `yaml:"id"`
	Name                string       `yaml:"name"`
	Description         string       `yaml:"description,omitempty"`
	Framework           string       `yaml:"framework,omitempty"`
	Domains             []string     `yaml:"domains,omitempty"`
	Maturity            int          `yaml:"maturity"`
	Layer               ControlLayer `yaml:"layer"`
	Effectiveness       float64      `yaml:"effectiveness,omitempty"`
	ReviewRequired      bool         `yaml:"review_required,omitempty"`
	Evidences           []Evidence   `yaml:"evidences,omitempty"`
	ContextWeight       float64      `yaml:"context_weight,omitempty"`
	WeightJustification string       `yaml:"weight_justification,omitempty"`
}

// CatalogControl represents a control from ISO/IEC 27001:2022 Annex A.
type CatalogControl struct {
	ID            string     `yaml:"id"`
	Name          string     `yaml:"name"`
	Domain        string     `yaml:"domain"`
	Domains       []string   `yaml:"domains,omitempty"`
	Keywords      []string   `yaml:"keywords,omitempty"`
	EvidenceTypes []string   `yaml:"evidence_types,omitempty"`
	BaseScore     float64    `yaml:"base_score"`
	Practices     []Practice `yaml:"practices,omitempty"`
}

// Practice represents a concrete practice associated with an Annex A control.
// For A.8.8: SCA scanner, release gate policy, SBOM generation.
type Practice struct {
	ID           string `yaml:"id"`
	Name         string `yaml:"name"`
	MinMaturity  int    `yaml:"min_maturity"`  // Minimum maturity for valid coverage
	GateRelevant bool   `yaml:"gate_relevant"` // true when this practice corresponds to a release gate
}

// Evidence represents declared evidence.
type Evidence struct {
	Type string `yaml:"type"`
	Ref  string `yaml:"ref"`
}

// Mapping represents the correlation between an existing control and an Annex A control.
type Mapping struct {
	ExistingControlID string   `yaml:"existing_control_id"`
	CatalogControlID  string   `yaml:"catalog_control_id"`
	Confidence        string   `yaml:"confidence"`
	MatchedDomains    []string `yaml:"matched_domains,omitempty"`
	MatchedKeywords   []string `yaml:"matched_keywords,omitempty"`
}
