// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

type ControlLayer string

const (
	LayerDocumented  ControlLayer = "documented"
	LayerImplemented ControlLayer = "implemented"
)

// ExistingControl representa um controle já implementado na organização.
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

// CatalogControl representa um controle da ISO 27001:2022 Annex A.
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

// Practice representa uma prática concreta associada a um controle Annex A.
// Para A.8.8: SCA scanner, release gate policy, SBOM generation.
type Practice struct {
	ID           string `yaml:"id"`
	Name         string `yaml:"name"`
	MinMaturity  int    `yaml:"min_maturity"`  // Maturidade mínima para cobertura válida
	GateRelevant bool   `yaml:"gate_relevant"` // true se esta prática corresponde a um release gate
}

// Evidence representa uma evidência declarada.
type Evidence struct {
	Type string `yaml:"type"`
	Ref  string `yaml:"ref"`
}

// Mapping representa a correlação entre um controle existente e um controle da Annex A.
type Mapping struct {
	ExistingControlID string   `yaml:"existing_control_id"`
	CatalogControlID  string   `yaml:"catalog_control_id"`
	Confidence        string   `yaml:"confidence"`
	MatchedDomains    []string `yaml:"matched_domains,omitempty"`
	MatchedKeywords   []string `yaml:"matched_keywords,omitempty"`
}
