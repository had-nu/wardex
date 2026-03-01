// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

// Vulnerability representa uma vulnerabilidade a ser avaliada pelo release gate.
type Vulnerability struct {
	CVEID     string  `yaml:"cve_id"`
	CVSSBase  float64 `yaml:"cvss_base"`
	EPSSScore float64 `yaml:"epss_score"`
	Component string  `yaml:"component"`
	Reachable bool    `yaml:"reachable"`
}

// AssetContext descreve o contexto do asset.
// Cada campo preenchido aumenta o nível de maturidade do gate inferido.
type AssetContext struct {
	Criticality    float64 `yaml:"criticality"` // 0.0–1.0: impacto de negócio se comprometido
	InternetFacing bool    `yaml:"internet_facing"`
	RequiresAuth   bool    `yaml:"requires_auth"` // Reduz exposure em 0.2 quando true
	DataClass      string  `yaml:"data_class"`    // "public" | "internal" | "confidential" | "restricted"
	Environment    string  `yaml:"environment"`   // "production" | "staging" | "development"
}

// CompensatingControl representa um controle que reduz exploitabilidade.
type CompensatingControl struct {
	Type          string  `yaml:"type"`          // "waf" | "network_segmentation" | "runtime_protection" | "ids"
	Effectiveness float64 `yaml:"effectiveness"` // 0.0–0.8: fração de redução de risco aplicada
	Justification string  `yaml:"justification"`
}

// RiskBreakdown expõe cada componente do cálculo para rastreabilidade.
type RiskBreakdown struct {
	CVSSBase           float64
	EPSSFactor         float64
	AdjustedScore      float64
	AssetCriticality   float64
	ExposureFactor     float64
	CompensatingEffect float64 // Efetividade combinada, clamped em 0.8
	FinalReleaseRisk   float64
}

// ReleaseDecision representa o resultado da avaliação de uma vulnerabilidade.
type ReleaseDecision struct {
	Vulnerability Vulnerability
	ReleaseRisk   float64
	RiskAppetite  float64
	Decision      string // "block" | "allow" | "warn"
	Breakdown     RiskBreakdown
	AuditTrail    string // Texto legível para auditoria
}

// GateReport agrega todas as decisões para um conjunto de vulnerabilidades.
type GateReport struct {
	OverallDecision   string // "block" | "allow"
	GateMaturityLevel int    // 1–5, inferido dos campos preenchidos
	Decisions         []ReleaseDecision
	BlockedCount      int
	AllowedCount      int
	WarnCount         int
	HighestRisk       float64
}
