// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

import "time"

type Asset struct {
	ID           string                      `yaml:"id" json:"id"`
	Name         string                      `yaml:"name" json:"name"`
	Type         string                      `yaml:"type" json:"type"` // application, database, network...
	Criticality  float64                     `yaml:"criticality" json:"criticality"` // C(α)
	Exposure     AssetExposureContext        `yaml:"exposure" json:"exposure"`
	Scope        []string                    `yaml:"scope,omitempty" json:"scope,omitempty"` // frameworks (iso27001, nis2...)
	Controls     []string                    `yaml:"controls" json:"controls"`       // IDs of ExistingControls applied to this asset
	CompControls []AssetCompensatingControl `yaml:"compensating_controls,omitempty" json:"compensating_controls,omitempty"`
	Owner        string                      `yaml:"owner,omitempty" json:"owner,omitempty"`
	Threats      []AssetThreat               `yaml:"threats,omitempty" json:"threats,omitempty"`
}

type AssetExposureContext struct {
	InternetFacing     bool   `yaml:"internet_facing" json:"internet_facing"`
	RequiresAuth       bool   `yaml:"requires_auth" json:"requires_auth"`
	NetworkZone        string `yaml:"network_zone,omitempty" json:"network_zone,omitempty"`
	DataClassification string `yaml:"data_classification,omitempty" json:"data_classification,omitempty"`
}

type AssetThreat struct {
	ID             string `yaml:"id" json:"id"`
	Scenario       string `yaml:"scenario" json:"scenario"`
	MitreTechnique string `yaml:"mitre_technique" json:"mitre_technique"`
	Likelihood     string `yaml:"likelihood" json:"likelihood"`
}

type AssetCompensatingControl struct {
	Type          string  `yaml:"type" json:"type"`
	Effectiveness float64 `yaml:"effectiveness" json:"effectiveness"` // Φ(α)
	Ref           string  `yaml:"ref,omitempty" json:"ref,omitempty"`
	ThreatRef     string  `yaml:"threat_ref,omitempty" json:"threat_ref,omitempty"`
}

type AssetCompliance struct {
	AssetID          string    `json:"asset_id"`
	AssetName        string    `json:"asset_name"`
	ComplianceScore  float64   `json:"compliance_score"` // 0.0 to 1.0
	Status           string    `json:"status"`           // compliant, partial, non_compliant
	MissingControls  []string  `json:"missing_controls"`
	LastAssessmentAt time.Time `json:"last_assessment_at"`
}

type LayerDelta struct {
	DocumentedCount  int      `json:"documented_count"`
	ImplementedCount int      `json:"implemented_count"`
	PolicyGap        []string `json:"policy_gap"`       // Documented \ Implemented (Paper Security)
	ImplementedOnly  []string `json:"implemented_only"` // Implemented \ Documented (Shadow Security)
	ActiveCoverage   []string `json:"active_coverage"`  // Documented ∩ Implemented
}
