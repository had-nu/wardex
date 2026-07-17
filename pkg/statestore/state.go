// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package statestore

import (
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// StateVersion is the current state format version.
const StateVersion = "1.0"

// State represents the consolidated cross-execution state.
type State struct {
	Version       string          `json:"version"`
	LastRun       time.Time       `json:"last_run"`
	LastDecision  model.Decision  `json:"last_decision"`
	LastRisk      float64         `json:"last_risk"`
	RunCount      int             `json:"run_count"`
	Trend         []TrendPoint    `json:"trend"`
	ActiveAccepts int             `json:"active_accepts"`
	ExpiringSoon  []string        `json:"expiring_soon"`
	ConfigHash    string          `json:"config_hash"`
	TrustRootSig  string          `json:"trust_root_sig"`
}

// TrendPoint is a single data point in the risk trend.
type TrendPoint struct {
	Date      time.Time      `json:"date"`
	Risk      float64        `json:"risk"`
	Decision  model.Decision `json:"decision"`
	VulnCount int            `json:"vuln_count"`
}

// TrendDirection indicates whether risk is improving or worsening.
type TrendDirection string

const (
	TrendImproving TrendDirection = "improving"
	TrendWorsening TrendDirection = "worsening"
	TrendStable    TrendDirection = "stable"
)

// TrendAnalysis is the result of trend analysis over historical data.
type TrendAnalysis struct {
	Direction    TrendDirection `json:"direction"`
	AverageRisk  float64        `json:"average_risk"`
	MinRisk      float64        `json:"min_risk"`
	MaxRisk      float64        `json:"max_risk"`
	TotalRuns    int            `json:"total_runs"`
	AllowCount   int            `json:"allow_count"`
	WarnCount    int            `json:"warn_count"`
	BlockCount   int            `json:"block_count"`
	OldestRun    time.Time      `json:"oldest_run"`
	NewestRun    time.Time      `json:"newest_run"`
	RiskDelta    float64        `json:"risk_delta"` // newest - oldest
}

// EmptyState returns a fresh State with defaults.
func EmptyState() *State {
	return &State{
		Version:      StateVersion,
		LastDecision: model.DecisionAllow,
		Trend:        make([]TrendPoint, 0),
		ExpiringSoon: make([]string, 0),
	}
}
