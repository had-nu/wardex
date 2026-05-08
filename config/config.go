// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package config

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/utils"
	"gopkg.in/yaml.v3"
)

type ReleaseGate struct {
	Enabled              bool                        `yaml:"enabled"`
	Mode                 string                      `yaml:"mode"` // "any" | "aggregate"
	RiskAppetite         float64                     `yaml:"risk_appetite"`
	WarnAbove            float64                     `yaml:"warn_above"`
	AggregateLimit       float64                     `yaml:"aggregate_limit"`
	AssetContext         model.AssetContext          `yaml:"asset_context"`
	CompensatingControls []model.CompensatingControl `yaml:"compensating_controls"`
}

type Limits struct {
	MaxAcceptanceDays     int `yaml:"max_acceptance_days"`
	MinJustificationChars int `yaml:"min_justification_chars"`
	MaxReportAgeHours     int `yaml:"max_report_age_hours"`
}

type AcceptanceConfig struct {
	SigningSecretFile          string   `yaml:"signing_secret_file"`
	Limits                     Limits   `yaml:"limits"`
	BannedJustificationPhrases []string `yaml:"banned_justification_phrases"`
}

type ReportingConfig struct {
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

type Profile struct {
	RiskAppetite  float64  `yaml:"risk_appetite"`
	WarnAbove     float64  `yaml:"warn_above"`
	AllowedActors []string `yaml:"allowed_actors"`
}

type Config struct {
	ReleaseGate      ReleaseGate        `yaml:"release_gate"`
	AcceptanceConfig AcceptanceConfig   `yaml:"acceptance"`
	Reporting        ReportingConfig    `yaml:"reporting"`
	Profiles         map[string]Profile `yaml:"profiles"`
}

// Load reads and parses the configuration file. Returns an empty default if not found.
func Load(path string) (*Config, error) {
	cwd, _ := os.Getwd()
	safePathStr, err := utils.SafePath(cwd, path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(safePathStr) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults
			return &Config{
				ReleaseGate: ReleaseGate{Mode: "any", RiskAppetite: 0.0},
			}, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.ReleaseGate.Mode == "" {
		cfg.ReleaseGate.Mode = "any"
	}

	return &cfg, nil
}
