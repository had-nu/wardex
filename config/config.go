// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package config

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/utils"
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

type GateLogConfig struct {
	Path    string   `yaml:"path"`    // default: "wardex-gate-audit.log"
	Forward []string `yaml:"forward"` // e.g. ["syslog", "enisa"]
	OnFail  string   `yaml:"on_fail"` // "warn" | "block"
}

// ENISAQueueConfig configures the local queue file for the ENISABackend stub.
// No data is transmitted — the queue is a local JSONL file awaiting operator dispatch.
type ENISAQueueConfig struct {
	Path string `yaml:"path"` // default: "wardex-enisa-queue.jsonl"
}

type ReportingConfig struct {
	Format     string          `yaml:"format"`
	Output     string          `yaml:"output"`
	GateLog    GateLogConfig   `yaml:"gate_log"`
	ENISAQueue ENISAQueueConfig `yaml:"enisa_queue"` // NEW in v2.0
}

type Profile struct {
	RiskAppetite  float64  `yaml:"risk_appetite"`
	WarnAbove     float64  `yaml:"warn_above"`
	AllowedActors []string `yaml:"allowed_actors"`
}

// Art14Config controls the CRA Article 14 notification artefact generation.
type Art14Config struct {
	// OutputDir is the directory where artefact JSON files are written.
	// Defaults to "." (working directory). In CI, set to a mounted persistent volume.
	OutputDir string `yaml:"output_dir"`

	// AwarenessSource determines the timestamp used as the Article 14 awareness timestamp.
	// "detection": time.Now() at wardex evaluate time (default).
	// "envelope":  actively_exploited_since from the vulnerability envelope (if set and earlier).
	AwarenessSource string `yaml:"awareness_source"` // "detection" | "envelope"

	// ProductName and ProductVersion pre-populate the notification artefact.
	// If empty, Wardex writes "[OPERATOR: complete before dispatch]" as the field value.
	ProductName    string `yaml:"product_name"`
	ProductVersion string `yaml:"product_version"`

	// KEVPath is the default path to a downloaded CISA KEV catalogue JSON snapshot.
	// When set, wardex evaluate will correlate the envelope against the KEV without
	// requiring the --kev flag on every invocation.
	KEVPath string `yaml:"kev_path"`

	// KEVMaxAgeDays emits a [WARN] if the KEV catalogue file mtime exceeds this value.
	// Defaults to 7. Set to 0 to disable the age check.
	KEVMaxAgeDays int `yaml:"kev_max_age_days"`
}

// CRAConfig groups all Cyber Resilience Act compliance settings.
type CRAConfig struct {
	Art14 Art14Config `yaml:"art14"`
}

type Config struct {
	ReleaseGate      ReleaseGate        `yaml:"release_gate"`
	AcceptanceConfig AcceptanceConfig   `yaml:"acceptance"`
	Reporting        ReportingConfig    `yaml:"reporting"`
	Profiles         map[string]Profile `yaml:"profiles"`
	CRA              CRAConfig          `yaml:"cra"` // NEW in v2.0
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
