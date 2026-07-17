// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package config

import (
	"bytes"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

// getActor resolves the actor identity from environment variables.
func getActor() string {
	if a := os.Getenv("WARDEX_ACTOR"); a != "" {
		return a
	}
	if a := os.Getenv("GITHUB_ACTOR"); a != "" {
		return a
	}
	return os.Getenv("USER")
}

// ApplyProfile applies an RBAC profile override to the config.
// If the profile exists and the actor is authorized, the config's gate thresholds
// are overridden. Returns a descriptive message for CLI output.
func ApplyProfile(cfg *Config, profileName string, stderr *os.File) string {
	if profileName == "" {
		return ""
	}

	p, ok := cfg.Profiles[profileName]
	if !ok {
		return fmt.Sprintf("Warning: Profile %q not found. Using defaults.", profileName)
	}

	actor := getActor()
	allowed := len(p.AllowedActors) == 0
	for _, a := range p.AllowedActors {
		if a == "*" || a == actor {
			allowed = true
			break
		}
	}

	if !allowed {
		fmt.Fprintf(stderr, "[RBAC VIOLATION] Actor %q is not authorized for profile %q!\n[RBAC ENFORCEMENT] Override rejected. Falling back to strict baseline configuration.\n", actor, profileName)
		return ""
	}

	cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
	cfg.ReleaseGate.WarnAbove = p.WarnAbove
	return fmt.Sprintf("RBAC Verified. Profile %q loaded (RiskAppetite: %.2f)", profileName, p.RiskAppetite)
}

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

// NotificationConfig configures external notifications for CPL divergence events.
type NotificationConfig struct {
	DivergenceWebhook DivergenceWebhookConfig `yaml:"divergence_webhook"`
}

// DivergenceWebhookConfig configures the fire-and-forget webhook for CPL divergence alerts.
type DivergenceWebhookConfig struct {
	URL            string            `yaml:"url"`             // env-var resolved at runtime
	AuthEnv        string            `yaml:"auth_env"`        // env var name for Bearer token
	TimeoutSeconds int               `yaml:"timeout_seconds"` // default 5, max 30
	Headers        map[string]string `yaml:"headers,omitempty"`
}

// StateStoreConfig configures the persistent state store.
type StateStoreConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Dir             string `yaml:"dir"`              // default: ".wardex"
	RetentionDays   int    `yaml:"retention_days"`   // default: 90
	WORM            bool   `yaml:"worm"`              // enable WORM protection
}

type ProvenanceConfig struct {
	Enabled string            `yaml:"enabled"` // "noop" | "grpc" | "gleipnir-embedded"
	Address string            `yaml:"address"` // host:port for grpc driver
	Options map[string]string `yaml:"options"` // driver-specific options
}

type Config struct {
	ReleaseGate      ReleaseGate        `yaml:"release_gate"`
	AcceptanceConfig AcceptanceConfig   `yaml:"acceptance"`
	Reporting        ReportingConfig    `yaml:"reporting"`
	Profiles         map[string]Profile `yaml:"profiles"`
	CRA              CRAConfig          `yaml:"cra"`             // NEW in v2.0
	Notifications    NotificationConfig `yaml:"notifications"`   // NEW in v2.2 — CPL
	StateStore       StateStoreConfig   `yaml:"state_store"`     // NEW in v2.3 — persistent state
	Provenance       ProvenanceConfig   `yaml:"provenance"`      // NEW in v2.3 — provenance anchor
}

// Load reads and parses the configuration file. Returns an empty default if not found.
func Load(path string) (*Config, error) {
	safePathStr, err := cli.SafePath(path)
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
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.ReleaseGate.Mode == "" {
		cfg.ReleaseGate.Mode = "any"
	}

	return &cfg, nil
}
