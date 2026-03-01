package config

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
	"gopkg.in/yaml.v3"
)

type Organization struct {
	Name   string `yaml:"name"`
	Sector string `yaml:"sector"`
	Scope  string `yaml:"scope"`
}

type ControlWeight struct {
	Weight        float64 `yaml:"weight"`
	Justification string  `yaml:"justification"`
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

type Thresholds struct {
	FailAbove float64 `yaml:"fail_above"`
	WarnAbove float64 `yaml:"warn_above"`
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
	Format  string `yaml:"format"`
	Output  string `yaml:"output"`
	Verbose bool   `yaml:"verbose"`
}

type Config struct {
	Organization     Organization             `yaml:"organization"`
	DomainWeights    map[string]float64       `yaml:"domain_weights"`
	ControlWeights   map[string]ControlWeight `yaml:"control_weights"`
	ReleaseGate      ReleaseGate              `yaml:"release_gate"`
	Thresholds       Thresholds               `yaml:"thresholds"`
	AcceptanceConfig AcceptanceConfig         `yaml:"acceptance"`
	Reporting        ReportingConfig          `yaml:"reporting"`
}

// Load reads and parses the configuration file. Returns an empty default if not found.
func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Return defaults
		return &Config{
			ReleaseGate: ReleaseGate{Mode: "any", RiskAppetite: 10.0},
		}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
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
