// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/had-nu/wardex/v3/pkg/cli"
	"github.com/had-nu/wardex/v3/pkg/model"
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
func ApplyProfile(cfg *Config, profileName string, stderr io.Writer) string {
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

	// Classes carries per-risk-class overrides (L3). The class↔severity table
	// defines four exams ("integrity", "policy", "freshness", "active_exploit")
	// with severities "block" | "advisory" | "off". Example:
	//
	//	gate:
	//	  classes:
	//	    pr:
	//	      freshness: block
	//
	// PR-class freshness therefore hard-blocks instead of exiting 6.
	// Unknown class/exam/severity keys are rejected at gate runtime.
	Classes map[string]map[string]string `yaml:"classes"`

	// ForcedUpgrade arms the regulatory-deadline gate (L7). When armed, a
	// release can only be attested with Wardex's own evidence — valid seal,
	// intact chain, fresh EPSS/KEV. A tripwire disarms the gate after
	// DefaultForcedUpgradeTripwireFailures consecutive evidence-refresh
	// failures so evidence absence never freezes the pipeline forever.
	// Absent or disabled → current behaviour is unchanged (L3/L4 additivity).
	ForcedUpgrade *ForcedUpgradeConfig `yaml:"forced_upgrade"`
}

// DefaultForcedUpgradeTripwireFailures is the default tripwire threshold N
// (P11): consecutive evidence-refresh failures after which the forced_upgrade
// gate auto-disarms and falls back to policy evaluation.
const DefaultForcedUpgradeTripwireFailures = 5

// ForcedUpgradeConfig configures the forced_upgrade regulatory gate (L7).
type ForcedUpgradeConfig struct {
	Enabled bool `yaml:"enabled"`

	// Deadline is the regulatory milestone this gate targets (audit-only), e.g.
	// "2026-09-14" for the CRA Art. 14 staged obligations. The gate blocks on
	// attestation evidence, not on wall-clock time.
	Deadline string `yaml:"deadline"`

	// TripwireFailures is the disarm threshold N. Zero/negative selects
	// DefaultForcedUpgradeTripwireFailures.
	TripwireFailures int `yaml:"tripwire_failures"`
}

// Tripwire returns the effective disarm threshold N.
func (f *ForcedUpgradeConfig) Tripwire() int {
	if f == nil || f.TripwireFailures < 1 {
		return DefaultForcedUpgradeTripwireFailures
	}
	return f.TripwireFailures
}

// Gate class and exam identifiers (L3). Keep in sync with
// pkg/orchestrator.resolveClassProfile.
const (
	// ClassPR is the pull-request CI class: no release path.
	ClassPR = "pr"
	// ClassDeploy is the release/deploy class (default, current behaviour).
	ClassDeploy = "deploy"
	// ClassNightly is the scheduled/nightly audit class: reporting focus.
	ClassNightly = "nightly"

	// Exam identifiers.
	ExamIntegrity     = "integrity"
	ExamPolicy        = "policy"
	ExamFreshness     = "freshness"
	ExamActiveExploit = "active_exploit"
)

// Severity values for the class exams.
const (
	SevBlock    = "block"    // hard stop with the exam's exit code
	SevAdvisory = "advisory" // warn; exit 6 for freshness, otherwise continue
	SevOff      = "off"      // report only; never blocks
)

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
	Format     string           `yaml:"format"`
	Output     string           `yaml:"output"`
	GateLog    GateLogConfig    `yaml:"gate_log"`
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

	// SupportPeriod is the number of years for which the manufacturer supports
	// vulnerabilities in the product, per Article 13(8).
	//
	// The Regulation sets a floor rather than a single figure: at least five
	// years, and where the product is expected to be in use for less than five
	// years, the support period corresponds to that expected use time. A value
	// below five years is therefore not automatically a defect, which is why the
	// reason field exists and why the check below warns rather than blocks.
	SupportPeriod SupportPeriodConfig `yaml:"support_period"`
}

// SupportPeriodConfig records the Article 13(8) support period and its rationale.
type SupportPeriodConfig struct {
	// Years is the support period. Zero means it has not been set.
	Years int `yaml:"years"`

	// Justification records what was taken into account when the period was set.
	// Article 13(8) lists the factors: reasonable user expectations, the nature
	// of the product including its intended purpose, Union law determining the
	// lifetime of the product, the support periods of comparable products, the
	// availability of the operating environment, the support periods of
	// integrated components, and any guidance from ADCO or the Commission.
	// Annex VII point 4 requires this to be in the technical documentation, so a
	// support period without a reason is not a complete record.
	Justification string `yaml:"justification"`

	// VDPReference is the vulnerability disclosure policy the manufacturer
	// publishes. Annex I Part II point (5) requires a policy on coordinated
	// vulnerability disclosure to be in place and enforced.
	VDPReference string `yaml:"vdp_reference"`

	// ExpectedUseIsShorterThanFiveYears records that the product is expected to
	// be in use for less than five years. It is set rather than inferred from
	// Years, because a short period below the floor is only correct when this is
	// true, and the two facts should not have to be derived from each other.
	ExpectedUseIsShorterThanFiveYears bool `yaml:"expected_use_shorter_than_five_years"`

	// SBOMPath is where a software bill of materials is expected. Annex VII
	// point 8 makes the SBOM producible on a reasoned request from a market
	// surveillance authority, so its absence is a warning rather than a stop.
	SBOMPath string `yaml:"sbom_path"`
}

// MinimumSupportPeriodYears is the floor Article 13(8) sets.
const MinimumSupportPeriodYears = 5

// ValidateSupportPeriod applies the Article 13(8) rule and returns warnings
// rather than errors.
//
// The rule has an exception, and enforcing the floor without it would report a
// short-lived product as non-compliant when the Regulation expressly allows the
// shorter period. The alternative — enforcing nothing — would let a five-year
// product ship with no support period recorded at all.
func (c CRAConfig) ValidateSupportPeriod() []string {
	var warnings []string

	if c.SupportPeriod.Years == 0 {
		warnings = append(warnings,
			"cra.support_period.years is not set; Article 13(8) requires a support period and "+
				"Annex VII point 4 requires the information behind it to be in the technical documentation")
		return warnings
	}

	if c.SupportPeriod.Years < 0 {
		warnings = append(warnings,
			fmt.Sprintf("cra.support_period.years is %d, which is not a duration", c.SupportPeriod.Years))
		return warnings
	}

	if c.SupportPeriod.Years < MinimumSupportPeriodYears && !c.SupportPeriod.ExpectedUseIsShorterThanFiveYears {
		warnings = append(warnings,
			fmt.Sprintf("cra.support_period.years is %d; Article 13(8) requires at least %d years "+
				"unless the product is expected to be in use for less than that, which is recorded "+
				"by setting cra.support_period.expected_use_shorter_than_five_years",
				c.SupportPeriod.Years, MinimumSupportPeriodYears))
	}

	if strings.TrimSpace(c.SupportPeriod.Justification) == "" {
		warnings = append(warnings,
			"cra.support_period.justification is empty; Annex VII point 4 requires the information "+
				"taken into account to determine the support period")
	}

	if strings.TrimSpace(c.SupportPeriod.VDPReference) == "" {
		warnings = append(warnings,
			"cra.support_period.vdp_reference is empty; Annex I Part II point (5) requires a policy "+
				"on coordinated vulnerability disclosure to be in place and enforced")
	}

	return warnings
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
	Enabled       bool   `yaml:"enabled"`
	Dir           string `yaml:"dir"`            // default: ".wardex"
	RetentionDays int    `yaml:"retention_days"` // default: 90
	WORM          bool   `yaml:"worm"`           // enable WORM protection
}

type ProvenanceConfig struct {
	Enabled string            `yaml:"enabled"` // "noop" | "grpc" | "gleipnir-embedded"
	Address string            `yaml:"address"` // host:port for grpc driver
	Options map[string]string `yaml:"options"` // driver-specific options
}

type Config struct {
	ConfigSchemaVersion int                `yaml:"config_schema_version"` // NEW in v2.6
	ReleaseGate         ReleaseGate        `yaml:"release_gate"`
	AcceptanceConfig    AcceptanceConfig   `yaml:"acceptance"`
	Reporting           ReportingConfig    `yaml:"reporting"`
	Profiles            map[string]Profile `yaml:"profiles"`
	CRA                 CRAConfig          `yaml:"cra"`           // NEW in v2.0
	Notifications       NotificationConfig `yaml:"notifications"` // NEW in v2.2 — CPL
	StateStore          StateStoreConfig   `yaml:"state_store"`   // NEW in v2.3 — persistent state
	Provenance          ProvenanceConfig   `yaml:"provenance"`    // NEW in v2.3 — provenance anchor
}

// Load reads and parses the configuration file. Returns an empty default if not found.
func Load(path string) (*Config, error) {
	data, err := cli.SafeReadFile(path)
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

	if err := MigrateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
