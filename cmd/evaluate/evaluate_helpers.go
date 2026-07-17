package evaluate

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/config"
	"github.com/had-nu/wardex/v2/pkg/trust"
	"gopkg.in/yaml.v3"
)

// loadEvalConfig loads the eval configuration from a sealed (.wexstate) or legacy (.yaml) config file,
// applies optional RBAC profile overrides, and returns the resolved config.
// Callers should check for a non-nil error and call exitFunc/return accordingly.
func loadEvalConfig(configPath string, strict bool, profileName string) (*config.Config, error) {
	var cfg *config.Config

	if trust.IsWexStatePath(configPath) {
		state, err := trust.LoadWexState(configPath)
		if err != nil {
			return nil, fmt.Errorf("load sealed config: %w", err)
		}

		ref := trust.ResolveTrustStoreRef("", "")
		if state.TrustStoreRef != "" {
			ref = trust.ResolveTrustStoreRef("", state.TrustStoreRef)
		}
		storeData, err := trust.FetchTrustStore(ref)
		if err != nil {
			return nil, fmt.Errorf("fetch trust store: %w", err)
		}
		store, err := trust.LoadStoreFromBytes(storeData)
		if err != nil {
			return nil, fmt.Errorf("parse trust store: %w", err)
		}
		if err := trust.VerifySeal(state, store, storeData); err != nil {
			return nil, fmt.Errorf("seal integrity: %w", err)
		}

		fmt.Fprintf(stderr, "[INFO] Sealed config verified — signed by %s (%s) at %s\n",
			state.SealedBy, state.SealedByKeyID, state.SealedAt.Format("2006-01-02 15:04 UTC"))

		cfg = &config.Config{}
		if err := yaml.Unmarshal([]byte(state.Payload), cfg); err != nil {
			return nil, fmt.Errorf("parse sealed payload: %w", err)
		}
		if cfg.ReleaseGate.Mode == "" {
			cfg.ReleaseGate.Mode = "any"
		}
	} else {
		if strict {
			return nil, fmt.Errorf("[STRICT ENFORCEMENT] Unsealed configuration rejected. Use 'wardex config seal' to govern this policy")
		}
		if isCI() {
			fmt.Fprintf(stderr, "[WARN] Using unsealed config. In production, use 'wardex config seal' for non-repudiation.\n")
		}
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			fmt.Fprintf(stderr, "Warning: failed to load config from %s: %v\n", configPath, err)
			cfg = &config.Config{}
		}
	}

	if msg := config.ApplyProfile(cfg, profileName, stderr); msg != "" {
		fmt.Fprintf(stderr, "[INFO] %s\n", msg)
	}

	return cfg, nil
}

// isCI detects common CI environment variables.
func isCI() bool {
	ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI"}
	for _, v := range ciVars {
		if strings.TrimSpace(os.Getenv(v)) != "" {
			return true
		}
	}
	return false
}

// formatDuration structures durations for CLI output.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "passed"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h >= 24 {
		return fmt.Sprintf("%dd %dh", h/24, h%24)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

// collectCLIOverrides collects CLI flags that override config values.
// These are recorded in the audit log as cli_overrides for CPL provenance.
func collectCLIOverrides() map[string]string {
	overrides := make(map[string]string)
	if gateMode != "any" {
		overrides["gate-mode"] = gateMode
	}
	if failAbove > 0 {
		overrides["fail-above"] = fmt.Sprintf("%.1f", failAbove)
	}
	if epssEnrich != "" {
		overrides["epss-enrichment"] = epssEnrich
	}
	if profileName != "" {
		overrides["profile"] = profileName
	}
	if strict {
		overrides["strict"] = "true"
	}
	if dryRun {
		overrides["dry-run"] = "true"
	}
	return overrides
}
