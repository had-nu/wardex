package evaluate

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/had-nu/wardex/v2/config"
	pathguard "github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/had-nu/wardex/v2/pkg/utils"
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

	// RBAC profile override
	if profileName != "" {
		if p, ok := cfg.Profiles[profileName]; ok {
			actor := os.Getenv("WARDEX_ACTOR")
			if actor == "" {
				actor = os.Getenv("GITHUB_ACTOR")
			}
			if actor == "" {
				actor = os.Getenv("USER")
			}
			allowed := len(p.AllowedActors) == 0
			for _, a := range p.AllowedActors {
				if a == "*" || a == actor {
					allowed = true
					break
				}
			}
			if !allowed {
				fmt.Fprintf(stderr, "[RBAC VIOLATION] Actor %q is not authorized for profile %q!\n[RBAC ENFORCEMENT] Override rejected. Falling back to strict baseline configuration.\n", actor, profileName)
			} else {
				cfg.ReleaseGate.RiskAppetite = p.RiskAppetite
				cfg.ReleaseGate.WarnAbove = p.WarnAbove
				fmt.Fprintf(stderr, "[INFO] RBAC Verified. Profile %q loaded (RiskAppetite: %.2f)\n", profileName, p.RiskAppetite)
			}
		} else {
			fmt.Fprintf(stderr, "Warning: Profile %q not found. Using defaults.\n", profileName)
		}
	}

	return cfg, nil
}

// loadEvidence reads and parses a vulnerability evidence file, returning the vulnerabilities list
// and the SHA-256 hash of the file content. It validates optional provenance metadata.
func loadEvidence(gateFile, cwd string, strict bool) ([]model.Vulnerability, string, error) {
	safeGatePath, err := pathguard.ValidateInputPath(cwd, gateFile)
	if err != nil {
		return nil, "", fmt.Errorf("evidence path: %w", err)
	}
	vdata, err := os.ReadFile(safeGatePath) // #nosec G304
	if err != nil {
		return nil, "", fmt.Errorf("read evidence file: %w", err)
	}

	evidenceHash := ""
	if h, err := utils.HashFile(safeGatePath); err == nil {
		evidenceHash = "sha256:" + h
	}

	var vulnsEnvelope model.VulnerabilityEnvelope
	if err := yaml.Unmarshal(vdata, &vulnsEnvelope); err != nil {
		return nil, "", fmt.Errorf("parse evidence file: %w", err)
	}

	if vulnsEnvelope.ConvertedBy == "" {
		if strict {
			return nil, "", fmt.Errorf("--strict requires canonicalised evidence. Run 'wardex convert' before evaluate")
		}
		fmt.Fprintf(stderr, "[WARN] Evidence file has no 'converted_by' field. Run 'wardex convert' to canonicalise scanner output. Proceeding with defaults (reachable=true, epss=1.0).\n")
	}

	return vulnsEnvelope.Vulnerabilities, evidenceHash, nil
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
