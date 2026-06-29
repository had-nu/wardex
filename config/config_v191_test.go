package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigWithRemovedFields garante que YAMLs escritos para v1.9.0,
// contendo campos removidos em v1.9.1, continuam a carregar sem erro.
// Os campos removidos eram já silenciosamente ignorados em runtime; este
// teste codifica essa garantia para evitar regressão futura.
func TestLoadConfigWithRemovedFields(t *testing.T) {
	legacyYAML := `
organization:
  name: "Legacy Org"
  sector: "automotive"
  scope: "ISMS perimeter"

domain_weights:
  technological: 1.5
  organizational: 1.0

control_weights:
  CTRL-001:
    weight: 1.2
    justification: "legacy"

thresholds:
  fail_above: 0.5
  warn_above: 0.3

release_gate:
  enabled: true
  risk_appetite: 0.20
  warn_above: 0.12

  asset_context:
    data_class: "restricted"

reporting:
  format: "markdown"
  verbose: true
`
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "legacy-config.yaml")
	if err := os.WriteFile(path, []byte(legacyYAML), 0o600); err != nil {
		t.Fatalf("write legacy fixture: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("legacy config should load without error, got: %v", err)
	}
	if !cfg.ReleaseGate.Enabled {
		t.Error("ReleaseGate.Enabled should be true after load")
	}
	if cfg.ReleaseGate.RiskAppetite != 0.20 {
		t.Errorf("expected RiskAppetite 0.20, got %v", cfg.ReleaseGate.RiskAppetite)
	}
	if cfg.ReleaseGate.WarnAbove != 0.12 {
		t.Errorf("expected WarnAbove 0.12, got %v", cfg.ReleaseGate.WarnAbove)
	}
	if cfg.Reporting.Format != "markdown" {
		t.Errorf("expected Reporting.Format 'markdown', got %q", cfg.Reporting.Format)
	}
}
