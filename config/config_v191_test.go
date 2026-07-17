package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigWithRemovedFields verifica que YAMLs com campos desconhecidos
// são agora rejeitados devido a KnownFields(true). Antes da v2.3.0, campos
// removidos eram silenciosamente ignorados.
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

	_, err := Load(path)
	if err == nil {
		t.Fatal("config with unknown fields should be rejected with KnownFields(true)")
	}
}
