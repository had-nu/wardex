package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/config"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestMigrateLegacyConfigUpgradesToCurrent(t *testing.T) {
	path := writeConfig(t, `release_gate:
  enabled: true
  risk_appetite: 0.20
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ConfigSchemaVersion != config.CurrentConfigSchemaVersion {
		t.Errorf("schema version = %d, esperado %d", cfg.ConfigSchemaVersion, config.CurrentConfigSchemaVersion)
	}
	if cfg.ReleaseGate.Mode != "any" {
		t.Errorf("mode = %q, esperado default any", cfg.ReleaseGate.Mode)
	}
	if cfg.Reporting.GateLog.Path != "wardex-gate-audit.log" {
		t.Errorf("gate_log.path = %q, esperado default", cfg.Reporting.GateLog.Path)
	}
}

func TestMigrateExplicitCurrentVersionStays(t *testing.T) {
	path := writeConfig(t, `config_schema_version: 2
release_gate:
  enabled: true
  mode: aggregate
  risk_appetite: 0.30
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ConfigSchemaVersion != 2 {
		t.Errorf("schema version = %d, esperado 2", cfg.ConfigSchemaVersion)
	}
	if cfg.ReleaseGate.Mode != "aggregate" {
		t.Errorf("mode = %q, nao deveria ser sobrescrito", cfg.ReleaseGate.Mode)
	}
}

func TestMigrateFutureVersionRejected(t *testing.T) {
	path := writeConfig(t, `config_schema_version: 99
release_gate:
  enabled: true
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("config future deveria ser rejeitada")
	}
}
