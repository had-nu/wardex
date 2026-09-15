package config

import "fmt"

// CurrentConfigSchemaVersion is the configuration schema version produced by
// current wardex builds.
const CurrentConfigSchemaVersion = 2

// legacyConfigSchemaVersion is the effective schema version of configuration
// files written before the config_schema_version field existed.
const legacyConfigSchemaVersion = 1

// MigrateConfig upgrades cfg in place from its recorded schema version to
// CurrentConfigSchemaVersion. Configurations from the future are rejected
// explicitly instead of being silently downgraded.
func MigrateConfig(cfg *Config) error {
	v := cfg.ConfigSchemaVersion
	if v == 0 {
		v = legacyConfigSchemaVersion
	}
	if v > CurrentConfigSchemaVersion {
		return fmt.Errorf("config schema version %d is newer than supported version %d", v, CurrentConfigSchemaVersion)
	}
	for v < CurrentConfigSchemaVersion {
		switch v {
		case 1:
			if err := migrateV1ToV2(cfg); err != nil {
				return err
			}
		}
		v++
	}
	cfg.ConfigSchemaVersion = CurrentConfigSchemaVersion
	return nil
}

// migrateV1ToV2 pins documented defaults into the loaded configuration so the
// in-memory config is self-describing and stable across rel up. Behaviour is
// unchanged: these defaults were already applied at use-time.
func migrateV1ToV2(cfg *Config) error {
	if cfg.ReleaseGate.Mode == "" {
		cfg.ReleaseGate.Mode = "any"
	}
	if cfg.Reporting.GateLog.Path == "" {
		cfg.Reporting.GateLog.Path = "wardex-gate-audit.log"
	}
	if cfg.Reporting.ENISAQueue.Path == "" {
		cfg.Reporting.ENISAQueue.Path = "wardex-enisa-queue.jsonl"
	}
	if cfg.StateStore.Dir == "" {
		cfg.StateStore.Dir = ".wardex"
	}
	return nil
}
