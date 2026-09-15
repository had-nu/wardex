package cpl_test

import (
	"testing"

	"github.com/had-nu/wardex/v2/internal/cpl"
)

func TestVerifyLinkAllOK(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))
	hash, err := cpl.ComputeConfigHash(raw, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}

	log := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"` + hash + `"}` + "\n")
	results, err := cpl.VerifyLinkWithConfig(log, raw)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	for _, r := range results {
		if r.Status != cpl.StatusOK {
			t.Errorf("entrada %s: %v (esperava OK)", r.EntryTimestamp, r.Status)
		}
	}
}

func TestVerifyLinkMismatch(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))

	log := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}` + "\n")
	results, err := cpl.VerifyLinkWithConfig(log, raw)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}

	var mismatches int
	for _, r := range results {
		if r.Status == cpl.StatusMismatch {
			mismatches++
		}
	}
	if mismatches == 0 {
		t.Error("divergencia esperada nao detectada")
	}
}

func TestVerifyLinkMissing(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))
	hash, err := cpl.ComputeConfigHash(raw, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}

	log := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"` + hash + `"}` + "\n")
	results, err := cpl.VerifyLink(log, "/nonexistent/directory")
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}

	var missing int
	for _, r := range results {
		if r.Status == cpl.StatusMissing {
			missing++
		}
	}
	if missing == 0 {
		t.Error("entrada MISSING esperada nao detectada")
	}
}

func TestVerifyLinkSchemaVersionMatch(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))
	hash, err := cpl.ComputeConfigHash(raw, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}

	log := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"` + hash + `","cpl_schema_version":2}` + "\n")
	results, err := cpl.VerifyLinkWithConfigAndSchemaVersion(log, raw, 2)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	if len(results) != 1 || results[0].Status != cpl.StatusOK {
		t.Errorf("schema v2 correspondente deveria ser OK: %+v", results)
	}
	if results[0].RecordedSchemaVersion != 2 {
		t.Errorf("schema registado = %d, esperado 2", results[0].RecordedSchemaVersion)
	}
}

func TestVerifyLinkSchemaVersionMismatch(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))
	hash, err := cpl.ComputeConfigHash(raw, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}

	log := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"` + hash + `","cpl_schema_version":1}` + "\n")
	results, err := cpl.VerifyLinkWithConfigAndSchemaVersion(log, raw, 2)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	if len(results) != 1 || results[0].Status != cpl.StatusSchemaVersion {
		t.Errorf("schema v1 vs esperado v2 deveria reportar SCHEMA_VERSION: %+v", results)
	}
}

func TestVerifyLinkLegacyEntryCountsAsV1(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))
	hash, err := cpl.ComputeConfigHash(raw, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}

	// Legacy entries have no cpl_schema_version field: effective schema = v1.
	matching := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"` + hash + `"}` + "\n")

	results, err := cpl.VerifyLinkWithConfigAndSchemaVersion(matching, raw, 1)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	if results[0].Status != cpl.StatusOK {
		t.Errorf("entrada legacy vs esperado v1 deveria ser OK: %+v", results[0])
	}

	results, err = cpl.VerifyLinkWithConfigAndSchemaVersion(matching, raw, 2)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	if results[0].Status != cpl.StatusSchemaVersion {
		t.Errorf("entrada legacy vs esperado v2 deveria reportar SCHEMA_VERSION: %+v", results[0])
	}
}

func TestVerifyLinkNoSchemaCheckWhenExpectedZero(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))
	hash, err := cpl.ComputeConfigHash(raw, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}

	log := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"` + hash + `","cpl_schema_version":7}` + "\n")
	results, err := cpl.VerifyLinkWithConfig(log, raw)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	if results[0].Status != cpl.StatusOK {
		t.Errorf("sem expectativa de schema, hash OK deveria ser OK: %+v", results[0])
	}
	if results[0].RecordedSchemaVersion != 0 {
		t.Errorf("schema nao deveria ser reportado sem expectativa: %+v", results[0])
	}
}
