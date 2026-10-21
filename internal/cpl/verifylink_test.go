package cpl_test

import (
	"bytes"
	"strings"
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
			t.Errorf("entry %s: %v (want OK)", r.EntryTimestamp, r.Status)
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
		t.Error("expected divergence not detected")
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
		t.Error("expected MISSING entry not detected")
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
		t.Errorf("matching v2 schema should be OK: %+v", results)
	}
	if results[0].RecordedSchemaVersion != 2 {
		t.Errorf("recorded schema = %d, want 2", results[0].RecordedSchemaVersion)
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
		t.Errorf("v1 vs expected v2 schema should report SCHEMA_VERSION: %+v", results)
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
		t.Errorf("legacy entry vs expected v1 should be OK: %+v", results[0])
	}

	results, err = cpl.VerifyLinkWithConfigAndSchemaVersion(matching, raw, 2)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	if results[0].Status != cpl.StatusSchemaVersion {
		t.Errorf("legacy entry vs expected v2 should report SCHEMA_VERSION: %+v", results[0])
	}
}

func TestVerifyLinkWarningsUseInjectedWriter(t *testing.T) {
	var warning bytes.Buffer
	_, err := cpl.VerifyLinkWithSchemaVersionWriter(
		[]byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":""}`+"\n"),
		".",
		0,
		&warning,
	)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	if !strings.Contains(warning.String(), "empty config hash") {
		t.Fatalf("expected warning in injected writer, got %q", warning.String())
	}
	if strings.Contains(warning.String(), "\x1b[") {
		t.Fatalf("warning contains ANSI: %q", warning.String())
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
		t.Errorf("without a schema expectation, an OK hash should be OK: %+v", results[0])
	}
	if results[0].RecordedSchemaVersion != 0 {
		t.Errorf("schema should not be reported without an expectation: %+v", results[0])
	}
}
