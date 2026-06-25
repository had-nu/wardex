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
