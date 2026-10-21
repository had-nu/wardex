// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package versionregistry_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	acceptaudit "github.com/had-nu/wardex/v3/pkg/accept/audit"
	"github.com/had-nu/wardex/v3/pkg/model"
	"github.com/had-nu/wardex/v3/pkg/versionregistry"
)

func TestRegistryAddHasRoundtrip(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wardex-gate-audit.log")

	reg := versionregistry.New()
	reg.Add(versionregistry.ReleaseInfo{
		Version:   "2.6.0",
		PolicyRef: "iso27001:a.8.1@2026-09",
		SealedAt:  time.Now().UTC(),
		EntryHash: "abc",
	}, "abc")
	if !reg.Has("2.6.0") {
		t.Fatal("added version should exist")
	}
	if reg.Has("2.6.1") {
		t.Fatal("version that was not added should not exist")
	}

	if err := reg.Save(logPath); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := versionregistry.Load(logPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.Has("2.6.0") {
		t.Error("roundtrip lost the version")
	}
	info := loaded.Releases["2.6.0"]
	if info.PolicyRef != "iso27001:a.8.1@2026-09" {
		t.Errorf("policy_ref = %q", info.PolicyRef)
	}
}

func TestLoadMissingIndexYieldsEmpty(t *testing.T) {
	reg, err := versionregistry.Load(filepath.Join(t.TempDir(), "nope.log"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(reg.Releases) != 0 {
		t.Error("missing index should be empty")
	}
}

func TestLoadCorruptOrFutureSchema(t *testing.T) {
	for name, body := range map[string]string{
		"corrupt": `{not json`,
		"future":  `{"schema": 99, "releases": {}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit.log")
			if err := os.WriteFile(versionregistry.IndexPath(logPath), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := versionregistry.Load(logPath); err == nil {
				t.Fatal("invalid index should return an error")
			}
		})
	}
}

func TestRebuildFromChain(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	logPath := filepath.Join(dir, "wardex-gate-audit.log")

	for i, v := range []string{"2.5.0", "2.5.1"} {
		_ = i
		if err := acceptaudit.ChainedAuditLog(logPath, model.AuditEntry{
			Timestamp:        time.Now().UTC(),
			Event:            "gate.evaluated",
			ReleaseVersion:   v,
			PolicyRef:        "policy:" + v,
			CplSchemaVersion: 2,
		}); err != nil {
			t.Fatalf("append %s: %v", v, err)
		}
	}
	// An entry without release_version must be skipped but still scanned.
	if err := acceptaudit.ChainedAuditLog(logPath, model.AuditEntry{
		Timestamp: time.Now().UTC(),
		Event:     "gate.evaluated",
	}); err != nil {
		t.Fatalf("append plain: %v", err)
	}

	reg := versionregistry.New()
	lastHash, err := reg.Rebuild(logPath)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !reg.Has("2.5.0") || !reg.Has("2.5.1") {
		t.Errorf("rebuild did not collect versions: %v", reg.Releases)
	}
	if len(reg.Releases) != 2 {
		t.Errorf("len(releases) = %d, want 2", len(reg.Releases))
	}
	expectedLast, err := acceptaudit.LastEntryHash(logPath)
	if err != nil {
		t.Fatalf("last entry hash: %v", err)
	}
	if lastHash != expectedLast {
		t.Errorf("lastHash = %s, want %s", lastHash, expectedLast)
	}
}
