// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// testDir creates a temporary directory within the workspace for testing.
func testDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cwd, "audit-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// testAuditEntry creates a valid audit entry for testing.
func testAuditEntry(t *testing.T) model.AuditEntry {
	return model.AuditEntry{
		Timestamp:       time.Now().UTC().Truncate(time.Second),
		Event:           "acceptance.created",
		ConfigHash:      "sha256:abcdef123456",
		CliOverrides:    map[string]string{"flag": "value"},
		EvidenceHash:    "sha256:fedcba654321",
		OverallDecision: model.DecisionAllow,
		Risk:            0.5,
		Status:          "allow",
		Detail:          "test detail",
		ActivelyExploited: []string{"CVE-2024-1234"},
	}
}

func TestAuditLog_Basic(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	entry := testAuditEntry(t)
	if err := AuditLog(path, entry); err != nil {
		t.Fatalf("AuditLog failed: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty audit log")
	}
}

func TestAuditLog_TimestampUTC(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	entry := model.AuditEntry{
		Event:      "test.event",
		Status:     "test",
		Timestamp:  time.Now().Local(), // non-UTC
	}
	if err := AuditLog(path, entry); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	var logged model.AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &logged); err != nil {
		t.Fatal(err)
	}
	if logged.Timestamp.Location() != time.UTC {
		t.Fatalf("expected UTC timestamp, got %v", logged.Timestamp.Location())
	}
}

func TestAuditLog_ZeroTimestampSet(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	entry := model.AuditEntry{
		Event:  "test.event",
		Status: "test",
		// Timestamp is zero
	}
	if err := AuditLog(path, entry); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	var logged model.AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &logged); err != nil {
		t.Fatal(err)
	}
	if logged.Timestamp.IsZero() {
		t.Fatal("expected timestamp to be set")
	}
	if logged.Timestamp.Location() != time.UTC {
		t.Fatalf("expected UTC timestamp, got %v", logged.Timestamp.Location())
	}
}

func TestAuditLog_ThreadSafe(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	const numGoroutines = 50
	errCh := make(chan error, 100)

	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			entry := model.AuditEntry{
				Event:           "concurrent.test",
				Status:          "test",
				Timestamp:       time.Now().UTC(),
				OverallDecision: model.DecisionAllow,
				Detail:          string(rune(i)),
			}
			errCh <- AuditLog(path, entry)
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent AuditLog failed: %v", err)
		}
	}

	// Verify all entries were written
	data, _ := os.ReadFile(path)
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != numGoroutines {
		t.Fatalf("expected %d lines, got %d", numGoroutines, lines)
	}
}

func TestAuditLog_NewFile(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "newdir", "audit.log")

	entry := testAuditEntry(t)
	if err := AuditLog(path, entry); err != nil {
		t.Fatal(err)
	}

	// Verify directory was created
	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Fatal("directory not created")
	}
}

func TestAuditLog_FilePermissions(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	entry := testAuditEntry(t)
	if err := AuditLog(path, entry); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %04o", info.Mode().Perm())
	}
}

func TestAuditLog_InvalidJSON(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	// Write invalid JSON first
	os.WriteFile(path, []byte("invalid json\n"), 0600)

	entry := testAuditEntry(t)
	// Should still be able to append
	if err := AuditLog(path, entry); err != nil {
		t.Fatal(err)
	}
}

func TestAuditCountCreated_Empty(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	count, err := AuditCountCreated(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}
}

func TestAuditCountCreated_Nonexistent(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "nonexistent.log")

	count, err := AuditCountCreated(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}
}

func TestAuditCountCreated_CountsCreated(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	entries := []model.AuditEntry{
		{Timestamp: time.Now().UTC(), Event: "acceptance.created", Status: "allow"},
		{Timestamp: time.Now().UTC(), Event: "other.event", Status: "allow"},
		{Timestamp: time.Now().UTC(), Event: "acceptance.created", Status: "block"},
		{Timestamp: time.Now().UTC(), Event: "acceptance.created", Status: "warn"},
	}

	for _, e := range entries {
		if err := AuditLog(path, e); err != nil {
			t.Fatal(err)
		}
	}

	count, err := AuditCountCreated(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("expected 3, got %d", count)
	}
}

func TestAuditCountCreated_IgnoresOtherEvents(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	entries := []model.AuditEntry{
		{Event: "acceptance.created"},
		{Event: "other.event"},
		{Event: "another.event"},
	}

	for _, e := range entries {
		if err := AuditLog(path, e); err != nil {
			t.Fatal(err)
		}
	}

	count, err := AuditCountCreated(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}
}

func TestAuditCountCreated_MalformedLineSkipped(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	// Write a malformed line first
	os.WriteFile(path, []byte("not valid json\n"), 0600)

	// Then write a valid entry
	validData, _ := json.Marshal(model.AuditEntry{Event: "acceptance.created"})
	os.WriteFile(path, append([]byte("malformed line\n"), append(validData, '\n')...), 0600)

	count, err := AuditCountCreated(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}
}
func TestAuditCountCreated_EmptyLines(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "audit.log")

	// Write empty lines and valid entries
	data := []byte("\n\n")
	os.WriteFile(path, data, 0600)

	entry := model.AuditEntry{Event: "acceptance.created"}
	data, _ = json.Marshal(entry)
	os.WriteFile(path, append(data, '\n'), 0600)

	count, err := AuditCountCreated(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}
}

// Fuzz tests

func FuzzAuditLog(f *testing.F) {
	f.Add([]byte(`{"event":"test","status":"ok"}`))
	f.Add([]byte(`{"event":"acceptance.created","timestamp":"2024-01-01T00:00:00Z"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "audit.log")

		var entry model.AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return // Invalid JSON, skip
		}
		entry.Timestamp = time.Now().UTC() // Ensure valid timestamp
		AuditLog(path, entry)
	})
}

func FuzzAuditCountCreated(f *testing.F) {
	f.Add([]byte("acceptance.created\n"))
	f.Add([]byte("acceptance.created\nacceptance.created\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "audit.log")
		os.WriteFile(path, data, 0600)
		AuditCountCreated(path)
	})
}