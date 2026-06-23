// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package accept

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

func TestENISABackend(t *testing.T) {
	dir := t.TempDir()
	queuePath := filepath.Join(dir, "enisa-queue.jsonl")

	backend := NewENISABackend(queuePath)
	if backend.Name() != "enisa" {
		t.Errorf("expected name to be 'enisa', got %q", backend.Name())
	}

	entry := model.AuditEntry{
		Timestamp: time.Now().UTC(),
		Event:     "gate.evaluated",
		Detail:    "test active exploit forward",
	}

	err := backend.Send(entry)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Verify that the queue file was written and contains the entry
	data, err := os.ReadFile(queuePath)
	if err != nil {
		t.Fatalf("failed to read queue file: %v", err)
	}

	var readEntry model.AuditEntry
	if err := json.Unmarshal(data, &readEntry); err != nil {
		t.Fatalf("failed to parse entry from queue: %v", err)
	}

	if readEntry.Event != entry.Event || readEntry.Detail != entry.Detail {
		t.Errorf("read entry %+v does not match sent entry %+v", readEntry, entry)
	}
}
