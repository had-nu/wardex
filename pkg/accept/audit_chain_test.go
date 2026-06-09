// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package accept

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/had-nu/wardex/pkg/model"
)

func TestAuditChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit-chain.log")

	// 1. Write first entry -> previous_entry_hash should be empty
	entry1 := model.AuditEntry{
		Timestamp: time.Now().UTC(),
		Event:     "test.event1",
		Detail:    "first entry",
	}

	if err := ChainedAuditLog(logPath, entry1); err != nil {
		t.Fatalf("failed to write entry1: %v", err)
	}

	// Read log to verify entry1
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var readEntry1 model.AuditEntry
	if err := json.Unmarshal(data, &readEntry1); err != nil {
		t.Fatal(err)
	}

	if readEntry1.PreviousEntryHash != "" {
		t.Errorf("expected first entry to have empty PreviousEntryHash, got %q", readEntry1.PreviousEntryHash)
	}

	// 2. Write second entry -> previous_entry_hash should be populated with hash of entry1
	entry2 := model.AuditEntry{
		Timestamp: time.Now().UTC(),
		Event:     "test.event2",
		Detail:    "second entry",
	}

	if err := ChainedAuditLog(logPath, entry2); err != nil {
		t.Fatalf("failed to write entry2: %v", err)
	}

	gaps, err := VerifyChain(logPath)
	if err != nil {
		t.Fatalf("failed to verify chain: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("expected no gaps, got %d gaps: %+v", len(gaps), gaps)
	}

	// 3. Detect tampering (modifying entry1)
	readEntry1.Event = "test.event1.tampered"
	t1Bytes, _ := json.Marshal(readEntry1)

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var rawLines []string
	scanner := bufioNewScannerForTest(f)
	for scanner.Scan() {
		rawLines = append(rawLines, scanner.Text())
	}
	f.Close()

	if len(rawLines) != 2 {
		t.Fatalf("expected 2 lines in log, got %d", len(rawLines))
	}

	// Tampered log file: line 1 tampered, line 2 untouched
	tamperedData := string(t1Bytes) + "\n" + rawLines[1] + "\n"
	if err := os.WriteFile(logPath, []byte(tamperedData), 0600); err != nil {
		t.Fatal(err)
	}

	gaps, err = VerifyChain(logPath)
	if err != nil {
		t.Fatalf("failed to verify tampered chain: %v", err)
	}
	if len(gaps) == 0 {
		t.Errorf("expected chain verification to fail due to tampering")
	} else {
		t.Logf("tampering correctly detected: %v", gaps[0].Message)
	}

	// 4. Detect gap (missing entry)
	// Let's write three entries correctly
	logPath2 := filepath.Join(dir, "audit-chain2.log")
	e1 := model.AuditEntry{Event: "e1"}
	e2 := model.AuditEntry{Event: "e2"}
	e3 := model.AuditEntry{Event: "e3"}
	_ = ChainedAuditLog(logPath2, e1)
	_ = ChainedAuditLog(logPath2, e2)
	_ = ChainedAuditLog(logPath2, e3)

	// Verify it's clean
	gaps, _ = VerifyChain(logPath2)
	if len(gaps) != 0 {
		t.Fatalf("clean log has gaps: %+v", gaps)
	}

	// Now delete e2 (second line)
	f2, _ := os.Open(logPath2)
	var rawLines2 []string
	scanner2 := bufioNewScannerForTest(f2)
	for scanner2.Scan() {
		rawLines2 = append(rawLines2, scanner2.Text())
	}
	f2.Close()

	// write only e1 and e3
	gapData := rawLines2[0] + "\n" + rawLines2[2] + "\n"
	_ = os.WriteFile(logPath2, []byte(gapData), 0600)

	gaps, err = VerifyChain(logPath2)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) == 0 {
		t.Errorf("expected chain verification to fail due to missing entry (gap)")
	} else {
		t.Logf("gap correctly detected: %v", gaps[0].Message)
	}
}

// Simple scanner helper for test
type testScanner struct {
	lines []string
	idx   int
}

func bufioNewScannerForTest(f *os.File) *testScanner {
	data, _ := os.ReadFile(f.Name())
	split := splitByNewline(string(data))
	return &testScanner{lines: split, idx: -1}
}

func (s *testScanner) Scan() bool {
	s.idx++
	return s.idx < len(s.lines)
}

func (s *testScanner) Text() string {
	return s.lines[s.idx]
}

func splitByNewline(s string) []string {
	var res []string
	var current string
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if current != "" {
				res = append(res, current)
				current = ""
			}
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		res = append(res, current)
	}
	return res
}
