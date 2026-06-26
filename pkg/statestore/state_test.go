// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package statestore

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewStore(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if store == nil {
		t.Fatal("New() returned nil store")
	}
	if store.root != dir {
		t.Errorf("store.root = %q, want %q", store.root, dir)
	}
}

func TestLoadStateEmpty(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	state, err := store.LoadState()
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state == nil {
		t.Fatal("LoadState() returned nil state")
	}
	if state.Version != StateVersion {
		t.Errorf("state.Version = %q, want %q", state.Version, StateVersion)
	}
	if state.RunCount != 0 {
		t.Errorf("state.RunCount = %d, want 0", state.RunCount)
	}
}

func TestSaveAndLoadState(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	state := EmptyState()
	state.LastDecision = "block"
	state.LastRisk = 0.75
	state.RunCount = 5

	if err := store.SaveState(state); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if loaded.LastDecision != "block" {
		t.Errorf("loaded.LastDecision = %q, want %q", loaded.LastDecision, "block")
	}
	if loaded.LastRisk != 0.75 {
		t.Errorf("loaded.LastRisk = %f, want 0.75", loaded.LastRisk)
	}
	if loaded.RunCount != 5 {
		t.Errorf("loaded.RunCount = %d, want 5", loaded.RunCount)
	}
}

func TestRecordDecision(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = store.RecordDecision("allow", 0.1, 10, 0, nil)
	if err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}

	state, err := store.LoadState()
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.LastDecision != "allow" {
		t.Errorf("state.LastDecision = %q, want %q", state.LastDecision, "allow")
	}
	if state.RunCount != 1 {
		t.Errorf("state.RunCount = %d, want 1", state.RunCount)
	}
	if len(state.Trend) != 1 {
		t.Errorf("len(state.Trend) = %d, want 1", len(state.Trend))
	}
}

func TestRecordDecisionMultiple(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	decisions := []struct {
		decision string
		risk     float64
	}{
		{"allow", 0.1},
		{"warn", 0.5},
		{"block", 0.9},
	}

	for _, d := range decisions {
		if err := store.RecordDecision(d.decision, d.risk, 5, 0, nil); err != nil {
			t.Fatalf("RecordDecision(%q) error = %v", d.decision, err)
		}
	}

	state, err := store.LoadState()
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.RunCount != 3 {
		t.Errorf("state.RunCount = %d, want 3", state.RunCount)
	}
	if state.LastDecision != "block" {
		t.Errorf("state.LastDecision = %q, want %q", state.LastDecision, "block")
	}
	if len(state.Trend) != 3 {
		t.Errorf("len(state.Trend) = %d, want 3", len(state.Trend))
	}
}

func TestHistory(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Record some decisions
	for i := 0; i < 5; i++ {
		if err := store.RecordDecision("allow", 0.1, 10, 0, nil); err != nil {
			t.Fatalf("RecordDecision() error = %v", err)
		}
	}

	history, err := store.History(30)
	if err != nil {
		t.Fatalf("History() error = %v", err)
	}
	if len(history) != 5 {
		t.Errorf("len(history) = %d, want 5", len(history))
	}
}

func TestTrendAnalysis(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Record decisions with increasing risk
	risks := []float64{0.1, 0.2, 0.3, 0.4, 0.5}
	for _, r := range risks {
		if err := store.RecordDecision("allow", r, 10, 0, nil); err != nil {
			t.Fatalf("RecordDecision() error = %v", err)
		}
	}

	analysis, err := store.TrendAnalysis()
	if err != nil {
		t.Fatalf("TrendAnalysis() error = %v", err)
	}

	if analysis.Direction != TrendWorsening {
		t.Errorf("analysis.Direction = %q, want %q", analysis.Direction, TrendWorsening)
	}
	if analysis.TotalRuns != 5 {
		t.Errorf("analysis.TotalRuns = %d, want 5", analysis.TotalRuns)
	}
}

func TestCleanup(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Record a decision
	if err := store.RecordDecision("allow", 0.1, 10, 0, nil); err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}

	// Verify history exists
	history, err := store.ListHistory()
	if err != nil {
		t.Fatalf("ListHistory() error = %v", err)
	}
	if len(history) == 0 {
		t.Fatal("expected history records, got none")
	}

	// Cleanup with very short retention (should not remove recent files)
	if err := store.Cleanup(1); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	// History should still exist
	history, err = store.ListHistory()
	if err != nil {
		t.Fatalf("ListHistory() error = %v", err)
	}
	if len(history) == 0 {
		t.Fatal("expected history records after cleanup, got none")
	}
}

func TestVerifyChain(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Record some decisions to build chain
	for i := 0; i < 3; i++ {
		if err := store.RecordDecision("allow", 0.1, 10, 0, nil); err != nil {
			t.Fatalf("RecordDecision() error = %v", err)
		}
	}

	// Verify chain integrity
	if err := store.VerifyChain(); err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
}

func TestComputeChainHash(t *testing.T) {
	hash1 := ComputeChainHash("abc", "def")
	hash2 := ComputeChainHash("abc", "def")
	hash3 := ComputeChainHash("abc", "xyz")

	if hash1 != hash2 {
		t.Errorf("same inputs produced different hashes: %q != %q", hash1, hash2)
	}
	if hash1 == hash3 {
		t.Errorf("different inputs produced same hash: %q", hash1)
	}
}

func TestHashBytes(t *testing.T) {
	hash1 := HashBytes([]byte("hello"))
	hash2 := HashBytes([]byte("hello"))
	hash3 := HashBytes([]byte("world"))

	if hash1 != hash2 {
		t.Errorf("same inputs produced different hashes: %q != %q", hash1, hash2)
	}
	if hash1 == hash3 {
		t.Errorf("different inputs produced same hash: %q", hash1)
	}
}

func TestEmptyState(t *testing.T) {
	state := EmptyState()
	if state.Version != StateVersion {
		t.Errorf("EmptyState().Version = %q, want %q", state.Version, StateVersion)
	}
	if state.Trend == nil {
		t.Error("EmptyState().Trend is nil, want non-nil")
	}
	if state.ExpiringSoon == nil {
		t.Error("EmptyState().ExpiringSoon is nil, want non-nil")
	}
}

func TestListHistoryEmpty(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	history, err := store.ListHistory()
	if err != nil {
		t.Fatalf("ListHistory() error = %v", err)
	}
	if len(history) != 0 {
		t.Errorf("len(history) = %d, want 0", len(history))
	}
}

func TestHistoryCount(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	count, err := store.HistoryCount()
	if err != nil {
		t.Fatalf("HistoryCount() error = %v", err)
	}
	if count != 0 {
		t.Errorf("HistoryCount() = %d, want 0", count)
	}

	// Record a decision
	if err := store.RecordDecision("allow", 0.1, 10, 0, nil); err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}

	count, err = store.HistoryCount()
	if err != nil {
		t.Fatalf("HistoryCount() error = %v", err)
	}
	if count != 1 {
		t.Errorf("HistoryCount() = %d, want 1", count)
	}
}

func TestStatePaths(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	expectedState := filepath.Join(dir, "state.json")
	expectedChain := filepath.Join(dir, "chain.json")

	if store.StatePath() != expectedState {
		t.Errorf("StatePath() = %q, want %q", store.StatePath(), expectedState)
	}
	if store.ChainPath() != expectedChain {
		t.Errorf("ChainPath() = %q, want %q", store.ChainPath(), expectedChain)
	}
}

func TestSaveStateTimestamps(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	state := EmptyState()
	before := time.Now().UTC()
	if err := store.SaveState(state); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}
	after := time.Now().UTC()

	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}

	if loaded.LastRun.Before(before) || loaded.LastRun.After(after) {
		t.Errorf("loaded.LastRun = %v, not between %v and %v", loaded.LastRun, before, after)
	}
}

func TestTrendPointSerialization(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	now := time.Date(2026, 6, 26, 10, 0, 0, 0, time.UTC)
	state := EmptyState()
	state.Trend = append(state.Trend, TrendPoint{
		Date:      now,
		Risk:      0.5,
		Decision:  "warn",
		VulnCount: 42,
	})

	if err := store.SaveState(state); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	// Read state.json directly
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("state.json is empty")
	}
}

func TestCleanupOldFiles(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create history directory and a fake old file
	historyDir := filepath.Join(dir, "history")
	if err := os.MkdirAll(historyDir, 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	oldFile := filepath.Join(historyDir, "2020-01-01T00:00:00Z.json")
	if err := os.WriteFile(oldFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Set mtime to 60 days ago
	oldTime := time.Now().AddDate(0, 0, -60)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	// Cleanup with 30 day retention - old file should be removed
	if err := store.Cleanup(30); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Errorf("old file still exists after cleanup")
	}
}
