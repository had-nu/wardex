// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package statestore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// HistoryRecord is a single historical state snapshot.
type HistoryRecord struct {
	State     *State   `json:"state"`
	FilePath  string   `json:"-"`
	Timestamp time.Time `json:"timestamp"`
}

// ListHistory returns all history records sorted by timestamp.
func (s *Store) ListHistory() ([]HistoryRecord, error) {
	historyDir := filepath.Join(s.root, "history")
	if _, err := os.Stat(historyDir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(historyDir)
	if err != nil {
		return nil, fmt.Errorf("statestore: read history dir: %w", err)
	}

	var records []HistoryRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(historyDir, entry.Name())
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			continue
		}

		var state State
		if err := json.Unmarshal(data, &state); err != nil {
			continue
		}

		records = append(records, HistoryRecord{
			State:     &state,
			FilePath:  path,
			Timestamp: state.LastRun,
		})
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	return records, nil
}

// HistoryBetween returns history records between two timestamps.
func (s *Store) HistoryBetween(from, to time.Time) ([]HistoryRecord, error) {
	all, err := s.ListHistory()
	if err != nil {
		return nil, err
	}

	var filtered []HistoryRecord
	for _, r := range all {
		if (r.Timestamp.Equal(from) || r.Timestamp.After(from)) &&
			(r.Timestamp.Equal(to) || r.Timestamp.Before(to)) {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// HistoryCount returns the number of history records.
func (s *Store) HistoryCount() (int, error) {
	historyDir := filepath.Join(s.root, "history")
	if _, err := os.Stat(historyDir); os.IsNotExist(err) {
		return 0, nil
	}

	entries, err := os.ReadDir(historyDir)
	if err != nil {
		return 0, fmt.Errorf("statestore: read history dir: %w", err)
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	return count, nil
}
