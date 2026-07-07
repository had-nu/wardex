// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package statestore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/had-nu/wardex/v2/pkg/atomicwrite"
)

// Store manages the persistent state directory.
type Store struct {
	root   string // .wardex/ directory
	chain  *ChainFile
}

// New creates or opens a state store at the given root directory.
func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("statestore: mkdir: %w", err)
	}

	chain, err := LoadChain(filepath.Join(root, "chain.json"))
	if err != nil {
		return nil, err
	}

	return &Store{
		root:  root,
		chain: chain,
	}, nil
}

// LoadState returns the current consolidated state.
func (s *Store) LoadState() (*State, error) {
	path := filepath.Join(s.root, "state.json")
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return EmptyState(), nil
		}
		return nil, fmt.Errorf("statestore: read state: %w", err)
	}

	var state State
	if err := unmarshalJSON(data, &state); err != nil {
		return nil, fmt.Errorf("statestore: parse state: %w", err)
	}
	return &state, nil
}

// SaveState writes the state atomically and appends to the BLAKE3 chain.
func (s *Store) SaveState(state *State) error {
	state.Version = StateVersion
	state.LastRun = time.Now().UTC()

	data, err := marshalJSON(state)
	if err != nil {
		return fmt.Errorf("statestore: marshal state: %w", err)
	}

	if err := atomicWrite(filepath.Join(s.root, "state.json"), data); err != nil {
		return err
	}

	dataHash := HashBytes(data)
	AppendEntry(s.chain, dataHash)

	return SaveChain(filepath.Join(s.root, "chain.json"), s.chain)
}

// RecordDecision records a gate decision to the state and history.
func (s *Store) RecordDecision(decision string, risk float64, vulnCount int, activeAccepts int, expiringSoon []string) error {
	state, err := s.LoadState()
	if err != nil {
		return err
	}

	state.LastDecision = decision
	state.LastRisk = risk
	state.RunCount++
	state.ActiveAccepts = activeAccepts
	state.ExpiringSoon = expiringSoon

	point := TrendPoint{
		Date:      time.Now().UTC(),
		Risk:      risk,
		Decision:  decision,
		VulnCount: vulnCount,
	}
	state.Trend = append(state.Trend, point)

	if len(state.Trend) > 90 {
		state.Trend = state.Trend[len(state.Trend)-90:]
	}

	if err := s.SaveState(state); err != nil {
		return err
	}

	if err := s.saveHistorySnapshot(state); err != nil {
		return fmt.Errorf("statestore: save history: %w", err)
	}

	return nil
}

// saveHistorySnapshot saves a timestamped snapshot.
func (s *Store) saveHistorySnapshot(state *State) error {
	historyDir := filepath.Join(s.root, "history")
	if err := os.MkdirAll(historyDir, 0o750); err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.json", state.LastRun.Format("2006-01-02T15:04:05Z"))
	path := filepath.Join(historyDir, filename)

	data, err := marshalJSON(state)
	if err != nil {
		return err
	}

	return atomicWrite(path, data)
}

// History returns trend points from the last N days.
func (s *Store) History(days int) ([]TrendPoint, error) {
	state, err := s.LoadState()
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	var result []TrendPoint
	for _, p := range state.Trend {
		if p.Date.After(cutoff) {
			result = append(result, p)
		}
	}
	return result, nil
}

// TrendAnalysis analyzes the trend over historical data.
func (s *Store) TrendAnalysis() (*TrendAnalysis, error) {
	history, err := s.History(90)
	if err != nil {
		return nil, err
	}

	if len(history) == 0 {
		return &TrendAnalysis{
			Direction: TrendStable,
		}, nil
	}

	analysis := &TrendAnalysis{
		TotalRuns:  len(history),
		OldestRun:  history[0].Date,
		NewestRun:  history[len(history)-1].Date,
		MinRisk:    1.0,
	}

	var totalRisk float64
	for _, p := range history {
		totalRisk += p.Risk
		if p.Risk < analysis.MinRisk {
			analysis.MinRisk = p.Risk
		}
		if p.Risk > analysis.MaxRisk {
			analysis.MaxRisk = p.Risk
		}
		switch p.Decision {
		case "allow":
			analysis.AllowCount++
		case "warn":
			analysis.WarnCount++
		case "block":
			analysis.BlockCount++
		}
	}

	analysis.AverageRisk = totalRisk / float64(len(history))
	analysis.RiskDelta = history[len(history)-1].Risk - history[0].Risk

	if analysis.RiskDelta < -0.05 {
		analysis.Direction = TrendImproving
	} else if analysis.RiskDelta > 0.05 {
		analysis.Direction = TrendWorsening
	} else {
		analysis.Direction = TrendStable
	}

	return analysis, nil
}

// Cleanup removes history snapshots older than retentionDays.
func (s *Store) Cleanup(retentionDays int) error {
	historyDir := filepath.Join(s.root, "history")
	if _, err := os.Stat(historyDir); os.IsNotExist(err) {
		return nil
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	entries, err := os.ReadDir(historyDir)
	if err != nil {
		return fmt.Errorf("statestore: read history dir: %w", err)
	}

	var removed int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(historyDir, entry.Name())
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("statestore: remove %s: %w", path, err)
			}
			removed++
		}
	}

	if removed > 0 {
		fmt.Fprintf(os.Stderr, "[INFO] Cleaned up %d old history snapshots\n", removed)
	}
	return nil
}

// VerifyChain checks the integrity of the BLAKE3 chain.
func (s *Store) VerifyChain() error {
	return VerifyChain(s.chain)
}

// StatePath returns the path to state.json.
func (s *Store) StatePath() string {
	return filepath.Join(s.root, "state.json")
}

// ChainPath returns the path to chain.json.
func (s *Store) ChainPath() string {
	return filepath.Join(s.root, "chain.json")
}

// atomicWrite writes data to a temp file then renames.
func atomicWrite(path string, data []byte) error {
	return atomicwrite.Write(path, data)
}

// marshalJSON marshals to indented JSON.
func marshalJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// unmarshalJSON unmarshals JSON data.
func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
