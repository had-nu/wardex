package snapshot

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

const SnapshotFile = ".wardex_snapshot.json"

// Save writes the current GapReport to the snapshot file.
func Save(report model.GapReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	if err := os.WriteFile(SnapshotFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write snapshot: %w", err)
	}

	return nil
}

// Load reads the snapshot file if it exists. Returns nil, nil if missing.
func Load() (*model.GapReport, error) {
	if _, err := os.Stat(SnapshotFile); os.IsNotExist(err) {
		return nil, nil // First run or snapshot deleted
	}

	data, err := os.ReadFile(SnapshotFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	var report model.GapReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snapshot: %w", err)
	}

	return &report, nil
}
