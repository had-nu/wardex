// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package snapshot

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

// Save writes the current GapReport to the snapshot file.
func Save(report model.GapReport, filename string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write snapshot: %w", err)
	}

	return nil
}

// Load reads the snapshot file if it exists. Returns nil, nil if missing.
func Load(filename string) (*model.GapReport, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, nil // First run or snapshot deleted
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	var report model.GapReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snapshot: %w", err)
	}

	return &report, nil
}
