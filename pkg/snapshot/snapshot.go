// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package snapshot provides save, load, and diff operations for compliance
// posture snapshots, enabling before/after comparisons across assessments.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
)

// Save writes the current GapReport to the snapshot file.
func Save(filename string, report *model.GapReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	return os.WriteFile(filename, data, 0600)
}

// Load reads the snapshot file if it exists. Returns nil, nil if missing.
func Load(filename string) (*model.GapReport, error) {
	cwd, _ := os.Getwd()
	safePathStr, err := cli.ValidateInputPath(cwd, filename)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(safePathStr); os.IsNotExist(err) {
		return nil, nil // First run or snapshot deleted
	}

	data, err := os.ReadFile(safePathStr) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	var report model.GapReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snapshot: %w", err)
	}

	return &report, nil
}
