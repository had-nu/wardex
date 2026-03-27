// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/utils"
)

var mu sync.Mutex

// Log appends a new AuditEntry to the JSONL log file.
// It ensures timestamps are in UTC and thread-safe writing.
func Log(path string, entry model.AuditEntry) error {
	mu.Lock()
	defer mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	} else {
		entry.Timestamp = entry.Timestamp.UTC()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	cwd, _ := os.Getwd()
	safePathStr, err := utils.SafePath(cwd, path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(safePathStr, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	_, err = f.Write(data)
	return err
}
