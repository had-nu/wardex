// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package accept

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/had-nu/wardex/v2/pkg/utils"
)

var auditMu sync.Mutex

// AuditLog appends a new AuditEntry to the JSONL log file.
// It ensures timestamps are in UTC and thread-safe writing.
func AuditLog(path string, entry model.AuditEntry) error {
	auditMu.Lock()
	defer auditMu.Unlock()

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

// AuditCountCreated returns the number of "acceptance.created" events in the audit log.
func AuditCountCreated(path string) (int, error) {
	cwd, _ := os.Getwd()
	safePathStr, err := utils.SafePath(cwd, path)
	if err != nil {
		return 0, err
	}
	file, err := os.Open(safePathStr) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer func() { _ = file.Close() }()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry model.AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			if entry.Event == "acceptance.created" {
				count++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return count, err
	}

	return count, nil
}
