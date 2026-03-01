// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package audit

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

// CountCreated returns the number of "acceptance.created" events in the audit log.
// Used internally to verify dataset integrity against the YAML store.
func CountCreated(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()

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
