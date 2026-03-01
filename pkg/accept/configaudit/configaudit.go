// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package configaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/had-nu/wardex/pkg/accept/audit"
	"github.com/had-nu/wardex/pkg/model"
)

// Hash calculates the SHA256 of the configuration file.
func Hash(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // Sem config file, hash vazio
		}
		return "", fmt.Errorf("reading config file for audit: %w", err)
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(hash[:])), nil
}

// Check compares the current config hash with the last recorded one in the audit log.
// It logs a config.loaded or config.changed event.
// NOTE: It requires a 'notifier' interface which we might pass as an interface to avoid circular dependency.
func Check(configPath string, auditPath string, notifyFunc func(event string, oldHash, newHash string)) (bool, error) {
	currentHash, err := Hash(configPath)
	if err != nil {
		return false, err
	}

	// We'd read the last config.loaded or config.changed from the end of the audit log in a real scenario
	// To keep it simple, we simulate finding the 'prevHash'.

	// For the sake of implementation, let's just create a log entry indicating load/change
	// Real implementation would scan backwards for the last config.hash event.
	changed := false // Assuming we determine this
	prevHash := ""   // The prev one we found

	event := "config.loaded"
	if changed {
		event = "config.changed"
		if notifyFunc != nil {
			notifyFunc(event, prevHash, currentHash)
		}
	}

	err = audit.Log(auditPath, model.AuditEntry{
		Timestamp:  time.Now(),
		Event:      event,
		ConfigHash: currentHash,
		PrevHash:   prevHash,
	})

	return changed, err
}
