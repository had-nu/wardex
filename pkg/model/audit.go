// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

import "time"

// AuditEntry represents an append-only line in the JSONL audit log.
// All fields are optional except Timestamp and Event.
type AuditEntry struct {
	Timestamp     time.Time `json:"ts"`
	Event         string    `json:"event"`
	ID            string    `json:"id,omitempty"`
	CVEID         string    `json:"cve_id,omitempty"`
	Actor         string    `json:"actor,omitempty"`
	Risk          float64   `json:"risk,omitempty"`
	Expires       string    `json:"expires,omitempty"`
	Status        string    `json:"status,omitempty"`
	Interactive   bool      `json:"interactive,omitempty"`
	ConfigHash    string    `json:"config_hash,omitempty"`
	PrevHash      string    `json:"prev_hash,omitempty"`
	ChangedFields []string  `json:"changed_fields,omitempty"`
	Detail        string    `json:"detail,omitempty"`

	// New in v1.9.2 for gate decision logging
	EvidenceHash    string   `json:"evidence_hash,omitempty"`
	OverallDecision Decision `json:"overall_decision,omitempty"`

	// NEW in v2.2 — CPL: CLI override flags that affected the evaluation
	CliOverrides map[string]string `json:"cli_overrides,omitempty"`

	// NEW in v2.0 — CRA Article 14 audit chain and deadline tracking
	PreviousEntryHash         string    `json:"previous_entry_hash,omitempty"`
	ActivelyExploited         []string  `json:"actively_exploited_cves,omitempty"`
	Art14DeadlineEarlyWarning time.Time `json:"art14_deadline_early_warning,omitempty"`
	Art14DeadlineNotification time.Time `json:"art14_deadline_notification,omitempty"`
	Art14NotificationArtefactPath string `json:"art14_notification_artefact_path,omitempty"`
}
