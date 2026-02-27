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
}
