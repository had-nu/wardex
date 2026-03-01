// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

import "time"

// Acceptance represents a formal risk acceptance for a vulnerability.
type Acceptance struct {
	ID            string    `json:"id" yaml:"id"`
	CVE           string    `json:"cve" yaml:"cve"`
	AcceptedBy    string    `json:"accepted_by" yaml:"accepted_by"`
	Justification string    `json:"justification" yaml:"justification"`
	CreatedAt     time.Time `json:"created_at" yaml:"created_at"`
	ExpiresAt     time.Time `json:"expires_at" yaml:"expires_at"`
	Ticket        string    `json:"ticket,omitempty" yaml:"ticket,omitempty"`

	// Integrity field - generated via HMAC-SHA256
	Signature  string `json:"signature" yaml:"signature"`
	ReportHash string `json:"report_hash" yaml:"report_hash"`

	// Contextual metadata
	ContextRiskScore float64 `json:"context_risk_score,omitempty" yaml:"context_risk_score,omitempty"`

	// Logical state
	Revoked      bool              `json:"revoked,omitempty" yaml:"revoked,omitempty"`
	RevokedBy    string            `json:"revoked_by,omitempty" yaml:"revoked_by,omitempty"`
	RevokedAt    time.Time         `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	RevokeReason string            `json:"revoke_reason,omitempty" yaml:"revoke_reason,omitempty"`
	Revocation   *RevocationRecord `json:"revocation,omitempty" yaml:"revocation,omitempty"`
}

// RevocationRecord represents the metadata regarding the revocation of an acceptance.
type RevocationRecord struct {
	RevokedBy string    `json:"revoked_by,omitempty" yaml:"revoked_by,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	Reason    string    `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// AcceptanceStore represents the structure of the acceptances.yaml file
type AcceptanceStore struct {
	Acceptances []Acceptance `yaml:"acceptances"`
}
