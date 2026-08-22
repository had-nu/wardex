// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package model

import "time"

// Art14NotificationArtefact is produced by Wardex when an actively exploited
// vulnerability is detected. It structures the three Article 14(2) reporting
// obligations of the CRA (EU 2024/2847) and is written to disk for operator
// review and dispatch. Wardex never transmits this artefact.
//
// Fields left empty by Wardex are populated with "[OPERATOR: complete before dispatch]"
// to make required-but-unknown fields visible before submission.
type Art14NotificationArtefact struct {
	// Metadata
	ArtefactID  string    `json:"artefact_id"`  // UUID v4
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"` // e.g. "wardex/v2.0.0"
	WardexActor string    `json:"wardex_actor"` // WARDEX_ACTOR env var
	// Status tracks operator lifecycle: "draft" → "dispatched"
	Status string `json:"status"` // "draft" | "dispatched"

	// Article 14(2)(a) — Early Warning (must be submitted within 24h of awareness)
	EarlyWarning Art14EarlyWarning `json:"early_warning"`

	// Article 14(2)(b) — Vulnerability Notification (must be submitted within 72h of awareness)
	Notification Art14Notification `json:"notification"`

	// Article 14(2)(c) — Final Report (must be submitted ≤ 14 days after corrective measure)
	// This block is populated later via `wardex art14 finalize`.
	FinalReport Art14FinalReport `json:"final_report,omitempty"`

	// HMAC-SHA256 over canonical JSON of all fields above (excluding this field itself).
	// Computed and verified by the art14 package. Tampering is detectable.
	HMAC string `json:"hmac"`
}

// Art14EarlyWarning covers the Art. 14(2)(a) early warning obligation.
type Art14EarlyWarning struct {
	AwarenessTimestamp time.Time `json:"awareness_timestamp"`
	Deadline           time.Time `json:"deadline"` // AwarenessTimestamp + 24h
	// AffectedStates is the list of EU member states whose users may be affected.
	// Left empty by Wardex; operator must complete before dispatch.
	AffectedStates []string `json:"affected_states,omitempty"`
}

// Art14Notification covers the Art. 14(2)(b) vulnerability notification obligation.
type Art14Notification struct {
	Deadline time.Time `json:"deadline"` // AwarenessTimestamp + 72h
	// ProductName and ProductVersion are pre-populated from cra.art14 config.
	// If absent in config, set to "[OPERATOR: complete before dispatch]".
	ProductName    string `json:"product_name"`
	ProductVersion string `json:"product_version"`
	// CVEIDs lists all CVEs in this evaluation that are actively exploited.
	// One artefact per evaluation (may contain multiple CVE IDs) per OQ-03.
	CVEIDs []string `json:"cve_ids"`
	// ExploitationNature describes how the vulnerability is being exploited (free text).
	ExploitationNature string `json:"exploitation_nature"`
	// VulnerabilityNature describes the technical nature of the vulnerability (free text).
	VulnerabilityNature string `json:"vulnerability_nature"`
	// CorrectiveMeasures describes any available patches or workarounds.
	CorrectiveMeasures string `json:"corrective_measures,omitempty"`
	// UserMitigations describes recommended actions for end users.
	UserMitigations string `json:"user_mitigations,omitempty"`
	// SensitivityFlag indicates whether the notification contains sensitive information
	// that should not be published before a coordinated disclosure window.
	SensitivityFlag bool `json:"sensitivity_flag"`
}

// Art14FinalReport covers the Art. 14(2)(c) final report obligation.
// This block is populated via `wardex art14 finalize` once a corrective measure
// is available and must be submitted no later than 14 days after that date.
type Art14FinalReport struct {
	Deadline                 time.Time `json:"deadline,omitempty"`  // PatchAvailableAt + 14 days
	PatchAvailableAt         time.Time `json:"patch_available_at,omitempty"`
	VulnerabilityDescription string    `json:"vulnerability_description,omitempty"`
	Severity                 string    `json:"severity,omitempty"`
	Impact                   string    `json:"impact,omitempty"`
	ThreatActorInfo          string    `json:"threat_actor_info,omitempty"`
	SecurityUpdateDetails    string    `json:"security_update_details,omitempty"`
}
