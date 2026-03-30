// Package policy defines the schema and validation logic for Wardex
// compliance policy files. Each file represents one domain within a
// framework (e.g. iso27001/technological_controls.yml).
package policy

// Status represents the compliance state of a control.
type Status string

const (
	StatusCompliant     Status = "compliant"
	StatusPartial       Status = "partial"
	StatusNonCompliant  Status = "non_compliant"
	StatusNotApplicable Status = "not_applicable"
)

// validStatuses is the authoritative set of allowed Status values.
// Using a map keeps the validation O(1) and avoids a switch that
// grows with every new status — Rule 4 (simple data structures).
var validStatuses = map[Status]bool{
	StatusCompliant:     true,
	StatusPartial:       true,
	StatusNonCompliant:  true,
	StatusNotApplicable: true,
}

// Exception documents a formally approved deviation from a control.
type Exception struct {
	Reason     string `yaml:"reason"`
	Expiry     string `yaml:"expiry"`      // ISO-8601 date, e.g. "2025-09-01"
	ApprovedBy string `yaml:"approved_by"` // role or name of approver
}

// Control is a single auditable control within a domain.
type Control struct {
	ID                 string      `yaml:"id"`
	Title              string      `yaml:"title"`
	Status             Status      `yaml:"status"`
	Owner              string      `yaml:"owner"`
	ImplementationNote string      `yaml:"implementation_note"`
	EvidenceRefs       []string    `yaml:"evidence_refs"`
	LastAssessed       string      `yaml:"last_assessed"` // ISO-8601 date
	Exceptions         []Exception `yaml:"exceptions"`
}

// DomainFile is the top-level structure of a domain YAML file.
// One file per domain section of a framework (e.g. Annex A.8).
type DomainFile struct {
	Framework    string    `yaml:"framework"`
	Version      string    `yaml:"version"`      // framework version, not wardex version
	Domain       string    `yaml:"domain"`       // machine-friendly slug
	Annex        string    `yaml:"annex"`        // e.g. "A.8", "PR", "ID"
	LastReviewed string    `yaml:"last_reviewed"`
	ReviewedBy   string    `yaml:"reviewed_by"`
	Controls     []Control `yaml:"controls"`
}
