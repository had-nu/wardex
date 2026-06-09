// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package art14 manages the lifecycle of CRA Article 14 notification artefacts.
// It generates, signs, verifies, and persists artefacts — but never transmits them.
// The operator receives a ready artefact and dispatches it externally.
package art14

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/had-nu/wardex/pkg/model"
)

// newUUID generates a random UUID v4 using crypto/rand.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}


const (
	// EarlyWarningWindow is the Art. 14(2)(a) deadline: 24 hours from awareness.
	EarlyWarningWindow = 24 * time.Hour
	// NotificationWindow is the Art. 14(2)(b) deadline: 72 hours from awareness.
	NotificationWindow = 72 * time.Hour
	// FinalReportWindow is the Art. 14(2)(c) deadline: 14 days from patch availability.
	FinalReportWindow = 14 * 24 * time.Hour

	// OperatorPlaceholder is written to required fields that the operator must complete.
	OperatorPlaceholder = "[OPERATOR: complete before dispatch]"
)

// Config holds the parameters needed to generate an Art14 artefact.
type Config struct {
	ProductName    string
	ProductVersion string
	GeneratedBy    string // e.g. "wardex/v2.0.0"
	WardexActor    string // from WARDEX_ACTOR env var
}

// GenerateArtefact creates a new Art14NotificationArtefact in "draft" status.
// awarenessAt is the timestamp used as the Art. 14 awareness timestamp.
// cves is the list of CVE IDs that are actively exploited in this evaluation.
func GenerateArtefact(cves []string, awarenessAt time.Time, cfg Config) (*model.Art14NotificationArtefact, error) {
	if len(cves) == 0 {
		return nil, fmt.Errorf("art14: at least one CVE ID required")
	}

	productName := cfg.ProductName
	if productName == "" {
		productName = OperatorPlaceholder
	}
	productVersion := cfg.ProductVersion
	if productVersion == "" {
		productVersion = OperatorPlaceholder
	}

	a := &model.Art14NotificationArtefact{
		ArtefactID:  newUUID(),
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: cfg.GeneratedBy,
		WardexActor: cfg.WardexActor,
		Status:      "draft",

		EarlyWarning: model.Art14EarlyWarning{
			AwarenessTimestamp: awarenessAt.UTC(),
			Deadline:           awarenessAt.UTC().Add(EarlyWarningWindow),
		},

		Notification: model.Art14Notification{
			Deadline:            awarenessAt.UTC().Add(NotificationWindow),
			ProductName:         productName,
			ProductVersion:      productVersion,
			CVEIDs:              cves,
			ExploitationNature:  OperatorPlaceholder,
			VulnerabilityNature: OperatorPlaceholder,
			SensitivityFlag:     false,
		},
	}

	return a, nil
}

// canonicalJSON returns the canonical JSON representation of the artefact
// with the HMAC field zeroed out, for use in signature computation.
func canonicalJSON(a *model.Art14NotificationArtefact) ([]byte, error) {
	// Temporarily blank the HMAC field so it does not affect its own hash
	orig := a.HMAC
	a.HMAC = ""
	data, err := json.Marshal(a)
	a.HMAC = orig
	if err != nil {
		return nil, fmt.Errorf("art14: canonical JSON: %w", err)
	}
	return data, nil
}

// SignArtefact computes an HMAC-SHA256 over the canonical JSON of the artefact
// and sets the HMAC field. key is the WARDEX_ACCEPT_SECRET.
func SignArtefact(a *model.Art14NotificationArtefact, key []byte) error {
	data, err := canonicalJSON(a)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	a.HMAC = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// VerifyArtefact recomputes the HMAC and compares it to the stored value.
// Returns an error if the HMAC does not match (tampering detected).
func VerifyArtefact(a *model.Art14NotificationArtefact, key []byte) error {
	data, err := canonicalJSON(a)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(a.HMAC), []byte(expected)) {
		return fmt.Errorf("art14: HMAC mismatch — artefact may have been tampered with")
	}
	return nil
}

// WriteArtefact serialises the artefact to disk as JSON.
// The file is named wardex-art14-{artefact_id}.json in the given directory.
// Returns the absolute path of the written file.
func WriteArtefact(a *model.Art14NotificationArtefact, dir string) (string, error) {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("art14: create output dir: %w", err)
	}

	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return "", fmt.Errorf("art14: marshal artefact: %w", err)
	}

	filename := fmt.Sprintf("wardex-art14-%s.json", a.ArtefactID)
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("art14: write artefact: %w", err)
	}

	return path, nil
}

// ReadArtefact reads and deserialises an Art14 artefact from disk.
func ReadArtefact(path string) (*model.Art14NotificationArtefact, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("art14: read artefact: %w", err)
	}

	var a model.Art14NotificationArtefact
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("art14: parse artefact: %w", err)
	}

	return &a, nil
}

// ListArtefacts returns all Art14 artefacts found in dir.
func ListArtefacts(dir string) ([]*model.Art14NotificationArtefact, error) {
	if dir == "" {
		dir = "."
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("art14: list artefacts: %w", err)
	}

	var artefacts []*model.Art14NotificationArtefact
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "wardex-art14-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		a, err := ReadArtefact(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // skip malformed files
		}
		artefacts = append(artefacts, a)
	}

	return artefacts, nil
}

// FindArtefactByID looks for an artefact file in dir whose ArtefactID matches id.
// Returns the path and the parsed artefact, or an error if not found.
func FindArtefactByID(dir string, id string) (string, *model.Art14NotificationArtefact, error) {
	if dir == "" {
		dir = "."
	}

	// Fast path: construct expected filename
	candidate := filepath.Join(dir, fmt.Sprintf("wardex-art14-%s.json", id))
	if _, err := os.Stat(candidate); err == nil {
		a, err := ReadArtefact(candidate)
		if err == nil && a.ArtefactID == id {
			return candidate, a, nil
		}
	}

	// Fallback: scan all artefacts
	artefacts, err := ListArtefacts(dir)
	if err != nil {
		return "", nil, err
	}
	for _, a := range artefacts {
		if a.ArtefactID == id {
			path := filepath.Join(dir, fmt.Sprintf("wardex-art14-%s.json", id))
			return path, a, nil
		}
	}

	return "", nil, fmt.Errorf("art14: artefact %q not found in %s", id, dir)
}

// MarkDispatched updates the artefact status to "dispatched" and re-signs it.
// phase must be one of: "early-warning", "notification", "final-report".
func MarkDispatched(path string, phase string, key []byte) error {
	validPhases := map[string]bool{
		"early-warning":  true,
		"notification":   true,
		"final-report":   true,
	}
	if !validPhases[phase] {
		return fmt.Errorf("art14: invalid phase %q — must be early-warning, notification, or final-report", phase)
	}

	a, err := ReadArtefact(path)
	if err != nil {
		return err
	}

	a.Status = fmt.Sprintf("dispatched:%s", phase)
	if err := SignArtefact(a, key); err != nil {
		return err
	}

	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("art14: marshal updated artefact: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// IsDispatched returns true if the artefact has been marked as dispatched for any phase.
func IsDispatched(a *model.Art14NotificationArtefact) bool {
	return strings.HasPrefix(a.Status, "dispatched")
}
