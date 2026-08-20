// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

// Package store persists acceptance records to the YAML store and keeps it
// consistent with the chained audit log.
package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/pkg/accept/audit"
	"github.com/had-nu/wardex/v2/pkg/accept/verify"
	"github.com/had-nu/wardex/v2/pkg/atomicwrite"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

// ErrStoreInconsistent is returned when the acceptance store has fewer YAML
// entries than audit log events, indicating possible tampering or data loss.
var ErrStoreInconsistent = errors.New("store inconsistency: yaml entries < audit log events")

// Load reads wardex-acceptances.yaml and sequentially executes verify logic.
// Rejected acceptances (expired, tampered, revoked) are logged to logw when non-nil.
func Load(path string, key []byte, auditPath string, currentReportHash string, currentConfigHash string, logw io.Writer) ([]model.Acceptance, error) {
	data, err := cli.SafeReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // First time
		}
		return nil, err
	}

	var st model.AcceptanceStore
	if err := yaml.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("failed to parse acceptances: %w", err)
	}

	countCreated, err := audit.AuditCountCreated(auditPath)
	if err != nil {
		return nil, fmt.Errorf("failed to count audit log events: %w", err)
	}

	if len(st.Acceptances) < countCreated {
		return nil, ErrStoreInconsistent
	}

	results, allValid := verify.VerifyAll(st.Acceptances, key, currentReportHash, currentConfigHash)
	if !allValid {
		for _, res := range results {
			if res.Tampered {
				return nil, fmt.Errorf("tampered acceptance detected: entry %s failed signature validation", res.Acceptance.ID)
			}
		}
	}

	// Return only non-expired and valid, logging rejections
	var validAcceptances []model.Acceptance
	for _, res := range results {
		if res.Valid {
			validAcceptances = append(validAcceptances, res.Acceptance)
		} else if logw != nil {
			reason := "unknown"
			switch {
			case res.Expired:
				reason = "expired"
			case res.Tampered:
				reason = "tampered"
			case res.Stale:
				reason = "config changed since acceptance"
			case res.ReportMismatch:
				reason = "report hash mismatch"
			}
			fmt.Fprintf(logw, "[REJECT] Acceptance %s for %s — %s\n", res.Acceptance.ID, res.Acceptance.CVE, reason)
		}
	}

	return validAcceptances, nil
}

// Append atomically writes a new Acceptance to the store
func Append(path string, a model.Acceptance) error {
	safePathStr, err := cli.SafePath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(safePathStr)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	// Read existing
	data, err := cli.SafeReadFile(path)
	var st model.AcceptanceStore
	if err == nil {
		if err := yaml.Unmarshal(data, &st); err != nil {
			return err
		}
	}
	st.Acceptances = append(st.Acceptances, a)

	out, err := yaml.Marshal(st)
	if err != nil {
		return err
	}

	return atomicwrite.Write(safePathStr, out)
}

// UpdateStatus actualiza status e RevocationRecord. Regenera assinatura.
func UpdateStatus(path string, id string, status string, revocation *model.RevocationRecord, key []byte) error {
	safePathStr, err := cli.SafePath(path)
	if err != nil {
		return err
	}
	data, err := cli.SafeReadFile(path)
	if err != nil {
		return err
	}

	var st model.AcceptanceStore
	if err := yaml.Unmarshal(data, &st); err != nil {
		return err
	}

	found := false
	for i, a := range st.Acceptances {
		if a.ID == id {
			if status == "revoked" {
				st.Acceptances[i].Revoked = true
				if revocation != nil {
					st.Acceptances[i].RevokedBy = revocation.RevokedBy
					st.Acceptances[i].RevokedAt = revocation.RevokedAt
					st.Acceptances[i].RevokeReason = revocation.Reason
					st.Acceptances[i].Revocation = revocation
				}
			}

			// Regenerate signature
			sig, err := verify.Sign(st.Acceptances[i], key)
			if err != nil {
				return err
			}
			st.Acceptances[i].Signature = sig

			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("acceptance ID %s not found", id)
	}

	out, err := yaml.Marshal(st)
	if err != nil {
		return err
	}

	return atomicwrite.Write(safePathStr, out)
}
