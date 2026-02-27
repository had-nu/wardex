package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/pkg/accept/audit"
	"github.com/had-nu/wardex/pkg/accept/signer"
	"github.com/had-nu/wardex/pkg/accept/verifier"
	"github.com/had-nu/wardex/pkg/model"
	"gopkg.in/yaml.v3"
)

var ErrTampered = errors.New("tampered acceptance detected")
var ErrStoreInconsistent = errors.New("store inconsistency: yaml entries < audit log events")

// Load reads wardex-acceptances.yaml and sequentially executes verify logic.
func Load(path string, key []byte, auditPath string, currentReportHash string, currentConfigHash string) ([]model.Acceptance, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // First time
		}
		return nil, err
	}

	var store model.AcceptanceStore
	if err := yaml.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse acceptances: %w", err)
	}

	countCreated, err := audit.CountCreated(auditPath)
	if err != nil {
		return nil, fmt.Errorf("failed to count audit log events: %w", err)
	}

	if len(store.Acceptances) < countCreated {
		return nil, ErrStoreInconsistent
	}

	results, allValid := verifier.VerifyAll(store.Acceptances, key, currentReportHash, currentConfigHash)
	if !allValid {
		for _, res := range results {
			if res.Tampered {
				return nil, fmt.Errorf("%w: entry %s failed signature validation", ErrTampered, res.Acceptance.ID)
			}
		}
	}

	// Return only non-expired and valid
	var validAcceptances []model.Acceptance
	for _, res := range results {
		if res.Valid {
			validAcceptances = append(validAcceptances, res.Acceptance)
		}
	}

	return validAcceptances, nil
}

// Append atomagically writes a new Acceptance to the store
func Append(path string, a model.Acceptance) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Read existing
	data, err := os.ReadFile(path)
	var store model.AcceptanceStore
	if err == nil {
		yaml.Unmarshal(data, &store)
	}
	store.Acceptances = append(store.Acceptances, a)

	out, err := yaml.Marshal(store)
	if err != nil {
		return err
	}

	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, out, 0644); err != nil {
		return err
	}

	return os.Rename(tempFile, path)
}

// UpdateStatus actualiza status e RevocationRecord. Regenera assinatura.
func UpdateStatus(path string, id string, status string, revocation *model.RevocationRecord, key []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var store model.AcceptanceStore
	if err := yaml.Unmarshal(data, &store); err != nil {
		return err
	}

	found := false
	for i, a := range store.Acceptances {
		if a.ID == id {
			if status == "revoked" {
				store.Acceptances[i].Revoked = true
				if revocation != nil {
					store.Acceptances[i].RevokedBy = revocation.RevokedBy
					store.Acceptances[i].RevokedAt = revocation.RevokedAt
					store.Acceptances[i].RevokeReason = revocation.Reason
					store.Acceptances[i].Revocation = revocation
				}
			}

			// Regenerate signature
			sig, err := signer.Sign(store.Acceptances[i], key)
			if err != nil {
				return err
			}
			store.Acceptances[i].Signature = sig

			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("acceptance ID %s not found", id)
	}

	out, err := yaml.Marshal(store)
	if err != nil {
		return err
	}

	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, out, 0644); err != nil {
		return err
	}

	return os.Rename(tempFile, path)
}
