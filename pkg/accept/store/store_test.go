// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package store

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/accept/audit"
	"github.com/had-nu/wardex/v2/pkg/accept/verify"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

// testDir creates a temporary directory within the workspace for testing.
func testDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cwd, "accept-store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// testAcceptance creates a valid acceptance for testing.
func testAcceptance(t *testing.T, id string) model.Acceptance {
	return model.Acceptance{
		ID:              id,
		CVE:             "CVE-2024-1234",
		AcceptedBy:      "tester@test.com",
		Justification:   "test justification",
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
		ExpiresAt:       time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		Ticket:          "TICKET-123",
		ContextRiskScore: 0.5,
		ReportHash:      "sha256:abcdef123456",
		ConfigHash:      "sha256:fedcba654321",
	}
}

// signAcceptance generates a valid HMAC signature for an acceptance.
func signAcceptance(a *model.Acceptance, key []byte) error {
	sig, err := verify.Sign(*a, key)
	if err != nil {
		return err
	}
	a.Signature = sig
	return nil
}

// randomKey generates a random HMAC key for testing.
func randomKey(t *testing.T) []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestLoad_Empty(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	accepted, err := Load(path, key, "", "report-hash", "config-hash", nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if accepted != nil {
		t.Fatalf("expected nil, got %v", accepted)
	}
}

func TestLoad_ValidAcceptance(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	accepted, err := Load(path, key, "", acc.ReportHash, acc.ConfigHash, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(accepted) != 1 {
		t.Fatalf("expected 1 acceptance, got %d", len(accepted))
	}
	if accepted[0].ID != "acc-001" {
		t.Fatalf("expected acc-001, got %s", accepted[0].ID)
	}
}

func TestLoad_TamperedRejected(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	// Tamper with the file
	if err := cli.SafeWriteFile(path, []byte("tampered: true")); err != nil {
		t.Fatal(err)
	}

	accepted, err := Load(path, key, "", "report-hash", "config-hash", nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("expected 0 acceptances (tampered rejected), got %d", len(accepted))
	}
}

func TestLoad_ExpiredRejected(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	acc.ExpiresAt = time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	accepted, err := Load(path, key, "", acc.ReportHash, acc.ConfigHash, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("expected 0 acceptances (expired rejected), got %d", len(accepted))
	}
}

func TestLoad_ReportHashMismatchRejected(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	accepted, err := Load(path, key, "", "different-report-hash", acc.ConfigHash, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("expected 0 acceptances (report hash mismatch rejected), got %d", len(accepted))
	}
}

func TestLoad_ConfigHashMismatchRejected(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	accepted, err := Load(path, key, "", acc.ReportHash, "different-config-hash", nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("expected 0 acceptances (config hash mismatch rejected), got %d", len(accepted))
	}
}

func TestLoad_EmptyReportHashRejected(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	acc.ReportHash = "" // empty
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	accepted, err := Load(path, key, "", acc.ReportHash, acc.ConfigHash, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("expected 0 acceptances (empty ReportHash rejected), got %d", len(accepted))
	}
}

func TestLoad_EmptyConfigHashRejected(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	acc.ConfigHash = "" // empty
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	accepted, err := Load(path, key, "", acc.ReportHash, acc.ConfigHash, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("expected 0 acceptances (empty ConfigHash rejected), got %d", len(accepted))
	}
}

func TestAppend_NewFile(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	if err := Append(path, acc); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Verify file was created and contains the acceptance
	data, err := cli.SafeReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var st model.AcceptanceStore
	if err := yaml.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Acceptances) != 1 {
		t.Fatalf("expected 1 acceptance, got %d", len(st.Acceptances))
	}
	if st.Acceptances[0].ID != "acc-001" {
		t.Fatalf("expected acc-001, got %s", st.Acceptances[0].ID)
	}
}

func TestAppend_AppendToExisting(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc1 := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc1, key); err != nil {
		t.Fatal(err)
	}
	if err := Append(path, acc1); err != nil {
		t.Fatal(err)
	}

	acc2 := testAcceptance(t, "acc-002")
	if err := signAcceptance(&acc2, key); err != nil {
		t.Fatal(err)
	}
	if err := Append(path, acc2); err != nil {
		t.Fatal(err)
	}

	data, _ := cli.SafeReadFile(path)
	var st model.AcceptanceStore
	yaml.Unmarshal(data, &st)
	if len(st.Acceptances) != 2 {
		t.Fatalf("expected 2 acceptances, got %d", len(st.Acceptances))
	}
}

func TestUpdateStatus_Revoked(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}
	if err := Append(path, acc); err != nil {
		t.Fatal(err)
	}

	revokedAt := time.Now().UTC().Truncate(time.Second)
	rev := &model.RevocationRecord{
		RevokedBy: "admin@test.com",
		RevokedAt: revokedAt,
		Reason:    "key rotated",
	}

	if err := UpdateStatus(path, "acc-001", "revoked", rev, key); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	data, _ := cli.SafeReadFile(path)
	var st model.AcceptanceStore
	yaml.Unmarshal(data, &st)
	if len(st.Acceptances) != 1 {
		t.Fatalf("expected 1 acceptance")
	}
	if !st.Acceptances[0].Revoked {
		t.Fatal("expected Revoked=true")
	}
	if st.Acceptances[0].RevokedBy != "admin@test.com" {
		t.Fatalf("expected RevokedBy=admin@test.com, got %s", st.Acceptances[0].RevokedBy)
	}
	if st.Acceptances[0].Revocation == nil {
		t.Fatal("expected RevocationRecord")
	}
	if st.Acceptances[0].Revocation.Reason != "key rotated" {
		t.Fatalf("expected reason 'key rotated', got %s", st.Acceptances[0].Revocation.Reason)
	}
	// Signature should be regenerated
	if st.Acceptances[0].Signature == "" {
		t.Fatal("expected signature to be regenerated")
	}
}

func TestUpdateStatus_NotFound(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")

	// Create empty acceptances file first
	st := model.AcceptanceStore{Acceptances: []model.Acceptance{}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	err := UpdateStatus(path, "nonexistent", "revoked", nil, randomKey(t))
	if err == nil {
		t.Fatal("expected error for nonexistent ID")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

func TestStore_ConcurrentLoadAppend(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	const numOps = 20
	errCh := make(chan error, numOps*2)

	// Concurrent appends
	for i := 0; i < numOps; i++ {
		go func(i int) {
			acc := testAcceptance(t, fmt.Sprintf("acc-%03d", i))
			if err := signAcceptance(&acc, key); err != nil {
				errCh <- err
				return
			}
			errCh <- Append(path, acc)
		}(i)
	}

	for i := 0; i < numOps; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("append error: %v", err)
		}
	}

	// Verify all were written
	data, _ := cli.SafeReadFile(path)
	var st model.AcceptanceStore
	yaml.Unmarshal(data, &st)
	if len(st.Acceptances) != numOps {
		t.Fatalf("expected %d acceptances, got %d", numOps, len(st.Acceptances))
	}
}

func TestLoad_AuditChainConsistency(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	auditPath := filepath.Join(tmp, "audit.log")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}
	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	// Create audit log entry
	auditEntry := model.AuditEntry{
		Timestamp:       time.Now().UTC(),
		Event:           "acceptance.created",
		ConfigHash:      "config-hash",
		OverallDecision: model.DecisionAllow,
		Status:          "allow",
	}
	if err := audit.AuditLog(auditPath, auditEntry); err != nil {
		t.Fatal(err)
	}

	// Load should succeed (1 acceptance, 1 audit entry)
	_, err := Load(path, key, auditPath, "report-hash", "config-hash", nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
}

func TestLoad_InconsistentAuditRejected(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	auditPath := filepath.Join(tmp, "audit.log")
	key := randomKey(t)

	// Two acceptances but only one audit entry
	acc1 := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc1, key); err != nil {
		t.Fatal(err)
	}
	acc2 := testAcceptance(t, "acc-002")
	if err := signAcceptance(&acc2, key); err != nil {
		t.Fatal(err)
	}
	st := model.AcceptanceStore{Acceptances: []model.Acceptance{acc1, acc2}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	// Only one audit entry
	auditEntry := model.AuditEntry{
		Timestamp:       time.Now().UTC(),
		Event:           "acceptance.created",
		ConfigHash:      "config-hash",
		OverallDecision: model.DecisionAllow,
		Status:          "allow",
	}
	if err := audit.AuditLog(auditPath, auditEntry); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path, key, auditPath, "report-hash", "config-hash", nil)
	if err == nil {
		t.Fatal("expected error for inconsistent audit log")
	}
	if !strings.Contains(err.Error(), "inconsistency") && !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("expected inconsistency error, got: %v", err)
	}
}

func TestLoad_LogsRejections(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	// Create one valid, one expired
	validAcc := testAcceptance(t, "acc-valid")
	if err := signAcceptance(&validAcc, key); err != nil {
		t.Fatal(err)
	}
	expiredAcc := testAcceptance(t, "acc-expired")
	expiredAcc.ExpiresAt = time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	if err := signAcceptance(&expiredAcc, key); err != nil {
		t.Fatal(err)
	}

	st := model.AcceptanceStore{Acceptances: []model.Acceptance{validAcc, expiredAcc}}
	data, _ := yaml.Marshal(st)
	if err := cli.SafeWriteFile(path, data); err != nil {
		t.Fatal(err)
	}

	var buf strings.Builder
	_, err := Load(path, key, "", validAcc.ReportHash, validAcc.ConfigHash, &buf)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "REJECT") {
		t.Fatalf("expected REJECT log, got: %s", output)
	}
	if !strings.Contains(output, "expired") {
		t.Fatalf("expected 'expired' in log, got: %s", output)
	}
}

func TestAppend_AtomicWrite(t *testing.T) {
	tmp := testDir(t)
	path := filepath.Join(tmp, "acceptances.yaml")
	key := randomKey(t)

	acc := testAcceptance(t, "acc-001")
	if err := signAcceptance(&acc, key); err != nil {
		t.Fatal(err)
	}

	if err := Append(path, acc); err != nil {
		t.Fatal(err)
	}

	// Verify file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %04o", info.Mode().Perm())
	}
}

// Fuzz tests

func FuzzLoad(f *testing.F) {
	key := make([]byte, 32)
	rand.Read(key)

	f.Fuzz(func(t *testing.T, yamlData []byte) {
		tmp := testDir(t)
		path := filepath.Join(tmp, "acceptances.yaml")
		if err := cli.SafeWriteFile(path, yamlData); err != nil {
			return // invalid YAML, skip
		}
		Load(path, nil, "", "", "", nil)
	})
}

func FuzzAppend(f *testing.F) {
	key := make([]byte, 32)
	rand.Read(key)

	f.Fuzz(func(t *testing.T, id string) {
		tmp := testDir(t)
		path := filepath.Join(tmp, "acceptances.yaml")
		acc := testAcceptance(t, id)
		key := make([]byte, 32)
		rand.Read(key)
		if err := signAcceptance(&acc, key); err != nil {
			return
		}
		Append(path, acc)
	})
}