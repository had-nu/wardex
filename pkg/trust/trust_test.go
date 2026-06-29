// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package trust_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/trust"
)

func TestKeypairGeneration(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "keyring.wex")

	pub, err := trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	if pub == nil {
		t.Fatalf("GenerateKeypair returned nil public key")
	}

	// Verify permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if info.Mode().Perm() != 0400 {
		t.Errorf("expected mode 0400, got %04o", info.Mode().Perm())
	}

	// Verify load
	priv, err := trust.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}

	// Verify sign/verify
	msg := []byte("test message")
	sig := trust.Sign(priv, msg)
	if err := trust.Verify(pub, msg, sig); err != nil {
		t.Errorf("Verify failed for valid signature: %v", err)
	}
}

func TestEnforceKeyringPermissions(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "keyring.wex")

	_, err := trust.GenerateKeypair(keyPath, false)
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Mess up permissions
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err = trust.LoadPrivateKey(keyPath)
	if err == nil {
		t.Errorf("LoadPrivateKey should have failed on 0644 permissions")
	} else if !strings.Contains(err.Error(), "must be 0400 or 0600") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestStoreLifecycle(t *testing.T) {
	tmp := t.TempDir()
	adminKeyPath := filepath.Join(tmp, "admin.wex")
	cisoKeyPath := filepath.Join(tmp, "ciso.wex")
	storePath := filepath.Join(tmp, "wardex-trust.yaml")

	// 1. Generate keys
	_, err := trust.GenerateKeypair(adminKeyPath, false)
	if err != nil {
		t.Fatalf("admin keygen: %v", err)
	}
	_, err = trust.GenerateKeypair(cisoKeyPath, false)
	if err != nil {
		t.Fatalf("ciso keygen: %v", err)
	}

	// 2. Init store
	err = trust.InitStore(adminKeyPath, "admin@test.com", "Admin User", storePath)
	if err != nil {
		t.Fatalf("InitStore failed: %v", err)
	}

	store, _, err := trust.LoadStore(storePath)
	if err != nil {
		t.Fatalf("LoadStore failed: %v", err)
	}
	if len(store.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(store.Keys))
	}
	if err := trust.VerifyRootSig(store); err != nil {
		t.Errorf("VerifyRootSig failed on init: %v", err)
	}

	adminKeyID := store.Keys[0].ID

	// 3. Add CISO
	err = trust.AddKey(storePath, adminKeyPath, cisoKeyPath+".pub", trust.RoleCISO, "ciso@test.com", "Ciso User")
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	store, _, err = trust.LoadStore(storePath)
	if err != nil {
		t.Fatalf("LoadStore failed: %v", err)
	}
	if len(store.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(store.Keys))
	}
	if err := trust.VerifyRootSig(store); err != nil {
		t.Errorf("VerifyRootSig failed after add: %v", err)
	}

	cisoKeyID := store.Keys[1].ID

	// 4. Revoke Admin (by itself, allowed since it's admin)
	err = trust.RevokeKey(storePath, adminKeyPath, adminKeyID, "rotated key")
	if err != nil {
		t.Fatalf("RevokeKey failed: %v", err)
	}

	store, _, err = trust.LoadStore(storePath)
	if err != nil {
		t.Fatalf("LoadStore failed: %v", err)
	}
	if len(store.Revocations) != 1 {
		t.Errorf("expected 1 revocation, got %d", len(store.Revocations))
	}
	if err := trust.VerifyRootSig(store); err != nil {
		t.Errorf("VerifyRootSig failed after revoke: %v", err)
	}

	// 5. Verify ActiveKey checks
	_, err = trust.ActiveKey(store, adminKeyID)
	if err == nil {
		t.Errorf("ActiveKey should have failed for revoked key")
	}
	_, err = trust.ActiveKey(store, cisoKeyID)
	if err != nil {
		t.Errorf("ActiveKey failed for active key: %v", err)
	}
}

func TestConfigSeal(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	adminKeyPath := filepath.Join(tmp, "admin.wex")
	storePath := filepath.Join(tmp, "wardex-trust.yaml")
	draftPath := filepath.Join(tmp, "draft.yaml")
	wexPath := filepath.Join(tmp, "wardex.wexstate")

	// Setup trust store
	trust.GenerateKeypair(adminKeyPath, false)
	trust.InitStore(adminKeyPath, "admin@test.com", "Admin", storePath)

	// Valid draft
	draftYAML := `organization:
  name: "Test"
release_gate:
  risk_appetite: 0.5`
	os.WriteFile(draftPath, []byte(draftYAML), 0644)

	// Seal
	err := trust.SealConfig(adminKeyPath, draftPath, wexPath, storePath)
	if err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	// Verify
	state, err := trust.LoadWexState(wexPath)
	if err != nil {
		t.Fatalf("LoadWexState failed: %v", err)
	}
	store, storeRaw, _ := trust.LoadStore(storePath)
	
	if err := trust.VerifySeal(state, store, storeRaw); err != nil {
		t.Errorf("VerifySeal failed: %v", err)
	}
}

func TestPendingApprovalDetection(t *testing.T) {
	yamlContent := `
organization:
  name: "PENDING_APPROVAL"
  list:
    - 1
    - "PENDING_APPROVAL"
release_gate:
  risk_appetite: 0.5
`
	pending, err := trust.DetectPendingApproval([]byte(yamlContent))
	if err != nil {
		t.Fatalf("DetectPendingApproval failed: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("expected 2 pending fields, got %d", len(pending))
	}
}
