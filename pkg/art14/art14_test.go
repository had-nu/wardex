// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package art14

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/model"
)

// testDir creates a temporary directory within the workspace for testing.
func testDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cwd, "art14-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func testConfig() Config {
	return Config{
		ProductName:    "Test Product",
		ProductVersion: "1.0.0",
		GeneratedBy:    "wardex/v2.5.0",
		WardexActor:    "test@example.com",
	}
}

func testCVEs() []string {
	return []string{"CVE-2024-1234", "CVE-2024-5678"}
}

func testKey(t *testing.T) []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func testArtefact(t *testing.T) (*model.Art14NotificationArtefact, []byte) {
	cfg := testConfig()
	key := testKey(t)
	a, err := GenerateArtefact(testCVEs(), time.Now().UTC(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignArtefact(a, key); err != nil {
		t.Fatal(err)
	}
	return a, key
}

func TestNewUUID(t *testing.T) {
	id := newUUID()
	if len(id) != 36 {
		t.Fatalf("expected UUID length 36, got %d", len(id))
	}
	// Verify format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
	if id[14] != '4' {
		t.Fatalf("expected version 4 UUID")
	}
	if id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b' {
		t.Fatalf("expected variant bits")
	}
}

func TestGenerateArtefact_Basic(t *testing.T) {
	cfg := testConfig()
	cves := testCVEs()
	awarenessAt := time.Now().UTC()

	a, err := GenerateArtefact(cves, awarenessAt, cfg)
	if err != nil {
		t.Fatalf("GenerateArtefact failed: %v", err)
	}

	if a.ArtefactID == "" {
		t.Fatal("expected non-empty ArtefactID")
	}
	if a.Status != "draft" {
		t.Fatalf("expected status 'draft', got %q", a.Status)
	}
	if a.GeneratedBy != cfg.GeneratedBy {
		t.Fatalf("expected GeneratedBy %q, got %q", cfg.GeneratedBy, a.GeneratedBy)
	}
	if a.WardexActor != cfg.WardexActor {
		t.Fatalf("expected WardexActor %q, got %q", cfg.WardexActor, a.WardexActor)
	}
	if a.EarlyWarning.AwarenessTimestamp != awarenessAt.UTC() {
		t.Fatalf("expected AwarenessTimestamp %v, got %v", awarenessAt.UTC(), a.EarlyWarning.AwarenessTimestamp)
	}
	if a.EarlyWarning.Deadline != awarenessAt.UTC().Add(EarlyWarningWindow) {
		t.Fatalf("expected EarlyWarning deadline %v, got %v", awarenessAt.UTC().Add(EarlyWarningWindow), a.EarlyWarning.Deadline)
	}
	if a.Notification.Deadline != awarenessAt.UTC().Add(NotificationWindow) {
		t.Fatalf("expected Notification deadline %v, got %v", awarenessAt.UTC().Add(NotificationWindow), a.Notification.Deadline)
	}
	if a.Notification.ProductName != cfg.ProductName {
		t.Fatalf("expected ProductName %q, got %q", cfg.ProductName, a.Notification.ProductName)
	}
	if a.Notification.ProductVersion != cfg.ProductVersion {
		t.Fatalf("expected ProductVersion %q, got %q", cfg.ProductVersion, a.Notification.ProductVersion)
	}
	if len(a.Notification.CVEIDs) != len(testCVEs()) {
		t.Fatalf("expected %d CVEs, got %d", len(testCVEs()), len(a.Notification.CVEIDs))
	}
}

func TestGenerateArtefact_EmptyCVEs(t *testing.T) {
	cfg := testConfig()
	_, err := GenerateArtefact([]string{}, time.Now().UTC(), cfg)
	if err == nil {
		t.Fatal("expected error for empty CVEs")
	}
	if !strings.Contains(err.Error(), "at least one CVE") {
		t.Fatalf("expected CVE error, got: %v", err)
	}
}

func TestGenerateArtefact_DefaultProduct(t *testing.T) {
	cfg := testConfig()
	cfg.ProductName = ""
	cfg.ProductVersion = ""

	a, err := GenerateArtefact(testCVEs(), time.Now().UTC(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.Notification.ProductName != OperatorPlaceholder {
		t.Fatalf("expected ProductName %q, got %q", OperatorPlaceholder, a.Notification.ProductName)
	}
	if a.Notification.ProductVersion != OperatorPlaceholder {
		t.Fatalf("expected ProductVersion %q, got %q", OperatorPlaceholder, a.Notification.ProductVersion)
	}
}

func TestCanonicalJSON_HMACZeroed(t *testing.T) {
	a, _ := testArtefact(t)

	data, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}

	var parsed model.Art14NotificationArtefact
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.HMAC != "" {
		t.Fatal("expected HMAC to be zeroed in canonical JSON")
	}
}

func TestSignArtefact_Verify(t *testing.T) {
	a, key := testArtefact(t)

	if err := VerifyArtefact(a, key); err != nil {
		t.Fatalf("VerifyArtefact failed: %v", err)
	}
}

func TestVerifyArtefact_Tampered(t *testing.T) {
	a, key := testArtefact(t)

	// Tamper with the artefact
	a.Notification.CVEIDs = append(a.Notification.CVEIDs, "CVE-2024-9999")

	err := VerifyArtefact(a, key)
	if err == nil {
		t.Fatal("expected error for tampered artefact")
	}
	if !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("expected tampered error, got: %v", err)
	}
}

func TestWriteArtefact_ReadArtefact(t *testing.T) {
	tmp := testDir(t)
	a, _ := testArtefact(t)

	path, err := WriteArtefact(a, tmp)
	if err != nil {
		t.Fatalf("WriteArtefact failed: %v", err)
	}

	readA, err := ReadArtefact(path)
	if err != nil {
		t.Fatalf("ReadArtefact failed: %v", err)
	}

	if readA.ArtefactID != a.ArtefactID {
		t.Fatalf("expected ArtefactID %q, got %q", a.ArtefactID, readA.ArtefactID)
	}
	if readA.HMAC != a.HMAC {
		t.Fatalf("HMAC mismatch: got %q, want %q", readA.HMAC, a.HMAC)
	}
}

func TestWriteArtefact_FilePermissions(t *testing.T) {
	tmp := testDir(t)
	a, _ := testArtefact(t)

	path, err := WriteArtefact(a, tmp)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %04o", info.Mode().Perm())
	}
}

func TestListArtefacts(t *testing.T) {
	tmp := testDir(t)
	a1, _ := testArtefact(t)
	a2, _ := testArtefact(t)

	if _, err := WriteArtefact(a1, tmp); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteArtefact(a2, tmp); err != nil {
		t.Fatal(err)
	}

	artefacts, err := ListArtefacts(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(artefacts) != 2 {
		t.Fatalf("expected 2 artefacts, got %d", len(artefacts))
	}
}

func TestListArtefacts_IgnoresNonArt14Files(t *testing.T) {
	tmp := testDir(t)
	a, _ := testArtefact(t)

	if _, err := WriteArtefact(a, tmp); err != nil {
		t.Fatal(err)
	}

	// Create a non-art14 file
	os.WriteFile(filepath.Join(tmp, "other.txt"), []byte("test"), 0600)

	artefacts, err := ListArtefacts(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(artefacts) != 1 {
		t.Fatalf("expected 1 artefact, got %d", len(artefacts))
	}
}

func TestFindArtefactByID(t *testing.T) {
	tmp := testDir(t)
	a, _ := testArtefact(t)

	path, err := WriteArtefact(a, tmp)
	if err != nil {
		t.Fatal(err)
	}

	foundPath, foundA, err := FindArtefactByID(tmp, a.ArtefactID)
	if err != nil {
		t.Fatal(err)
	}
	if foundPath != path {
		t.Fatalf("expected path %q, got %q", path, foundPath)
	}
	if foundA.ArtefactID != a.ArtefactID {
		t.Fatalf("expected ArtefactID %q, got %q", a.ArtefactID, foundA.ArtefactID)
	}
}

func TestFindArtefactByID_NotFound(t *testing.T) {
	tmp := testDir(t)

	_, _, err := FindArtefactByID(tmp, "non-existent-id")
	if err == nil {
		t.Fatal("expected error for non-existent ID")
	}
}

func TestMarkDispatched(t *testing.T) {
	tmp := testDir(t)
	a, _ := testArtefact(t)
	path, err := WriteArtefact(a, tmp)
	if err != nil {
		t.Fatal(err)
	}

	key := testKey(t)
	if err := MarkDispatched(path, "early-warning", key); err != nil {
		t.Fatal(err)
	}

	// Read back and verify
	readA, err := ReadArtefact(path)
	if err != nil {
		t.Fatal(err)
	}
	if readA.Status != "dispatched:early-warning" {
		t.Fatalf("expected status 'dispatched:early-warning', got %q", readA.Status)
	}

	// Verify signature is still valid
	if err := VerifyArtefact(readA, key); err != nil {
		t.Fatalf("signature invalid after marking dispatched: %v", err)
	}
}

func TestMarkDispatched_InvalidPhase(t *testing.T) {
	tmp := testDir(t)
	a, _ := testArtefact(t)
	path, _ := WriteArtefact(a, tmp)

	key := testKey(t)
	err := MarkDispatched(path, "invalid-phase", key)
	if err == nil {
		t.Fatal("expected error for invalid phase")
	}
}

func TestIsDispatched(t *testing.T) {
	a := &model.Art14NotificationArtefact{Status: "dispatched:early-warning"}
	if !IsDispatched(a) {
		t.Fatal("expected true for dispatched status")
	}

	a.Status = "draft"
	if IsDispatched(a) {
		t.Fatal("expected false for draft status")
	}

	a.Status = "dispatched:notification"
	if !IsDispatched(a) {
		t.Fatal("expected true for dispatched:notification")
	}
}

func TestCanonicalJSON_HMAC(t *testing.T) {
	a, _ := testArtefact(t)
	key := testKey(t)

	// Sign first
	if err := SignArtefact(a, key); err != nil {
		t.Fatal(err)
	}

	data, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}

	var parsed model.Art14NotificationArtefact
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.HMAC != "" {
		t.Fatal("expected HMAC zeroed")
	}
}

func FuzzGenerateArtefact(f *testing.F) {
	f.Add("CVE-2024-1234", "2024-01-01T00:00:00Z", "Test", "1.0", "wardex", "test@example.com")

	f.Fuzz(func(t *testing.T, cve string, awarenessAt string, productName, productVersion, generatedBy, wardexActor string) {
		if cve == "" {
			return
		}
		awarenessAtTime, err := time.Parse(time.RFC3339, awarenessAt)
		if err != nil {
			return
		}
		cfg := Config{
			ProductName:    productName,
			ProductVersion: productVersion,
			GeneratedBy:    generatedBy,
			WardexActor:    wardexActor,
		}
		_, _ = GenerateArtefact([]string{cve}, awarenessAtTime, cfg)
	})
}

func FuzzCanonicalJSON(f *testing.F) {
	f.Add([]byte(`{"artefact_id":"test","status":"draft","hmac":""}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var a model.Art14NotificationArtefact
		if err := json.Unmarshal(data, &a); err != nil {
			return
		}
		canonicalJSON(&a)
	})
}

func FuzzVerifyArtefact(f *testing.F) {
	f.Add([]byte(`{"artefact_id":"test","status":"draft","hmac":"invalid"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var a model.Art14NotificationArtefact
		if err := json.Unmarshal(data, &a); err != nil {
			return
		}
		key := make([]byte, 32)
		rand.Read(key)
		VerifyArtefact(&a, key)
	})
}