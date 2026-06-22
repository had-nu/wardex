// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package art14

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/had-nu/wardex/v2/pkg/art14"
	"github.com/had-nu/wardex/v2/pkg/model"
	"github.com/spf13/cobra"
)

func TestArt14CLI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARDEX_ACCEPT_SECRET", "test-secret-key-123456789012345678901234")

	// Pre-create a draft artefact
	cfgArt := art14.Config{
		ProductName:    "Test",
		ProductVersion: "1.0",
		GeneratedBy:    "wardex/v2.0.0",
	}
	art, err := art14.GenerateArtefact([]string{"CVE-2024-3094"}, time.Now().UTC(), cfgArt)
	if err != nil {
		t.Fatal(err)
	}

	secretKey := []byte("test-secret-key-123456789012345678901234")
	_ = art14.SignArtefact(art, secretKey)
	path, err := art14.WriteArtefact(art, dir)
	if err != nil {
		t.Fatal(err)
	}

	configPathFile := filepath.Join(dir, "config.yaml")
	logPath := filepath.Join(dir, "gate.log")
	configContent := `
release_gate:
  enabled: true
reporting:
  gate_log:
    path: "` + logPath + `"
cra:
  art14:
    output_dir: "` + dir + `"
`
	_ = os.WriteFile(configPathFile, []byte(configContent), 0600)

	// Set CLI flag vars
	configPath = configPathFile
	artOutputDir = dir

	// 1. Test List
	var bufList bytes.Buffer
	listCmd := &cobra.Command{}
	listCmd.SetOut(&bufList)

	err = runList(listCmd, []string{})
	if err != nil {
		t.Fatalf("runList failed: %v", err)
	}

	listOut := bufList.String()
	if !strings.Contains(listOut, art.ArtefactID[:7]) {
		t.Errorf("expected artefact ID prefix %s in list output, got %q", art.ArtefactID[:7], listOut)
	}

	// 2. Test Show
	var bufShow bytes.Buffer
	showCmd := &cobra.Command{}
	showCmd.SetOut(&bufShow)

	err = runShow(showCmd, []string{art.ArtefactID})
	if err != nil {
		t.Fatalf("runShow failed: %v", err)
	}

	showOut := bufShow.String()
	var readArt model.Art14NotificationArtefact
	if err := json.Unmarshal([]byte(showOut), &readArt); err != nil {
		t.Fatalf("failed to parse show output as JSON: %v", err)
	}
	if readArt.ArtefactID != art.ArtefactID {
		t.Errorf("expected ID %q, got %q", art.ArtefactID, readArt.ArtefactID)
	}

	// 3. Test Verify PASS
	var bufVerify bytes.Buffer
	verifyCmd := &cobra.Command{}
	verifyCmd.SetOut(&bufVerify)

	err = runVerify(verifyCmd, []string{art.ArtefactID})
	if err != nil {
		t.Fatalf("runVerify failed: %v", err)
	}
	if !strings.Contains(bufVerify.String(), "[PASS]") {
		t.Errorf("expected verification to pass, got: %q", bufVerify.String())
	}

	// 4. Test Finalize (non-interactive)
	finalizeCmd := &cobra.Command{}
	finalizeCmd.SetOut(os.Stdout)
	nonInteractive = true
	patchDate = "2026-06-09T15:00:00Z"
	vulnDesc = "backdoored build system in xz"
	severity = "CRITICAL"
	impact = "remote code execution"
	threatActor = "unknown APT"
	updateDetails = "upgrade xz to 5.6.1"

	err = runFinalize(finalizeCmd, []string{art.ArtefactID})
	if err != nil {
		t.Fatalf("runFinalize failed: %v", err)
	}

	// Reload artefact and verify fields are updated and HMAC is valid
	updatedArt, err := art14.ReadArtefact(path)
	if err != nil {
		t.Fatal(err)
	}
	if updatedArt.FinalReport.Severity != "CRITICAL" || updatedArt.FinalReport.VulnerabilityDescription != "backdoored build system in xz" {
		t.Errorf("fields not updated in finalized report: %+v", updatedArt.FinalReport)
	}
	if err := art14.VerifyArtefact(updatedArt, secretKey); err != nil {
		t.Errorf("HMAC signature invalid after finalization: %v", err)
	}

	// 5. Test Mark Dispatched
	var bufMark bytes.Buffer
	markCmd := &cobra.Command{}
	markCmd.SetOut(&bufMark)
	phase = "early-warning"

	err = runMarkDispatched(markCmd, []string{art.ArtefactID})
	if err != nil {
		t.Fatalf("runMarkDispatched failed: %v", err)
	}

	// Reload and verify status
	dispatchedArt, _ := art14.ReadArtefact(path)
	if dispatchedArt.Status != "dispatched:early-warning" {
		t.Errorf("expected status 'dispatched:early-warning', got %q", dispatchedArt.Status)
	}

	// Verify gate audit log entry
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected audit log to be created: %v", err)
	}
	var auditEntry model.AuditEntry
	if err := json.Unmarshal(logData, &auditEntry); err != nil {
		t.Fatal(err)
	}
	if auditEntry.Event != "active-exploit.dispatched" {
		t.Errorf("expected event active-exploit.dispatched, got %q", auditEntry.Event)
	}

	// 6. Test Verify TAMPERED
	// Let's modify the file manually to break HMAC
	dispatchedArt.WardexActor = "attacker"
	dataBytes, _ := json.Marshal(dispatchedArt)
	_ = os.WriteFile(path, dataBytes, 0600)

	// Mock exitFunc to prevent os.Exit from killing the test
	origExit := exitFunc
	exitCalled := false
	exitFunc = func(code int) {
		exitCalled = true
	}
	t.Cleanup(func() { exitFunc = origExit })

	var bufVerify2 bytes.Buffer
	verifyCmd2 := &cobra.Command{}
	verifyCmd2.SetOut(&bufVerify2)

	err = runVerify(verifyCmd2, []string{art.ArtefactID})
	if err != nil {
		t.Fatalf("runVerify should not return error when exitFunc is mocked: %v", err)
	}
	if !strings.Contains(bufVerify2.String(), "[TAMPERED]") {
		t.Errorf("expected tampered message, got: %q", bufVerify2.String())
	}
	if !exitCalled {
		t.Error("expected exitFunc to be called on tampered artefact")
	}
}
