package evaluate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

func TestEvaluateWritesGateAuditLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "gate.log")
	evidenceFile := filepath.Join(tmpDir, "evidence.yaml")

	// Create canonical evidence
	evidence := model.VulnerabilityEnvelope{
		ConvertedBy: "test-converter",
		Vulnerabilities: []model.Vulnerability{
			{CVEID: "CVE-2024-0001", CVSSBase: 5.0},
		},
	}
	data, _ := yaml.Marshal(evidence)
	_ = os.WriteFile(evidenceFile, data, 0600)

	// Setup mockable environment
	oldExit := exitFunc
	oldStderr := stderr
	exitFunc = func(code int) {}
	stderr = ioDiscard()
	defer func() {
		exitFunc = oldExit
		stderr = oldStderr
	}()

	// Setup flags
	gateLogPath = logPath
	gateFile = evidenceFile
	configPath = filepath.Join(tmpDir, "config.yaml")
	_ = os.WriteFile(configPath, []byte("release_gate: {enabled: true, risk_appetite: 1.0}"), 0600)
	strict = false

	// Run
	err := runEvaluate(&cobra.Command{}, []string{})
	if err != nil {
		t.Fatalf("runEvaluate failed: %v", err)
	}

	// Verify log
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Log file not created: %v", err)
	}

	var entry model.AuditEntry
	if err := json.Unmarshal(logData, &entry); err != nil {
		t.Fatalf("Invalid JSON in log: %v", err)
	}

	if entry.Event != "gate.evaluated" {
		t.Errorf("Expected event gate.evaluated, got %s", entry.Event)
	}
	if entry.OverallDecision != "allow" {
		t.Errorf("Expected decision allow, got %s", entry.OverallDecision)
	}
}

type discardWriter struct{}
func (d discardWriter) Write(p []byte) (n int, err error) { return len(p), nil }
func ioDiscard() *os.File {
	return os.NewFile(0, os.DevNull)
}
