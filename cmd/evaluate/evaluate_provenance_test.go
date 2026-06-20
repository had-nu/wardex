package evaluate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/had-nu/wardex/v2/pkg/model"
	"gopkg.in/yaml.v3"
)

func TestEvaluateProvenance(t *testing.T) {
	tmpDir := t.TempDir()
	evidenceFile := filepath.Join(tmpDir, "evidence.yaml")
	configPath = filepath.Join(tmpDir, "config.yaml")
	_ = os.WriteFile(configPath, []byte("release_gate: {enabled: true}"), 0600)

	// Mock environment
	oldExit := exitFunc
	oldStderr := stderr
	var capturedExitCode int
	exitFunc = func(code int) { capturedExitCode = code }
	stderr = ioDiscard()
	defer func() {
		exitFunc = oldExit
		stderr = oldStderr
	}()

	t.Run("WarnOnMissingConvertedBy", func(t *testing.T) {
		// Non-canonical evidence (raw list)
		vulns := []model.Vulnerability{{CVEID: "CVE-1", CVSSBase: 5.0}}
		data, _ := yaml.Marshal(map[string]any{"vulnerabilities": vulns})
		_ = os.WriteFile(evidenceFile, data, 0600)

		gateFile = evidenceFile
		strict = false
		capturedExitCode = -1

		_ = runEvaluate(&cobra.Command{}, []string{})
		if capturedExitCode == exitcodes.IntegrityFailure {
			t.Errorf("Should not have failed on missing provenance without --strict")
		}
	})

	t.Run("FailOnMissingConvertedByWithStrict", func(t *testing.T) {
		gateFile = evidenceFile
		strict = true
		capturedExitCode = -1

		_ = runEvaluate(&cobra.Command{}, []string{})
		if capturedExitCode != exitcodes.IntegrityFailure {
			t.Errorf("Expected failure (exit 3) on missing provenance with --strict, got %d", capturedExitCode)
		}
	})

	t.Run("PassOnCanonicalEvidence", func(t *testing.T) {
		evidence := model.VulnerabilityEnvelope{
			ConvertedBy:     "wardex-convert/test",
			Vulnerabilities: []model.Vulnerability{{CVEID: "CVE-1", CVSSBase: 5.0}},
		}
		data, _ := yaml.Marshal(evidence)
		_ = os.WriteFile(evidenceFile, data, 0600)

		gateFile = evidenceFile
		strict = false // Avoid strict config check in unit test
		capturedExitCode = -1

		_ = runEvaluate(&cobra.Command{}, []string{})
		if capturedExitCode == exitcodes.IntegrityFailure {
			t.Errorf("Should have passed with canonical evidence")
		}
	})
}
