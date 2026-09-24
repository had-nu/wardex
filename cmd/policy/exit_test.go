package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/exitcodes"
	"github.com/spf13/cobra"
)

func TestPolicyCheckExpiryPreservesExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	policyFile := filepath.Join(dir, "controls.yml")
	contents := []byte(`framework: test
domain: protect
controls:
  - id: A.1
    title: Test control
    status: compliant
    exceptions:
      - expiry: "2000-01-01"
        reason: old exception
`)
	if err := os.WriteFile(policyFile, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	oldExit := policyExitFunc
	defer func() { policyExitFunc = oldExit }()
	var code int
	policyExitFunc = func(value int) { code = value }

	var out, errOut bytes.Buffer
	cmd := &cobra.Command{Use: "check-expiry"}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := runPolicyCheckExpiry(cmd, []string{"."}); err != nil {
		t.Fatalf("check-expiry returned error: %v", err)
	}
	if code != exitcodes.ComplianceFail {
		t.Fatalf("expected preserved exit code %d, got %d", exitcodes.ComplianceFail, code)
	}
	if !strings.Contains(out.String(), "expired exception") {
		t.Fatalf("expected legacy result on configured stdout, got %q", out.String())
	}
}
