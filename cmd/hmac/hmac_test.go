package hmac_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/cmd/hmac"
)

func TestHMACCmdHasSubcommands(t *testing.T) {
	cmd := hmac.HMACCmd

	// Verify sign subcommand exists
	found := false
	for _, child := range cmd.Commands() {
		if child.Use == "sign" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected subcommand 'sign' to exist")
	}
}

func TestHMACCmdUse(t *testing.T) {
	cmd := hmac.HMACCmd
	if cmd.Use != "hmac" {
		t.Errorf("expected Use to be 'hmac', got %q", cmd.Use)
	}
}

func TestSignCmdHasFlags(t *testing.T) {
	cmd := hmac.SignCmd

	// Verify the command has the required flags
	if cmd.Flags().Lookup("file") == nil {
		t.Error("expected --file flag to exist")
	}
	if cmd.Flags().Lookup("secret-env") == nil {
		t.Error("expected --secret-env flag to exist")
	}
	if cmd.Flags().Lookup("output") == nil {
		t.Error("expected --output flag to exist")
	}
}

func TestSignCmdExecution(t *testing.T) {
	// Create a temporary directory within the current workspace
	cwd, _ := os.Getwd()
	dir := filepath.Join(cwd, ".test-hmac-sign-tmp")
	os.MkdirAll(dir, 0755)
	defer os.RemoveAll(dir)

	// Create test file
	testFile := filepath.Join(dir, "test.txt")
	os.WriteFile(testFile, []byte("hello world"), 0644)

	// Set the secret in env (must be at least 32 characters)
	os.Setenv("WARDEX_TEST_SECRET", "test-secret-key-that-is-at-least-32-chars")
	defer os.Unsetenv("WARDEX_TEST_SECRET")

	// Output file
	output := filepath.Join(dir, "test.txt.hmac")

	// Execute the hmac sign command via parent
	cmd := hmac.HMACCmd
	cmd.SetArgs([]string{"sign", "--file", testFile, "--secret-env", "WARDEX_TEST_SECRET", "--output", output})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("hmac sign command failed: %v", err)
	}

	// Verify output file exists
	if _, err := os.Stat(output); os.IsNotExist(err) {
		t.Error("expected output file to exist")
	}
}
