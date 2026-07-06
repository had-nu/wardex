package chain_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/cmd/chain"
)

func TestChainCmdHasSubcommands(t *testing.T) {
	cmd := chain.ChainCmd

	// Verify seal subcommand exists
	found := false
	for _, child := range cmd.Commands() {
		if child.Use == "seal" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected subcommand 'seal' to exist")
	}
}

func TestChainCmdUse(t *testing.T) {
	cmd := chain.ChainCmd
	if cmd.Use != "chain" {
		t.Errorf("expected Use to be 'chain', got %q", cmd.Use)
	}
}

func TestSealCmdHasFlags(t *testing.T) {
	cmd := chain.SealCmd

	// Verify the command has the required flags
	if cmd.Flags().Lookup("output") == nil {
		t.Error("expected --output flag to exist")
	}
	if cmd.Flags().Lookup("exclude") == nil {
		t.Error("expected --exclude flag to exist")
	}
	if cmd.Flags().Lookup("dir") == nil {
		t.Error("expected --dir flag to exist")
	}
}

func TestSealCmdExecution(t *testing.T) {
	// Create a temporary directory within the current workspace
	cwd, _ := os.Getwd()
	dir := filepath.Join(cwd, ".test-chain-seal-tmp")
	os.MkdirAll(dir, 0755)
	defer os.RemoveAll(dir)

	// Create test files
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "test.json"), []byte(`{"key":"value"}`), 0644)

	// Create output file path
	output := filepath.Join(dir, "chain-seal.json")

	// Execute the chain seal command via parent
	cmd := chain.ChainCmd
	cmd.SetArgs([]string{"seal", "--dir", dir, "--output", output})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("seal command failed: %v", err)
	}

	// Verify output file exists
	if _, err := os.Stat(output); os.IsNotExist(err) {
		t.Error("expected output file to exist")
	}
}
