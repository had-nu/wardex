package contract_test

import (
	"testing"

	"github.com/had-nu/wardex/v2/cmd/contract"
)

func TestContractCmdHasSubcommands(t *testing.T) {
	cmd := contract.ContractCmd

	// Verify verify subcommand exists
	found := false
	for _, child := range cmd.Commands() {
		if child.Use == "verify" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected subcommand 'verify' to exist")
	}
}

func TestContractCmdUse(t *testing.T) {
	cmd := contract.ContractCmd
	if cmd.Use != "contract" {
		t.Errorf("expected Use to be 'contract', got %q", cmd.Use)
	}
}

func TestVerifyCmdHasFlags(t *testing.T) {
	cmd := contract.VerifyCmd

	// Verify the command has the required flags
	if cmd.Flags().Lookup("file") == nil {
		t.Error("expected --file flag to exist")
	}
	if cmd.Flags().Lookup("hash") == nil {
		t.Error("expected --hash flag to exist")
	}
}
