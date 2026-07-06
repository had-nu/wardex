package configseal_test

import (
	"testing"

	"github.com/had-nu/wardex/v2/cmd/configseal"
)

func TestConfigCmdHasSubcommands(t *testing.T) {
	cmd := configseal.ConfigCmd

	// Verify subcommands exist
	found := map[string]bool{"seal": false, "hash": false, "show": false}
	for _, child := range cmd.Commands() {
		if _, ok := found[child.Use]; ok {
			found[child.Use] = true
		}
	}

	for name, exists := range found {
		if !exists {
			t.Errorf("expected subcommand %q to exist", name)
		}
	}
}

func TestShowCmdHasFlags(t *testing.T) {
	cmd := configseal.ShowCmd

	// Verify the command has the required flags
	if cmd.Flags().Lookup("config") == nil {
		t.Error("expected --config flag to exist")
	}
}
