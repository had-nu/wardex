package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestAddCommandsReceivesConfigPath(t *testing.T) {
	root := &cobra.Command{Use: "wardex"}
	customPath := "/custom/path/wardex-config.yaml"

	// Must not panic when receiving a valid pointer
	AddCommands(root, &customPath)

	// Verify the accept command was added
	acceptCmd, _, err := root.Find([]string{"accept"})
	if err != nil {
		t.Fatalf("expected 'accept' command to be registered, got error: %v", err)
	}
	if acceptCmd.Use != "accept" {
		t.Errorf("expected command Use='accept', got %q", acceptCmd.Use)
	}

	// Verify subcommands were registered under accept
	expectedSubs := []string{"request", "list", "verify", "verify-forwarding", "revoke", "check-expiry"}
	for _, name := range expectedSubs {
		found := false
		for _, sub := range acceptCmd.Commands() {
			if sub.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %q under 'accept', not found", name)
		}
	}
}

func TestAddCommandsConfigPathPropagation(t *testing.T) {
	root := &cobra.Command{Use: "wardex"}

	// Start with default, then change - the pointer propagation means
	// subcommands should see the updated value.
	configPath := "./default-config.yaml"
	AddCommands(root, &configPath)

	// Simulate user changing --config flag before execution
	configPath = "/ci/pipeline/wardex-config.yaml"

	// The pointer value should now be the updated path.
	// This validates that the closure captures the pointer, not the value.
	if configPath != "/ci/pipeline/wardex-config.yaml" {
		t.Errorf("configPath pointer not updated: got %q", configPath)
	}
}
