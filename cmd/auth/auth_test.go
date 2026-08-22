package auth_test

import (
	"testing"

	"github.com/had-nu/wardex/v2/cmd/auth"
)

func TestAuthCmdHasSubcommands(t *testing.T) {
	cmd := auth.AuthCmd

	// Verify subcommands exist
	found := map[string]bool{"status": false, "verify": false}
	for _, child := range cmd.Commands() {
		// Use field may contain flags like "verify --actor <email>"
		for key := range found {
			if len(child.Use) >= len(key) && child.Use[:len(key)] == key {
				found[key] = true
			}
		}
	}

	for name, exists := range found {
		if !exists {
			t.Errorf("expected subcommand %q to exist", name)
		}
	}
}

func TestAuthCmdUse(t *testing.T) {
	cmd := auth.AuthCmd
	if cmd.Use != "auth" {
		t.Errorf("expected Use to be 'auth', got %q", cmd.Use)
	}
}

func TestStatusCmdHasFlags(t *testing.T) {
	// The --trust flag is a persistent flag on the parent AuthCmd
	cmd := auth.AuthCmd
	if cmd.PersistentFlags().Lookup("trust") == nil {
		t.Error("expected --trust flag to exist on parent command")
	}
}

