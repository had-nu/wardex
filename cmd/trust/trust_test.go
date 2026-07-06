package trustcmd_test

import (
	"strings"
	"testing"

	trustcmd "github.com/had-nu/wardex/v2/cmd/trust"
)

func TestTrustCmdHasSubcommands(t *testing.T) {
	cmd := trustcmd.TrustCmd

	// Verify subcommands exist (Use fields may include args like "show <key-id>")
	found := map[string]bool{"init": false, "add": false, "revoke": false, "list": false, "show": false, "verify": false}
	for _, child := range cmd.Commands() {
		for key := range found {
			if strings.HasPrefix(child.Use, key) {
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

func TestTrustCmdUse(t *testing.T) {
	cmd := trustcmd.TrustCmd
	if cmd.Use != "trust" {
		t.Errorf("expected Use to be 'trust', got %q", cmd.Use)
	}
}
