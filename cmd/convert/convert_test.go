package convert_test

import (
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/cmd/convert"
	"github.com/spf13/cobra"
)

func TestConvertCommandsExist(t *testing.T) {
	// Verify all convert subcommands exist
	commands := map[string]bool{
		"grype": false,
		"sbom":  false,
		"kev":   false,
	}

	allCmds := []*cobra.Command{convert.GrypeCmd, convert.SbomCmd, convert.KevCmd}
	for _, cmd := range allCmds {
		for key := range commands {
			if strings.HasPrefix(cmd.Use, key) {
				commands[key] = true
			}
		}
	}

	for name, exists := range commands {
		if !exists {
			t.Errorf("expected command %q to exist", name)
		}
	}
}

func TestKevCmdHasFlags(t *testing.T) {
	cmd := convert.KevCmd

	// Verify the command has the required flags
	if cmd.Flags().Lookup("output") == nil && cmd.Flags().Lookup("o") == nil {
		t.Error("expected --output flag to exist")
	}
}
