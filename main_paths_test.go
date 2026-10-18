package main

import "testing"

// TestMachineCommandPathCoversSubcommands is the regression guard for the
// banner leaking into `wardex completion <shell>`. The classifier matched whole
// command paths exactly, so a path carrying a subcommand ("wardex completion
// bash") fell through to the default case and printed the banner on a
// machine-oriented command.
func TestMachineCommandPathCoversSubcommands(t *testing.T) {
	machine := []string{
		"wardex completion",
		"wardex completion bash",
		"wardex completion zsh",
		"wardex completion fish",
		"wardex completion powershell",
		"wardex help",
		"wardex help evaluate",
		"wardex audit export",
		"wardex audit verify-link",
		"wardex config hash",
		"wardex provenance attest",
	}
	for _, path := range machine {
		if !machineCommandPath(path) {
			t.Errorf("machineCommandPath(%q) = false, want true", path)
		}
	}

	human := []string{
		"",
		"wardex",
		"wardex evaluate",
		"wardex assess",
		"wardex art14",
		"wardex audit verify-chain",
		"wardex config seal",
		"wardex provenance seal",
		// Near misses must not match a machine path by prefix.
		"wardex completions",
		"wardex helper",
		"wardex audits",
		"wardex configuration",
	}
	for _, path := range human {
		if machineCommandPath(path) {
			t.Errorf("machineCommandPath(%q) = true, want false", path)
		}
	}
}
