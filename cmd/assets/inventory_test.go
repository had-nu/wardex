package assets_test

import (
	"testing"

	"github.com/had-nu/wardex/v2/cmd/assets"
)

func TestInventoryCmdHasFlags(t *testing.T) {
	cmd := assets.InventoryCmd

	// Verify the command has the required flags
	if cmd.Flags().Lookup("assets") == nil {
		t.Error("expected --assets flag to exist")
	}
	if cmd.Flags().Lookup("format") == nil {
		t.Error("expected --format flag to exist")
	}
}

func TestInventoryCmdUse(t *testing.T) {
	cmd := assets.InventoryCmd
	if cmd.Use != "inventory" {
		t.Errorf("expected Use to be 'inventory', got %q", cmd.Use)
	}
}
