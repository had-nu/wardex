package ethanchor_test

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/had-nu/immutable-provenance/ethanchor"
)

func TestContractABI(t *testing.T) {
	parsedABI, err := abi.JSON(strings.NewReader(ethanchor.ProvenanceAnchorABI))
	if err != nil {
		t.Fatalf("failed to parse hardcoded ABI JSON: %v", err)
	}

	// Verify methods exist
	if _, ok := parsedABI.Methods["anchor"]; !ok {
		t.Error("expected method 'anchor' to exist in contract ABI")
	}

	if _, ok := parsedABI.Methods["proofs"]; !ok {
		t.Error("expected method 'proofs' to exist in contract ABI")
	}

	// Verify proofs input is bytes32
	proofsMethod := parsedABI.Methods["proofs"]
	if len(proofsMethod.Inputs) != 1 {
		t.Errorf("expected 'proofs' to have 1 input, got %d", len(proofsMethod.Inputs))
	}
}
