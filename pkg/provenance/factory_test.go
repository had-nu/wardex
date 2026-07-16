package provenance

import (
	"context"
	"testing"

	"github.com/had-nu/wardex/v2/config"
)

func TestNewNoop(t *testing.T) {
	cfg := config.ProvenanceConfig{Enabled: "noop"}
	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(noop) failed: %v", err)
	}
	if a == nil {
		t.Fatal("New(noop) returned nil anchorer")
	}

	result, err := a.Submit(context.Background(), []byte("test"), "label")
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	if result.Found {
		t.Error("expected Found=false for noop")
	}

	result, err = a.Verify(context.Background(), []byte("test"))
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if result.Found {
		t.Error("expected Found=false for noop")
	}

	result, err = a.WaitForAnchor(context.Background(), []byte("test"))
	if err != nil {
		t.Fatalf("WaitForAnchor failed: %v", err)
	}
	if result.Found {
		t.Error("expected Found=false for noop")
	}

	health, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if health == nil {
		t.Fatal("Status returned nil")
	}

	if err := a.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestNewEmptyEnabled(t *testing.T) {
	cfg := config.ProvenanceConfig{Enabled: ""}
	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(empty) failed: %v", err)
	}
	if a == nil {
		t.Fatal("New(empty) returned nil anchorer")
	}
	_ = a.Close()
}

func TestNewGRPCStub(t *testing.T) {
	cfg := config.ProvenanceConfig{Enabled: "grpc", Address: "localhost:50051"}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for grpc stub, got nil")
	}
}

func TestNewUnknown(t *testing.T) {
	cfg := config.ProvenanceConfig{Enabled: "unknown"}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unknown driver, got nil")
	}
}

func TestAnchorResult(t *testing.T) {
	r := &AnchorResult{
		Found:      true,
		BlockIndex: 42,
		BlockTime:  1000,
		StateRoot:  []byte("root"),
		Proof:      []byte("proof"),
		Label:      "v1.0",
	}
	if !r.Found {
		t.Error("expected Found=true")
	}
	if r.BlockIndex != 42 {
		t.Errorf("expected BlockIndex=42, got %d", r.BlockIndex)
	}
	if r.Label != "v1.0" {
		t.Errorf("expected Label=v1.0, got %s", r.Label)
	}
}

func TestHealth(t *testing.T) {
	h := &Health{
		BlockHeight: 100,
		Pending:     5,
		ActivePeers: 3,
	}
	if h.BlockHeight != 100 {
		t.Errorf("expected BlockHeight=100, got %d", h.BlockHeight)
	}
	if h.Pending != 5 {
		t.Errorf("expected Pending=5, got %d", h.Pending)
	}
}
