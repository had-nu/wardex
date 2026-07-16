package provenance

import (
	"context"
	"testing"
	"time"
)

func TestNewEmbeddedGleipnir(t *testing.T) {
	opts := map[string]string{
		"cycle_interval": "100ms",
		"node_id":        "test-embedded",
		"simulated":      "true",
	}
	g, err := newEmbeddedGleipnir(opts)
	if err != nil {
		t.Fatalf("newEmbeddedGleipnir failed: %v", err)
	}
	defer func() {
		if err := g.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	health, err := g.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if health == nil {
		t.Fatal("Status returned nil")
	}
}

func TestEmbeddedGleipnirSubmitVerify(t *testing.T) {
	opts := map[string]string{
		"cycle_interval": "100ms",
		"node_id":        "test-submit-verify",
		"simulated":      "true",
	}
	g, err := newEmbeddedGleipnir(opts)
	if err != nil {
		t.Fatalf("newEmbeddedGleipnir failed: %v", err)
	}
	defer func() {
		if err := g.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := []byte("test-hash-content")

	result, err := g.Submit(ctx, hash, "test-label")
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	if result == nil {
		t.Fatal("Submit returned nil")
		return
	}

	result, err = g.WaitForAnchor(ctx, hash)
	if err != nil {
		t.Fatalf("WaitForAnchor failed: %v", err)
	}
	if result == nil || !result.Found {
		t.Fatal("expected hash to be found after wait")
	}

	result, err = g.Verify(ctx, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if result == nil || !result.Found {
		t.Fatal("expected hash to be found on verify")
	}
	if result.Label != "test-label" {
		t.Errorf("expected Label=test-label, got %s", result.Label)
	}
}
