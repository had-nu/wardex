package ots_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/immutable-provenance/ots"
)

func TestVerifyMagicHeader(t *testing.T) {
	dir, err := os.MkdirTemp("", "ots-test-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	manifestPath := filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte("version: 1.0\n"), 0644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}

	// 1. Create a simulated invalid OTS file
	badOtsPath := filepath.Join(dir, "bad.ots")
	if err := os.WriteFile(badOtsPath, []byte("bad header content"), 0644); err != nil {
		t.Fatalf("writing bad.ots: %v", err)
	}

	_, err = ots.Verify(manifestPath, badOtsPath)
	if err == nil {
		t.Error("expected verification to fail for bad OTS header, but it succeeded")
	}

	// 2. Create a simulated valid OTS file with correct header
	goodOtsPath := filepath.Join(dir, "good.ots")
	header := []byte{0x00}
	header = append(header, []byte("OpenTimestamps")...)
	header = append(header, 0x00)
	header = append(header, []byte("Proof")...)
	header = append(header, []byte("rest of content")...)

	if err := os.WriteFile(goodOtsPath, header, 0644); err != nil {
		t.Fatalf("writing good.ots: %v", err)
	}

	// This should pass the header check (it might fail checkHashStatus but we handle/mock or it defaults)
	// We can run verification. Since checkHashStatus queries a public URL, it might return false or error.
	// But it shouldn't panic.
	_, _ = ots.Verify(manifestPath, goodOtsPath)
}
