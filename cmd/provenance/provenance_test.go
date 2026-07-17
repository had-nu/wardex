package provenance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/provenance"
)

// testAnchorer implements provenance.Anchorer for testing.
type testAnchorer struct{}

func (t *testAnchorer) Submit(ctx context.Context, hash []byte, label string) (*provenance.AnchorResult, error) {
	return &provenance.AnchorResult{Found: true, Label: label, BlockIndex: 1}, nil
}

func (t *testAnchorer) SubmitAttested(ctx context.Context, hash []byte, label string, reference []byte) (*provenance.AnchorResult, error) {
	return &provenance.AnchorResult{Found: true, Label: label, BlockIndex: 2}, nil
}

func (t *testAnchorer) Verify(ctx context.Context, hash []byte) (*provenance.AnchorResult, error) {
	return &provenance.AnchorResult{Found: true, Label: "verified", BlockIndex: 1, BlockTime: 1000}, nil
}

func (t *testAnchorer) WaitForAnchor(ctx context.Context, hash []byte) (*provenance.AnchorResult, error) {
	return &provenance.AnchorResult{Found: true, Label: "wait", BlockIndex: 3}, nil
}

func (t *testAnchorer) Status(ctx context.Context) (*provenance.Health, error) {
	return &provenance.Health{BlockHeight: 42, Pending: 0, ActivePeers: 3}, nil
}

func (t *testAnchorer) Close() error { return nil }

func setupTest(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	getAnchorerFn = func() (provenance.Anchorer, error) { return &testAnchorer{}, nil }
	t.Cleanup(func() { getAnchorerFn = getAnchorerDefault })
	return &bytes.Buffer{}, &bytes.Buffer{}
}

func TestSubmitCmd(t *testing.T) {
	out, _ := setupTest(t)
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetArgs([]string{
		"submit",
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"--label", "test",
	})
	if err := ProvenanceCmd.Execute(); err != nil {
		t.Fatalf("submit command failed: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("submitted")) {
		t.Errorf("expected 'submitted' message, got: %s", out.String())
	}
}

func TestVerifyCmd(t *testing.T) {
	out, _ := setupTest(t)
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetArgs([]string{
		"verify",
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	})
	if err := ProvenanceCmd.Execute(); err != nil {
		t.Fatalf("verify command failed: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("FOUND")) {
		t.Errorf("expected 'FOUND' message, got: %s", out.String())
	}
}

func TestStatusCmd(t *testing.T) {
	out, _ := setupTest(t)
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetArgs([]string{"status"})
	if err := ProvenanceCmd.Execute(); err != nil {
		t.Fatalf("status command failed: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("42")) {
		t.Errorf("expected block height 42, got: %s", out.String())
	}
}

func TestAttestCmd(t *testing.T) {
	dir := filepath.Join(os.Getenv("PWD"), ".testdata", t.Name())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	inputFile := filepath.Join(dir, "input.txt")
	keyFile := filepath.Join(dir, "key.wex")
	attestFile := filepath.Join(dir, "attest.cbor")

	if err := os.WriteFile(inputFile, []byte("test data"), 0644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyEncoded := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(keyFile, []byte(keyEncoded), 0400); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// --input bypasses SafePath so we can use tmp dirs
	out, _ := setupTest(t)

	attFlags = attestFlags{} // reset flags between tests
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetArgs([]string{
		"attest", inputFile,
		"--sign-key", keyFile,
		"--tool", "wardex-test",
		"--version", "1.0",
		"--output", attestFile,
	})
	if err := ProvenanceCmd.Execute(); err != nil {
		t.Fatalf("attest command failed: %v", err)
	}

	if _, err := os.Stat(attestFile); os.IsNotExist(err) {
		t.Fatalf("attestation file not created at %s", attestFile)
	}
	data, err := os.ReadFile(attestFile)
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty attestation file")
	}
}

func TestAttestCmdWithSubmit(t *testing.T) {
	dir := filepath.Join(os.Getenv("PWD"), ".testdata", t.Name())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	inputFile := filepath.Join(dir, "input.txt")
	keyFile := filepath.Join(dir, "key.wex")

	if err := os.WriteFile(inputFile, []byte("test data for submit"), 0644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyEncoded := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(keyFile, []byte(keyEncoded), 0400); err != nil {
		t.Fatalf("write key: %v", err)
	}

	out, _ := setupTest(t)

	attFlags = attestFlags{}
	attestFile := filepath.Join(dir, "attest.cbor")
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetArgs([]string{
		"attest", inputFile,
		"--sign-key", keyFile,
		"--tool", "wardex-test",
		"--version", "1.0",
		"--output", attestFile,
		"--submit",
	})
	if err := ProvenanceCmd.Execute(); err != nil {
		t.Fatalf("attest with submit failed: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("Anchored")) {
		t.Errorf("expected 'Anchored' message, got: %s", out.String())
	}
}

func TestAttestCmdMissingKey(t *testing.T) {
	out, errOut := setupTest(t)
	attFlags = attestFlags{}
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetErr(errOut)
	ProvenanceCmd.SetArgs([]string{
		"attest", "input.txt",
		"--sign-key", "/nonexistent/key.wex",
		"--tool", "test",
	})
	err := ProvenanceCmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestSubmitCmdInvalidHex(t *testing.T) {
	out, errOut := setupTest(t)
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetErr(errOut)
	ProvenanceCmd.SetArgs([]string{"submit", "not-a-hex-string", "--label", "test"})
	err := ProvenanceCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestVerifyCmdInvalidHex(t *testing.T) {
	out, errOut := setupTest(t)
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetErr(errOut)
	ProvenanceCmd.SetArgs([]string{"verify", "not-a-hex-string"})
	err := ProvenanceCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestStatusCmdNoAnchorer(t *testing.T) {
	getAnchorerFn = func() (provenance.Anchorer, error) {
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() { getAnchorerFn = getAnchorerDefault })

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetErr(errOut)
	ProvenanceCmd.SetArgs([]string{"status"})
	err := ProvenanceCmd.Execute()
	if err == nil {
		t.Fatal("expected error when anchorer unavailable")
	}
}

func TestAttestCmdInputHash(t *testing.T) {
	dir := filepath.Join(os.Getenv("PWD"), ".testdata", t.Name())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	inputFile := filepath.Join(dir, "test.bin")
	keyFile := filepath.Join(dir, "key.wex")

	content := []byte("deterministic content for hash verification")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyEncoded := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(keyFile, []byte(keyEncoded), 0400); err != nil {
		t.Fatalf("write key: %v", err)
	}

	out, _ := setupTest(t)

	attFlags = attestFlags{}
	attestFile := filepath.Join(dir, "attest.cbor")
	ProvenanceCmd.SetOut(out)
	ProvenanceCmd.SetArgs([]string{
		"attest", inputFile,
		"--sign-key", keyFile,
		"--tool", "hash-test",
		"--version", "1.0",
		"--output", attestFile,
	})
	if err := ProvenanceCmd.Execute(); err != nil {
		t.Fatalf("attest command failed: %v", err)
	}

	expectedHash := sha256.Sum256(content)
	if !bytes.Contains(out.Bytes(), []byte(hex.EncodeToString(expectedHash[:])[:8])) {
		t.Errorf("output should contain input hash prefix, got: %s", out.String())
	}
}
