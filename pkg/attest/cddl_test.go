package attest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/attest"
)

func cddlFixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "spec", "cddl", "tool-attestation.cddl")
}

func TestCDDLToolAttestationSchemaExists(t *testing.T) {
	data, err := os.ReadFile(cddlFixturePath(t))
	if err != nil {
		t.Fatalf("read CDDL schema: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("tool-attestation.cddl is empty")
	}
}

func TestCDDLToolAttestationDeterministicCBOR(t *testing.T) {
	a1 := attest.New("test-tool", "1.0.0").
		SetInputHash([]byte("input")).
		SetOutputHash([]byte("output")).
		SetConfigHash("sha256:abc123").
		SetConvertedBy("test-converter")

	a2 := attest.New("test-tool", "1.0.0").
		SetInputHash([]byte("input")).
		SetOutputHash([]byte("output")).
		SetConfigHash("sha256:abc123").
		SetConvertedBy("test-converter")

	b1, err := a1.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal a1: %v", err)
	}
	b2, err := a2.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal a2: %v", err)
	}

	if len(b1) != len(b2) {
		t.Errorf("length mismatch: %d vs %d", len(b1), len(b2))
	}
	for i := range b1 {
		if b1[i] != b2[i] {
			t.Errorf("byte %d differs: %02x vs %02x", i, b1[i], b2[i])
			break
		}
	}
}

func TestCDDLToolAttestationRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	a := attest.New("wardex-convert/grype", "2.3.0").
		SetInputHash([]byte{1, 2, 3, 4}).
		SetOutputHash([]byte{5, 6, 7, 8}).
		SetConfigHash("sha256:abc123")

	signer := func(msg []byte) ([]byte, error) {
		return ed25519.Sign(priv, msg), nil
	}

	signed, err := a.Sign(signer, "ed25519:test-key")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sig, ok := signed.Signatures["ed25519:test-key"]
	if !ok {
		t.Fatal("missing expected signature key")
	}

	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	pub := priv.Public().(ed25519.PublicKey)
	err = signed.Attestation.Verify(
		signed.Signatures,
		func(sig, msg []byte) error {
			if !ed25519.Verify(pub, msg, sig) {
				return fmt.Errorf("invalid signature")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	payload, err := signed.Attestation.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal canonical: %v", err)
	}
	_ = payload
}
