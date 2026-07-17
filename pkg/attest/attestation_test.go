package attest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/attest"
)

func TestNewAttestation(t *testing.T) {
	a := attest.New("wardex-convert/grype", "1.0.0")
	if a.Tool != "wardex-convert/grype" {
		t.Errorf("tool = %q, want %q", a.Tool, "wardex-convert/grype")
	}
	if a.Timestamp == "" {
		t.Error("timestamp should not be empty")
	}
}

func TestSetMethods(t *testing.T) {
	a := attest.New("test-tool", "0.1.0").
		SetInputHash([]byte("input-hash")).
		SetOutputHash([]byte("output-hash")).
		SetConfigHash("sha256:abc123").
		SetConvertedBy("test-converter")

	if string(a.InputHash) != "input-hash" {
		t.Errorf("input hash mismatch")
	}
	if a.ConfigHash != "sha256:abc123" {
		t.Errorf("config hash mismatch")
	}
	if a.ConvertedBy != "test-converter" {
		t.Errorf("converted_by mismatch")
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	a := attest.New("test-tool", "1.0.0").
		SetInputHash([]byte("in")).
		SetOutputHash([]byte("out"))

	signed, err := a.Sign(
		func(msg []byte) ([]byte, error) {
			return ed25519.Sign(priv, msg), nil
		},
		"ed25519:test-key",
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if len(signed.Signatures) == 0 {
		t.Fatal("no signatures")
	}

	err = signed.Attestation.Verify(
		signed.Signatures,
		func(sig, msg []byte) error {
			if !ed25519.Verify(pub, msg, sig) {
				return fmt.Errorf("ed25519: signature verification failed")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignTampered(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	differentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate different key: %v", err)
	}

	a := attest.New("test-tool", "1.0.0").
		SetOutputHash([]byte("original"))

	signed, err := a.Sign(
		func(msg []byte) ([]byte, error) {
			return ed25519.Sign(priv, msg), nil
		},
		"ed25519:test-key",
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	signed.Attestation.OutputHash = []byte("tampered")

	err = signed.Attestation.Verify(
		signed.Signatures,
		func(sig, msg []byte) error {
			if !ed25519.Verify(differentPub, msg, sig) {
				return fmt.Errorf("ed25519: signature verification failed")
			}
			return nil
		},
	)
	if err == nil {
		t.Error("expected verification to fail for tampered attestation")
	}
}

func TestMarshalCanonicalDeterminism(t *testing.T) {
	a1 := attest.New("tool", "1.0").
		SetInputHash([]byte("hash")).
		SetConfigHash("sha256:abc")

	a2 := attest.New("tool", "1.0").
		SetInputHash([]byte("hash")).
		SetConfigHash("sha256:abc")

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
