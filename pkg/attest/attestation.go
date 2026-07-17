// Package attest implements 3CP (Cryptographic Chain of Custody Protocol)
// tool provenance attestation. It defines the signed envelope that a tool
// produces to attest to its identity and the cryptographic hashes of its
// inputs and outputs.
//
// Reference: spec/cddl/tool-attestation.cddl
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// FileHash computes the SHA-256 hash of a file.
func FileHash(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// SignWithEd25519 signs a message using an Ed25519 private key loaded from disk.
// Returns the raw signature bytes and the hex-encoded public key ID ("ed25519:<hex>").
func SignWithEd25519(keyPath string, msg []byte) (sig []byte, keyID string, err error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("read key: %w", err)
	}

	decoded, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, "", fmt.Errorf("decode key: %w", err)
	}

	if len(decoded) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("invalid ed25519 private key size: got %d, want %d", len(decoded), ed25519.PrivateKeySize)
	}

	priv := ed25519.PrivateKey(decoded)
	pub := priv.Public().(ed25519.PublicKey)
	keyID = "ed25519:" + hex.EncodeToString(pub)

	sig = ed25519.Sign(priv, msg)
	return sig, keyID, nil
}

// AttestFile creates a signed tool attestation for a single file.
// Reads the file, computes SHA-256 hash, creates a ToolAttestation, and signs
// it with the given Ed25519 private key.
func AttestFile(tool, version, filePath, keyPath string) (*SignedAttestation, error) {
	hash, err := FileHash(filePath)
	if err != nil {
		return nil, err
	}

	a := New(tool, version).
		SetInputHash(hash).
		SetOutputHash(hash).
		SetTimestamp(time.Now())

	signer := func(msg []byte) ([]byte, error) {
		sig, _, err := SignWithEd25519(keyPath, msg)
		return sig, err
	}

	_, keyID, err := SignWithEd25519(keyPath, []byte("probe"))
	if err != nil {
		return nil, fmt.Errorf("load signer key: %w", err)
	}

	return a.Sign(signer, keyID)
}

var deterministicCBOR cbor.EncMode

func init() {
	opts := cbor.CanonicalEncOptions()
	opts.Time = cbor.TimeRFC3339
	var err error
	deterministicCBOR, err = opts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("attest: failed to initialize CBOR canonical mode: %v", err))
	}
}

type ToolAttestation struct {
	Tool        string `cbor:"0,keyasint"`
	Version     string `cbor:"1,keyasint"`
	InputHash   []byte `cbor:"2,keyasint"`
	OutputHash  []byte `cbor:"3,keyasint"`
	ConfigHash  string `cbor:"4,keyasint"`
	Timestamp   string `cbor:"5,keyasint"`
	ConvertedBy string `cbor:"6,keyasint"`
}

type SignedAttestation struct {
	Attestation ToolAttestation          `cbor:"0,keyasint"`
	Signatures  map[string][]byte        `cbor:"1,keyasint"`
}

func New(tool, version string) *ToolAttestation {
	return &ToolAttestation{
		Tool:      tool,
		Version:   version,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

func (a *ToolAttestation) SetInputHash(hash []byte) *ToolAttestation {
	a.InputHash = hash
	return a
}

func (a *ToolAttestation) SetOutputHash(hash []byte) *ToolAttestation {
	a.OutputHash = hash
	return a
}

func (a *ToolAttestation) SetConfigHash(hash string) *ToolAttestation {
	a.ConfigHash = hash
	return a
}

func (a *ToolAttestation) SetConvertedBy(convertedBy string) *ToolAttestation {
	a.ConvertedBy = convertedBy
	return a
}

func (a *ToolAttestation) SetTimestamp(ts time.Time) *ToolAttestation {
	a.Timestamp = ts.UTC().Format(time.RFC3339)
	return a
}

func (a *ToolAttestation) MarshalCanonical() ([]byte, error) {
	return deterministicCBOR.Marshal(a)
}

func (a *ToolAttestation) Sign(signer func([]byte) ([]byte, error), keyID string) (*SignedAttestation, error) {
	payload, err := a.MarshalCanonical()
	if err != nil {
		return nil, fmt.Errorf("attest: marshal for signing: %w", err)
	}

	sig, err := signer(payload)
	if err != nil {
		return nil, fmt.Errorf("attest: sign: %w", err)
	}

	sigs := map[string][]byte{keyID: sig}
	if a.ConvertedBy != "" {
		sigs["converted_by:"+a.ConvertedBy] = sig
	}

	return &SignedAttestation{
		Attestation: *a,
		Signatures:  sigs,
	}, nil
}

func (a *ToolAttestation) Verify(signatures map[string][]byte, verifier func([]byte, []byte) error) error {
	payload, err := a.MarshalCanonical()
	if err != nil {
		return fmt.Errorf("attest: marshal for verification: %w", err)
	}

	for keyID, sig := range signatures {
		if err := verifier(sig, payload); err != nil {
			return fmt.Errorf("attest: signature %q invalid: %w", keyID, err)
		}
	}
	return nil
}

func (s *SignedAttestation) MarshalAttestationCBOR() ([]byte, error) {
	return deterministicCBOR.Marshal(s)
}
