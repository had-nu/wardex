// Package provenance implements the 3CP (Cryptographic Chain of Custody
// Protocol) client abstraction. It defines the Anchorer interface that
// Wardex uses to submit and verify provenance anchors.
//
// Backends:
//   - gleipnir-embedded: reference 3CP implementation (local consensus)
//   - grpc: remote 3CP-compatible anchor service (e.g. Gleipnir, Carcosa)
//   - noop: dry-run mode with no persistence
//
// The 3CP protocol format is defined in spec/cddl/tool-attestation.cddl.
// All attestation payloads use CBOR deterministic encoding (RFC 8949 §4.2.3).
package provenance

import "context"

// Anchorer is the 3CP client interface. Implementations translate between
// 3CP semantics and their backend protocol (Gleipnir gRPC, embedded consensus,
// Carcosa ZKP, etc.).
type Anchorer interface {
	// Submit anchors a hash with a human-readable label.
	Submit(ctx context.Context, hash []byte, label string) (*AnchorResult, error)

	// SubmitAttested anchors a hash with a 3CP tool attestation as reference.
	// The reference bytes should be a CBOR-serialized SignedAttestation
	// conforming to spec/cddl/tool-attestation.cddl.
	SubmitAttested(ctx context.Context, hash []byte, label string, reference []byte) (*AnchorResult, error)

	// Verify checks whether a hash exists in the provenance chain.
	Verify(ctx context.Context, hash []byte) (*AnchorResult, error)

	// WaitForAnchor blocks until a hash is anchored.
	WaitForAnchor(ctx context.Context, hash []byte) (*AnchorResult, error)

	// Status returns the health of the provenance network.
	Status(ctx context.Context) (*Health, error)

	// Close shuts down the anchorer and releases resources.
	Close() error
}

// AnchorResult is the 3CP generic anchor result. Fields are populated
// according to backend capability.
type AnchorResult struct {
	Found      bool
	BlockIndex uint64
	BlockTime  int64
	StateRoot  []byte
	Proof      []byte
	Label      string
}

// Health represents the health of the 3CP provenance network.
type Health struct {
	BlockHeight  uint64
	Pending      int
	ActivePeers  int
}

// SubmitEnvelope is the 3CP canonical submission format used by
// SubmitAttested. Backends map this to their native protocol types.
type SubmitEnvelope struct {
	Hash      []byte
	Submitter []byte
	Label     string
	Reference []byte
	Timestamp int64
}
