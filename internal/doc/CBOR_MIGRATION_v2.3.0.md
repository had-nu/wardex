# CBOR Deterministic Encoding Migration — v2.3.0

## Summary

This release replaces ad-hoc canonicalization strategies with **CBOR Core
Deterministic Encoding** (RFC 8949 §4.2.3) across three subsystems:

| Subsystem | Before | After |
|---|---|---|
| CPL config hashing | YAML → `any` → `json.Marshal` | YAML → `any` → CBOR deterministic |
| WexState signing | `\n`-separated field concatenation | CBOR deterministic struct |
| Tool provenance | `converted_by` string (unsigned) | Signed CBOR attestation envelope |

## What Changed

### 1. CPL `canonicalConfig()` — `internal/cpl/hash.go`

**Before:** `yaml.Unmarshal(raw)` → `json.Marshal(data)`

**After:** `yaml.Unmarshal(raw)` → CBOR deterministic marshal

The input (YAML config bytes) and output (`"sha256:<hex>"` hash) types are
identical. Only the intermediate canonical bytes changed.

**Impact:** All config hash values are new. Existing CPL audit logs that record
`config_hash` values computed with the old canonicalizer will not match if
re-hashed. To migrate:

1. Re-compute config hashes for all archived configs:
   ```bash
   wardex config hash --algorithm sha256 --input wardex-config.yaml
   ```
2. Update CPL audit log entries to use the new hashes.
3. Run `wardex audit verify-link` to confirm consistency.

**Test vectors updated:**
- `internal/cpl/hash_test.go:TestCanonicalConfigKnownVector`
  - Old: `sha256:9fb10556b293b483c9ad27d8e6f2b3f1168368169ebdea3502006de93b5820ea`
  - New: `sha256:64110201d1499240e24d9aaf01b301267342cf74f230e8cc78b1aa3885480c34`

### 2. WexState Signing — `pkg/trust/wexstate.go`, `pkg/trust/wexstate_cbor.go`

**Before:** `SealMessage()` returned `[]byte` concatenated with `\n`:
```
version\npayload\nsealed_at\nsealed_by\ntrust_store_ref\ntrust_store_sig
```

**After:** `SealMessage()` returns `([]byte, error)`. Version `"2"` uses CBOR:
```cbordiag
{
  0: "2",                    ; version
  1: h'...',                 ; payload (canonical CBOR of config)
  2: "2026-07-17T10:00:00Z", ; sealed_at (RFC3339)
  3: "admin@org",             ; sealed_by
  4: "./wardex-trust.yaml",  ; trust_store_ref
  5: "sha256:abc123",        ; trust_store_sig
}
```

**Backward compatibility:** `VerifySeal()` tries CBOR first; if that fails and
the state version is `"2"`, it falls back to the legacy `\n` format. This means
v2 signatures created during the migration window can still be verified.

**New `WexState.Version` semantics:**
- `"1"` — legacy `\n`-separated signing (unchanged)
- `"2"` — CBOR deterministic signing (new default)
- Any other value — treated as CBOR (future-proof)

### 3. Tool Attestation — `pkg/attest/` (new)

New package for 3CP (Cryptographic Chain of Custody Protocol) provenance.
The `ToolAttestation` struct uses CBOR deterministic encoding for signing.
This is a protocol-agnostic package — it defines the 3CP attestation format
without depending on any specific backend (Gleipnir, Carcosa, etc.).

```go
type ToolAttestation struct {
    Tool        string `cbor:"0,keyasint"`
    Version     string `cbor:"1,keyasint"`
    InputHash   []byte `cbor:"2,keyasint"`
    OutputHash  []byte `cbor:"3,keyasint"`
    ConfigHash  string `cbor:"4,keyasint"`
    Timestamp   string `cbor:"5,keyasint"`
    ConvertedBy string `cbor:"6,keyasint"`
}
```

See `spec/cddl/tool-attestation.cddl` for the formal CDDL schema.

### 4. Dependencies

`github.com/fxamacker/cbor/v2 v2.9.0` promoted from indirect to direct.

No new external dependencies. The library was already in `go.sum` (indirect via
`github.com/had-nu/gleipnir`).

## CBOR Encoding Details

All CBOR encoding uses `cbor.CanonicalEncOptions()` with RFC3339 timestamps:

```go
opts := cbor.CanonicalEncOptions()
opts.Time = cbor.TimeRFC3339
mode, _ := opts.EncMode()
```

This guarantees:
- Map keys sorted by CBOR byte representation
- Integers encoded in the shortest form
- Floats use IEEE 754 binary64 (no mixed precision)
- Strings as UTF-8 text strings (major type 3)
- Byte strings as major type 2
- Timestamps as RFC3339 text strings

## CDDL Schemas

Located in `spec/cddl/`:

| File | Schema | Used by |
|---|---|---|
| `cpl-entry.cddl` | CPL audit log entry | `internal/cpl/` |
| `wexstate.cddl` | WexState + SealMessage | `pkg/trust/` |
| `tool-attestation.cddl` | 3CP provenance | `pkg/attest/`, Gleipnir |

These are design artifacts and conformance test fixtures. Runtime validation
will be added in a follow-up release via `cbor.ValidCDDL()`.

## Rollback

To revert to pre-v2.3.0 behavior:

1. **CPL hashing:** Restore `canonicalConfig()` in `internal/cpl/hash.go` to
   `json.Marshal(data)`.
2. **WexState:** Set `state.Version = "1"` in `SealConfig()` and revert
   `SealMessage()` to return `[]byte` with `\n` concatenation.
3. **go.mod:** Demote `github.com/fxamacker/cbor/v2` back to indirect (or remove).
4. **Test vectors:** Restore old known hash in `hash_test.go`.

## Testing

```bash
# Run all CPL tests (hash determinism, known vector, chain verify)
go test ./internal/cpl/ -v

# Run trust tests (seal, verify, fallback)
go test ./pkg/trust/ -v

# Run attestation tests (sign, verify, tamper detection)
go test ./pkg/attest/ -v

# Full suite
go test ./... -count=1
```

## Architecture: 3CP Abstraction

The `Anchorer` interface (`pkg/provenance/anchorer.go`) is the 3CP protocol
abstraction. Wardex only depends on this interface, never directly on any
provenance backend (Gleipnir, Carcosa, etc.).

Backends:
- **gleipnir-embedded**: Embedded Gleipnir consensus engine (reference 3CP impl)
- **grpc**: Remote 3CP-compatible gRPC service — currently uses Gleipnir's
  protobuf definitions as the wire format, replaceable with any 3CP-compliant
  service

The attestation format (`spec/cddl/tool-attestation.cddl`) is the canonical
3CP provenance envelope. Backends map between 3CP types and their native
protocols. See `pkg/provenance/factory.go` for backend registration.

## Future Work

- [ ] Runtime CDDL validation at ingestion boundaries
- [ ] `wardex prove attest --submit` submits attestation hash + CBOR reference
- [ ] Shared 3CP CDDL definitions across all protocol implementations
- [ ] WexState v1 support removal (planned for v2.4.0, once migration complete)
- [ ] Independent 3CP protobuf definitions (decouple from Gleipnir proto)
