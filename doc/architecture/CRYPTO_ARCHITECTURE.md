# Wardex Cryptographic Architecture 2026
**Version**: 2.0 (July 2026)
**Scope**: Risk Acceptance Integrity Module (`pkg/accept/signer`), CPL canonicalization (`internal/cpl/`), WexState sealing (`pkg/trust/`), 3CP Tool Attestation (`pkg/attest/`)

## 1. Objective and Threat Model
The Wardex Release Gate natively blocks builds that violate enterprise risk appetite thresholds. To gracefully manage exceptions, developers can request Risk Acceptances. Because these acceptances bypass security controls and permit known vulnerabilities to ship to production, their integrity is the most critical security boundary in the Wardex ecosystem.

### Threat Model
The architecture is designed to defend against the following threats:
1.  **Tampering (The Inside Job)**: A malicious insider modifies `wardex-acceptances.yaml` manually to inject an unapproved CVE exception or alter an expiration date.
2.  **Repudiation**: A developer claims they did not accept a specific risk.
3.  **Cross-Context Replay**: A risk acceptance signed in a "dev" repository context is illicitly copied to bypass the gate in a "prod" repository.

## 2. Signature Specification (HMAC-SHA256)
All Risk Acceptances are cryptographically bound using Hash-based Message Authentication Codes (HMAC) utilizing the `SHA-256` hashing algorithm.

### 2.1 The Secret Key (`WARDEX_ACCEPT_SECRET`)
The secret key must be exactly 32 bytes (256 bits) of high-entropy data. 
It is injected into the CI/CD environment runtime exclusively as an environment variable and is **never** written to disk during gate evaluation.
*   **Derivation**: N/A (Symmetric Key)
*   **Rotation**: Supported manually holding older keys in an array (pending automated JWK rotation).

### 2.2 The Canonical Payload
To prevent tampering, the payload hashed by the HMAC must represent the exact semantic state of the acceptance. Wardex extracts the following fields, in strict order, formatted precisely as a delimiter-separated string:
`"{ID}|{CVE}|{AcceptedBy}|{Justification}|{ExpiresAt_UnixNano}|{Ticket}|{ReportHash}"`

*Rationale for fields:*
*   **ID**: Prevents duplication.
*   **CVE**: The core subject of the exception.
*   **AcceptedBy**: Non-repudiation tracker.
*   **Justification & Ticket**: Binds the business context to the signature.
*   **ExpiresAt**: Prevents indefinite exploitation of the exception.
*   **ReportHash**: Cross-Context Replay protection. Binds the signature to a specific point-in-time compliance report.

### 2.3 Verification Flow
When `wardex` evaluates `wardex-acceptances.yaml`:
1.  It loads the 256-bit symmetric key from the environment.
2.  It reads the YAML payload, stripping the stored `Signature` field.
3.  It reconstructs the Canonical Payload string.
4.  It generates a localized HMAC-SHA256 hash.
5.  It performs a **Constant-Time Comparison** (`subtle.ConstantTimeCompare`) against the stored signature to prevent timing-based side-channel attacks.

## 3. Storage and Immutability
Risk Acceptances are stored in plaintext YAML (`wardex-acceptances.yaml`) to ensure they remain human-readable and git-compatible for code reviews. Their security is guaranteed by the mathematically irreversible HMAC process, not by encryption. 

### Write-Once / Append-Only 
The application logically prevents the internal modification of an acceptance once signed. If an acceptance must be invalidated before its expiration date, it must be explicitly **Revoked**, which issues a new cryptographically verifiable revocation entry in the `wardex-accept-audit.log`.

---

## 4. BLAKE3 Support (v2.2.0 — CPL)

A partir da v2.2.0, o Wardex suporta BLAKE3 como alternativa ao SHA-256 para hashing
de configurações (Configuration Provenance Link). BLAKE3 oferece:

- **Performance superior**: 10-15× mais rápido que SHA-256 em software
- **Segurança equivalente**: 256 bits de segurança, mesma margem que SHA-256
- **Determinismo**: Output consistente entre plataformas

O algoritmo é seleccionado pela flag `--algorithm sha256|blake3` no comando
`wardex config hash`. Hashes produzem sempre um prefixo identificador (`sha256:` ou
`blake3:`) que impede comparação silenciosa entre algoritmos diferentes.

A canonicalização YAML (chaves ordenadas, comentários removidos, whitespace normalizado)
é aplicada antes do hash independentemente do algoritmo escolhido, garantindo
reprodutibilidade entre ambientes.

---

## 5. CBOR Deterministic Encoding (v2.3.0 — CPL & WexState)

A partir da v2.3.0, toda a canonicalização para efeitos de assinatura criptográfica
migrou de formatos ad-hoc (`json.Marshal`, `\n`-separado) para **CBOR Core Deterministic
Encoding** conforme RFC 8949 §4.2.3, via `github.com/fxamacker/cbor/v2`.

### 5.1 Onde se aplica

| Componente | Antes | Agora |
|------------|-------|-------|
| `internal/cpl/hash.go` | `json.Marshal(map[string]any)` | `cbor.Marshal(canonicalConfig)` com `CanonicalEncOptions()` |
| `pkg/trust/wexstate.go` | `fmt.Sprintf("%s\n%s\n%d\n%s", ...)` | `sealMessageCBOR()` com CBOR determinístico + `cbor.TimeRFC3339` |

### 5.2 Propriedades

- **Byte-idêntico**: A mesma estrutura de dados produz sempre os mesmos bytes
  em qualquer linguagem/plataforma.
- **Sem ambiguidade de tipos**: CBOR distingue `0` de `0.0`, string de número,
  mapa de array — ao contrário de JSON.
- **Timestamps RFC3339**: Codificados como text string RFC 3339 (`cbor.TimeRFC3339`)
  em vez de números Unix, para legibilidade e consistência entre assinaturas.

### 5.3 WexState v1→v2

- WexState `version: "1"` usava `\n`-separado (legado)
- WexState `version: "2"` usa CBOR determinístico
- `VerifySeal()` tenta v2 primeiro; se falhar, faz fallback para v1
- `.wexstate` continua YAML (humano legível); só o campo `seal_message` muda

## 6. CDDL Schemas (v2.3.0)

`spec/cddl/` contém esquemas formais CDDL (RFC 8610) para os três tipos de
dados que cruzam a fronteira de confiança:

| Schema | Domínio |
|--------|---------|
| `cpl-entry.cddl` | CPL audit entry — `config_hash`, `prev_hash`, timestamps |
| `wexstate.cddl` | WexState seal envelope — `version`, `seal_message`, `seal_sig` |
| `tool-attestation.cddl` | 3CP tool provenance — `tool_id`, `input_hash`, `output_hash`, `config_hash`, `timestamp` |

Os schemas são a fonte da verdade para serialização. Testes de confluência
verificam que os marshalers Go produzem CBOR coerente com as definições CDDL.

## 7. 3CP Tool Provenance Attestation (v2.3.0)

`pkg/attest/` implementa o encerramento de provenance (3CP — Cryptographic Chain
of Custody Protocol) para ferramentas de conversão e análise.

### 7.1 Estruturas

```
ToolAttestation          — metadados da execução da ferramenta
  ├── tool_id
  ├── tool_version
  ├── input_hash (SHA-256 do input)
  ├── output_hash (SHA-256 do output)
  ├── config_hash (SHA-256 da config em vigor)
  └── timestamp (RFC 3339)

SignedAttestation        — envelope assinado
  ├── data (CBOR do ToolAttestation)
  ├── signature (Ed25519)
  └── pubkey
```

### 7.2 Fluxo

1. Ferramenta executa conversão (ex: `grype → wardex-vulns.yaml`)
2. `pkg/attest.AttestFile()` calcula SHA-256 do input e output
3. Cria `ToolAttestation` com os hashes + identidade + timestamp
4. Serializa CBOR deterministicamente
5. `SignWithEd25519()` produz `SignedAttestation`
6. Ficheiro `.attest` escrito ao lado do output

### 7.3 CLI

```bash
# Converter e atestar
wardex convert grype grype-output.json --attest signing-key.wex

# Atestar standalone
wardex provenance attest input.txt --tool my-scanner --version 1.0 --sign-key signing-key.wex
```

### 7.4 3CP Abstraction

Wardex não depende de nenhuma implementação específica de 3CP. A interface
`Anchorer` em `pkg/provenance/` define o contrato:

```go
type Anchorer interface {
    Seal(seal *SealRequest) (*SealResponse, error)
    Submit(hash string, opts ...SubmitOption) (*SubmitReceipt, error)
    SubmitAttested(att *SignedAttestation) (*SubmitReceipt, error)
    Verify(hash string) (*VerificationProof, error)
    Status() (*EngineStatus, error)
}
```

Backends concretos:
- **embedded** (Gleipnir como referência 3CP) — `pkg/provenance/embedded_gleipnir.go`
- **gRPC** — `pkg/provenance/grpc.go` (requer build tag `grpc`)
- **noop** — `pkg/provenance/noop.go` (disconnected/dev)
