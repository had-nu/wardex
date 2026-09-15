# Acknowledgments

Este ficheiro regista as atribuições e a proveniência de terceiros dos padrões de
desenho aplicados no Wardex. É a fonte canónica para qualquer contribuição que
seja baseada em trabalho de terceiros (cf. `CLA.md §4(b)`).

---

## Nym Privacy Platform — referência de desenho (v2.6.0)

As funcionalidades de hardening do Wardex v2.6.0 transpõem padrões de engenharia
do ecossistema **Nym** (Nym Privacy Platform), usados como **referência de
desenho** — não como cópia literal de código.

| Campo | Valor |
|-------|-------|
| Projeto | Nym Privacy Platform (monorepo Rust) |
| Upstream | https://github.com/nymtech/nym |
| Licença | Apache-2.0 (`Cargo.toml` → `license = "Apache-2.0"`; `LICENSES/Apache-2.0.txt`) |
| Estado estudado | Snapshot do monorepo `nym-develop`, 2026-09-14 (sem metadados git no snapshot local; sem pin de commit) |
| Relação | Design reference apenas; sem código do Nym no tree, sem dependências (`go.mod`/`go.sum` sem Nym, sem `vendor/`) |

### Padrões aplicados (P1–P11)

Mapeamento completo com referências `ficheiro:linha` do upstream em
`doc/specs/SPEC_wardex_v2.6.0_nym_patterns.md` (§2). Resumo:

| Padrão | Origem Nym (referência) | Aplicação Wardex |
|--------|------------------------|------------------|
| P1 — versão explícita por frame | `models.rs`; `store-cipher` `CURRENT_VERSION` | `format_version` numérico em artefactos novos (L2) |
| P2 — parse de versões antigas mantido | `api/mod.rs:73-114` | Leitura legada em todos os formatos evoluídos |
| P3 — teste `the_current_version_is_one_we_support` | Nym test suite | `TestCurrentArtifactVersionIsSupported` |
| P4 — nunca mutar o ficheiro de origem | `upgrade_helpers.rs` | Migrações in-memory (config/domain) |
| P5 — o audit log é a fonte de verdade | — (invariante Wardex) | Índices derivados são cache reconstruível |
| P6 — carga-antiga-tentada-primeiro | `upgrade_helpers.rs:10-47` | Loader `KnownFields(true)` + fallback leniente v1 |
| P7 — `deny_unknown_fields` | `nym-node/config/mod.rs:478-502` | `yaml.Decoder.KnownFields(true)` |
| P8 — gate por classes de risco/deadlines | `ci-cargo-deny.yml` vs `nightly-security-audit.yml` | `--gate-class pr\|deploy\|nightly\|canary` (L3) |
| P9 — paginação por cursor `LIMIT+1` | `gateway-storage/src/inboxes.rs:23-33` | `wardex audit export --limit --cursor` (L5) |
| P10 — persistência cifrada em envelope | `common/store-cipher/src/lib.rs` | `pkg/keys` Argon2id + AES-256-GCM opt-in (L6) |
| P11 — kill-switch com tripwire | `upgrade_mode/watcher.rs:19-110` | `forced_upgrade` com tripwire de atestação (L7) |

### Declaração

- Os padrões acima são princípios de engenharia (não expressão copyrightável) e
  foram reimplementados de forma original em Go.
- Nenhuma porção do código-fonte do Nym foi copiada, traduzida ou incorporada no
  Wardex; o repositório não contém código, fixtures ou dependências do Nym.
- O licenciamento do Wardex mantém-se inalterado: AGPL-3.0-or-later **ou**
  LicenseRef-Wardex-Commercial.
- Nenhum componente do Nym é exigido em runtime — o tripwire (L7) assenta nas
  fontes de evidência próprias do Wardex (EPSS/KEV) e o Gleipnir continua uma
  interface opcional pós-evidência.

---

## English

This file records third-party attribution and provenance for design patterns
applied in Wardex, and is the canonical reference for contributions based on
third-party work (see `CLA.md §4(b)`).

### Nym Privacy Platform — design reference (v2.6.0)

The v2.6.0 hardening features transpose engineering patterns from the **Nym**
ecosystem (Nym Privacy Platform), used as a **design reference** — not as a
literal copy of code.

| Field | Value |
|-------|-------|
| Project | Nym Privacy Platform (Rust monorepo) |
| Upstream | https://github.com/nymtech/nym |
| License | Apache-2.0 (`Cargo.toml` → `license = "Apache-2.0"`; `LICENSES/Apache-2.0.txt`) |
| Studied state | `nym-develop` monorepo snapshot, 2026-09-14 (no git metadata in the local snapshot; no commit pin) |
| Relationship | Design reference only; no Nym code in the tree, no dependencies (`go.mod`/`go.sum` clean, no `vendor/`) |

**Statement:** the patterns above are engineering principles (not copyrightable
expression) and were re-implemented natively in Go. No Nym source code has been
copied, translated, or embedded in Wardex; the repository contains no Nym code,
fixtures, or dependencies. Wardex licensing is unchanged (AGPL-3.0-or-later **or**
LicenseRef-Wardex-Commercial). No Nym component is required at runtime — the
tripwire (L7) relies on Wardex's own evidence sources (EPSS/KEV) and Gleipnir
remains an optional post-evidence interface.