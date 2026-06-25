# Wardex em Pipelines CI/CD

Wardex é um **release gate**, não um scanner. Não encontra vulnerabilidades — decide o que fazer com elas. Cada scanner na tua pipeline produz findings; o Wardex consome esses findings e transforma-os numa decisão de governança ancorada nos teus ficheiros de politica reais.

Os padrões abaixo cobrem os pontos de integração mais comuns, começando pelo GitHub Actions.

> **Versão de referência:** v2.2.0  
> **Instalação:** `go install github.com/had-nu/wardex/v2@latest`

---

## Mapa de Comandos (v2.2.0)

| Comando | Propósito |
|---------|-----------|
| `wardex evaluate --evidence <file> --config <file>` | Release Gate com contexto de activo |
| `wardex assess <doc> <imp> --framework <name>` | Gap Analysis + LayerDelta |
| `wardex convert grype <file>` | Converte output Grype → formato Wardex |
| `wardex convert sbom <file>` | Converte SBOM CycloneDX → formato Wardex |
| `wardex enrich epss <file>` | Fetch EPSS real da FIRST.org + assina |
| `wardex accept request` | Cria aceitação de risco formal |
| `wardex accept verify` | Verifica integridade criptográfica |
| `wardex art14 list \| show \| finalize` | CRA Article 14 — ciclo de vida do artefacto |
| `wardex policy validate <dir>` | Valida schema dos ficheiros YAML |
| `wardex policy list <dir>` | Lista estado de conformidade |
| `wardex policy add` | Upsert de controlo por ID |
| `wardex policy check-expiry` | Verifica aceitações a expirar |
| `wardex simulate` | Simulação interactiva de risco |
| `wardex aggregate` | Agrega decisões de múltiplos frameworks |
| `wardex keygen` | Gera par de chaves Ed25519 |
| `wardex trust add \| revoke \| list` | Gerencia trust store |
| `wardex config seal` | Sela configuração em `.wexstate` |

---

## Padrão 1 — Release Gate Básico (Grype + GitHub Actions)

O fluxo mais comum: Grype faz o scan, o Wardex converte e avalia.

```
push → grype scan → wardex convert → wardex [gate] → deploy ou block
```

**`.github/workflows/risk-gate.yml`**

```yaml
name: Risk Governance Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  risk-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      # Passo 1: Scan com Grype
      - name: Scan with Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype dir:. -o json > grype-output.json

      # Passo 2: Instalar Wardex (SHA-pinned)
      - name: Install Wardex
        run: go install github.com/had-nu/wardex/v2@latest

      # Passo 3: Validar que os policy files estão bem formados
      - name: Validate policy files
        run: wardex policy validate ./frameworks/iso27001/

      # Passo 4: Converter output Grype → formato Wardex
      - name: Convert Grype findings
        run: wardex convert grype grype-output.json --output wardex-vulns.yaml

      # Passo 5: Enriquecer EPSS (Human-in-the-Loop)
      - name: Enrich EPSS scores
        env:
          WARDEX_ACCEPT_SECRET: ${{ secrets.WARDEX_ACCEPT_SECRET }}
        run: wardex enrich epss wardex-vulns.yaml --output epss-enriched.yaml

      # Passo 6: Avaliar o Release Gate
      - name: Evaluate Release Gate
        env:
          WARDEX_ACCEPT_SECRET: ${{ secrets.WARDEX_ACCEPT_SECRET }}
          WARDEX_ACTOR: ${{ github.actor }}
        run: |
          wardex evaluate \
            --evidence wardex-vulns.yaml \
            --epss-enrichment epss-enriched.yaml \
            --config ./wardex-config.yaml

      # Passo 7: Publicar relatório como artefacto
      - name: Upload security report
        if: always()
        uses: actions/upload-artifact@65c4c4a1ddce5f7f3d7f6de4d45ea3c70a2cca2f # v4
        with:
          name: wardex-security-report
          path: wardex-report.md
```

O `if: always()` no upload do relatório é deliberado. Um deploy bloqueado também é evidência — os auditores precisam de o ver.

---

## Padrão 2 — Excepção de Risco via Git (Formal Risk Acceptance)

Um gate que nunca pode ser ultrapassado não é governança — é um interruptor binário. O Wardex permite excepções documentadas e auditáveis via `wardex accept`.

```bash
# 1. Gerar relatório JSON com as decisões
wardex evaluate \
  --evidence wardex-vulns.yaml \
  --config wardex-config.yaml \
  -o json --out-file report.json

# 2. Solicitar aceitação formal (CISO aprova)
WARDEX_ACCEPT_SECRET=${{ secrets.WARDEX_ACCEPT_SECRET }} \
  wardex accept request \
    --report report.json \
    --cve CVE-2024-1234 \
    --accepted-by ciso@empresa.com \
    --justification "CVE mitigada por WAF; patch previsto para 2024-04-15" \
    --expires 30d

# 3. Na pipeline seguinte, a CVE aceite é automaticamente ignorada
wardex evaluate \
  --evidence wardex-vulns.yaml \
  --config wardex-config.yaml
# [INFO] CVE CVE-2024-1234 is covered by an active risk acceptance and will be ignored.
```

**Integração com o schema de policy files:**  
As excepções no formato `wardex accept` são armazenadas em `wardex-acceptances.yaml` com HMAC-SHA256. Para excepções a nível de controlo (não de CVE), usa o campo `exceptions[]` no próprio YAML de domínio:

```yaml
# frameworks/iso27001/technological_controls.yml
controls:
  - id: A.8.2
    title: "Privileged access rights"
    status: partial
    exceptions:
      - reason: "Sistema legado requer conta admin partilhada até migração Q3"
        expiry: "2025-09-01"
        approved_by: "CISO"
```

O PR que adiciona esta excepção é o registo de aprovação. O histórico de commits é o audit log.

---

## Padrão 3 — Gate Multi-Framework

Alguns ambientes precisam de satisfazer múltiplos frameworks em simultâneo. Corre uma avaliação por framework e interpreta os exit codes separadamente:

```yaml
      - name: Evaluate ISO 27001 gate
        id: iso_gate
        continue-on-error: true
        env:
          WARDEX_ACCEPT_SECRET: ${{ secrets.WARDEX_ACCEPT_SECRET }}
        run: |
          wardex evaluate \
            --evidence wardex-vulns.yaml \
            --config wardex-config.yaml \
            --framework iso27001 \
            -o json --out-file iso-result.json
          echo "iso_exit=$?" >> $GITHUB_ENV

      - name: Evaluate NIS2 gate
        id: nis2_gate
        continue-on-error: true
        env:
          WARDEX_ACCEPT_SECRET: ${{ secrets.WARDEX_ACCEPT_SECRET }}
        run: |
          wardex evaluate \
            --evidence wardex-vulns.yaml \
            --config wardex-config.yaml \
            --framework nis2 \
            -o json --out-file nis2-result.json
          echo "nis2_exit=$?" >> $GITHUB_ENV

      - name: Fail if any framework blocked
        run: |
          if [ "$iso_exit" != "0" ] || [ "$nis2_exit" != "0" ]; then
            echo "One or more framework gates blocked the release."
            exit 10
          fi
```

---

## Padrão 4 — Pre-Commit Hook Local

Um hook de pre-commit apanha problemas no momento em que um developer tenta commitar um policy file inválido. Segundos de feedback local valem mais que minutos de pipeline falhada.

**`.git/hooks/pre-commit`**

```bash
#!/bin/sh
# Valida todos os ficheiros de política antes de cada commit.

FRAMEWORKS_DIR="./frameworks"

if [ -d "$FRAMEWORKS_DIR" ]; then
  echo "wardex: validating policy files..."
  wardex policy validate "$FRAMEWORKS_DIR" || {
    echo "wardex: policy validation failed — fix YAML errors before committing"
    exit 1
  }
fi
```

Com o framework `pre-commit`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: wardex-policy-validate
        name: Wardex policy validation
        entry: wardex policy validate ./frameworks
        language: system
        pass_filenames: false
        files: '^frameworks/.*\.yml$'
```

O filtro `files:` garante que o hook só corre quando um `.yml` sob `frameworks/` está em stage — não em cada commit.

---

## Padrão 5 — Verificação de Drift Semanal (Snapshot)

Os policy files ficam desactualizados. Controlos marcados como `compliant` em Janeiro podem já não o estar em Junho. Um workflow agendado que compara snapshots detecta drift antes de uma auditoria:

```yaml
name: Compliance Drift Check

on:
  schedule:
    - cron: '0 9 * * 1'  # todas as segundas às 09:00 UTC

jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Install Wardex
        run: go install github.com/had-nu/wardex/v2@latest

      - name: Validate all framework policy files
        run: |
          for dir in ./frameworks/*/; do
            echo "Validating $dir..."
            wardex policy validate "$dir"
          done

      - name: Generate compliance snapshot and delta report
        run: |
          wardex assess \
            documented-controls.yaml implemented-controls.yaml \
            --config wardex-config.yaml \
            --framework iso27001 \
            -o markdown --out-file compliance-report.md

      - name: Upload compliance report
        if: always()
        uses: actions/upload-artifact@65c4c4a1ddce5f7f3d7f6de4d45ea3c70a2cca2f # v4
        with:
          name: weekly-compliance-report
          path: compliance-report.md
```

O relatório incluirá a secção **Delta** comparando com o snapshot anterior — evidência objectiva de evolução de maturidade para auditores.

---

## Convenção de Localização dos Policy Files

O Wardex espera policy files num local previsível para que comandos locais e workflows CI apontem para a mesma fonte de verdade sem duplicação de configuração:

```
repo-root/
  frameworks/
    iso27001/
      organizational_controls.yml    # A.5 — Organisational Controls
      people_controls.yml            # A.6 — People Controls
      physical_controls.yml          # A.7 — Physical Controls
      technological_controls.yml     # A.8 — Technological Controls
    nis2/
      governance.yml
      supply_chain.yml
    nist_csf/
      identify.yml
      protect.yml
      detect.yml
  wardex-config.yaml
  wardex-acceptances.yaml
  wardex-accept-audit.log
  .github/
    workflows/
      risk-gate.yml
```

A estrutura de directórios espelha a hierarquia de secções do framework. Quando um novo domínio é adicionado, é um ficheiro novo — não uma edição a um existente. O `git blame` num único ficheiro cobre o histórico completo desse domínio sem ruído de outros domínios.

---

## Exit Codes (v2.2.0)

| Código | Constante | Quando ocorre |
|--------|-----------|---------------|
| `0` | `ALLOW` | Gate passou / validação limpa |
| `3` | `IntegrityFailure` / `Tampered` | Configuração adulterada — selo `.wexstate` não corresponde |
| `4` | `StoreInconsistent` | Armazém de aceitações inconsistente |
| `10` | `GateBlocked` | Gate bloqueou — risco excede `risk_appetite` |
| `11` | `ComplianceFail` | Gap excede `--fail-above` |
| `12` | `ActivelyExploited` | CRA Article 14 — CVE no catálogo CISA KEV |

```bash
wardex evaluate --evidence vulns.yaml --config wardex-config.yaml
exit_code=$?

case $exit_code in
  0) echo "Gate passed — deploy authorized" ;;
  3) echo "Integrity failure / Tampered — sealed config mismatch or acceptance tampered" ;;
  4) echo "Store inconsistent — acceptance store mismatch, run wardex accept verify" ;;
  10) echo "Gate BLOCKED — review risk report and consider wardex accept" ;;
  11) echo "Compliance gap exceeds threshold — update controls" ;;
  12) echo "ACTIVE EXPLOITATION — CRA Article 14 notification required" ;;
  *) echo "Unexpected error (exit $exit_code) — check stderr" ;;
esac
```

---

### CPL — Config Provenance Link (v2.2+)

```yaml
# .github/workflows/cpl-audit.yml
name: CPL Audit
on:
  schedule:
    - cron: '0 6 * * 1'   # every Monday 06:00 UTC
  workflow_dispatch:

jobs:
  verify-link:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # fetch all history for config archives
      - run: wardex audit verify-link --audit-log wardex-gate-audit.log --config-archive ./config-versions/
      - run: wardex audit verify-chain --audit-log wardex-gate-audit.log
```

### Hash da configuração

```yaml
# Usar em steps que precisam de proveniência
- name: Record config hash
  run: |
    echo "CONFIG_HASH=$(wardex config hash --config wardex-config.yaml)" >> $GITHUB_ENV
```
