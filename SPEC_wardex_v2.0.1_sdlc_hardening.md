# SPEC — Wardex v2.0.1: SDLC Hardening

**Status:** Draft  
**Author:** Root Security Governance Advisory  
**Version target:** v2.0.1  
**Tipo:** Patch de segurança — sem alterações funcionais  
**Âmbito:** Pipeline CI/CD, configuração de linters, documentação de segurança

---

## 1. Contexto

O Wardex é uma ferramenta de segurança usada directamente em pipelines CI/CD de terceiros. Um compromisso do próprio Wardex — via dependência envenenada, action comprometida, ou binário adulterado — transforma-o num vector de ataque contra os seus utilizadores. O v1.7.1 reconheceu este risco e aplicou SHA256 pinning nas GitHub Actions. A avaliação do estado actual encontrou cinco desvios que ficaram por corrigir, dois dos quais são vectores activos num adversário com acesso ao repositório ou à cadeia de supply chain.

Este patch não introduz funcionalidade. Corrige o que existe.

---

## 2. Alterações por ficheiro

### 2.1 `.github/workflows/cla.yml` — Substituir tag por SHA

**Severidade:** Alta  
**Razão:** O único workflow que ainda usa tag em vez de SHA. Agrava o risco porque usa `pull_request_target` — que tem acesso a segredos mesmo em PRs de forks — e `contents: write`. Uma tag pode ser movida silenciosamente para apontar para código malicioso; um SHA é imutável.

**Alteração:**

```yaml
# ANTES
uses: contributor-assistant/github-action@v2.6.1

# DEPOIS
uses: contributor-assistant/github-action@<SHA-de-v2.6.1>
```

O SHA correcto deve ser obtido no momento da implementação:

```bash
gh api repos/contributor-assistant/github-action/git/ref/tags/v2.6.1 \
  --jq '.object.sha'
```

Se a tag for anotada (annotated tag), o SHA do commit subjacente obtém-se com:

```bash
gh api repos/contributor-assistant/github-action/git/tags/<sha-da-tag> \
  --jq '.object.sha'
```

O comentário de referência de versão mantém-se por legibilidade:

```yaml
uses: contributor-assistant/github-action@<sha>  # v2.6.1
```

**Verificação:** Após a alteração, confirmar que o workflow CLA passa em PRs de teste antes de fazer merge.

---

### 2.2 `.github/workflows/ci.yml` — Remover exclusão global G304 do gosec

**Severidade:** Alta  
**Razão:** `-exclude=G304` cega toda a categoria "file path provided as taint input" para código futuro. O v1.1.0 corrigiu os ficheiros específicos que geravam G304; a exclusão global deveria ter sido removida no mesmo momento. Qualquer path manipulation introduzida em v2.0 ou posterior passa despercebida.

**Alteração:**

```yaml
# ANTES
- name: Run gosec
  run: gosec -exclude=G304 ./...

# DEPOIS
- name: Run gosec
  run: gosec ./...
```

Se a remoção da exclusão revelar findings residuais legítimos (falsos positivos no código existente), suprimir inline com `// #nosec G304 -- <razão>` no ficheiro específico. Não restaurar a exclusão global.

**Procedimento de implementação:**

1. Remover `-exclude=G304` do workflow.
2. Correr `gosec ./...` localmente.
3. Para cada finding G304 que aparecer, avaliar se é exploitável no contexto do Wardex.
4. Falsos positivos confirmados: suprimir com `// #nosec G304 -- [justificação]` no ficheiro.
5. Findings reais: corrigir antes de fazer merge.

---

### 2.3 `.golangci.yml` — Expandir cobertura de linters

**Severidade:** Alta  
**Razão:** Com `disable-all: true` e apenas três linters activos (`errcheck`, `govet`, `ineffassign`), classes inteiras de problemas passam na CI sem aviso. Para uma ferramenta de segurança, a configuração mínima aceitável inclui análise estática (`staticcheck`), detecção de problemas de segurança (`gosec`), e controlo de dependências (`gomodguard`).

**Configuração actualizada:**

```yaml
version: "3"
run:
  timeout: 5m
  go: "1.26"

linters:
  disable-all: true
  enable:
    # existentes
    - errcheck
    - govet
    - ineffassign
    # análise estática
    - staticcheck
    - unused
    # segurança
    - gosec
    # dependências
    - gomodguard
    # qualidade
    - misspell
    - exhaustive

linters-settings:
  errcheck:
    check-type-assertions: true
    check-blank: true

  gosec:
    excludes:
      # Excluir apenas se confirmado como falso positivo após avaliação em 2.2
      # Deixar vazio por omissão — preencher após o passo 2.2
    severity: medium
    confidence: medium

  gomodguard:
    blocked:
      modules: []
      # Preencher com módulos explicitamente proibidos conforme política de dependências
      # evolui. Por agora vazio — a lista em branco activa o linter sem bloquear nada.

  exhaustive:
    default-signifies-exhaustive: true

  misspell:
    locale: US

issues:
  exclude-use-default: false
  max-issues-per-linter: 0
  max-same-issues: 0
```

**Nota sobre `exhaustive`:** O flag `default-signifies-exhaustive: true` significa que um `switch` com `default` não é reportado como não-exaustivo — comportamento correcto para o modelo de decisão do Wardex (ALLOW/WARN/BLOCK/ActivelyExploited) onde um `default` defensivo é intencional.

**Nota sobre `gomodguard`:** A lista de módulos bloqueados começa vazia. O linter activa-se agora para que a infraestrutura esteja pronta quando a política de dependências for formalizada, sem impacto imediato na pipeline.

---

### 2.4 `SECURITY.md` — Completar contacto, PGP e scope

**Severidade:** Média  
**Razão:** O ficheiro actual tem `Exemplo Empresa SA / had-nu` como contacto — um placeholder nunca resolvido. Com dual-license comercial e clientes reais, é a primeira coisa que um researcher lê antes de reportar. Um contacto inválido redirige vulnerabilidades para canais públicos.

**Conteúdo actualizado:**

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v2.x    | Yes       |
| v1.9.x  | Critical fixes only |
| < v1.9  | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to: **andre.ataide@proton.me**

PGP key fingerprint: `979A C8CE 8F35 7652`  
Public key: https://keys.openpgp.org/search?q=979AC8CE8F357652

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what an attacker can achieve)
- Affected versions
- Suggested fix (optional)

**Response timeline:**
- Acknowledgement within 48 hours
- Triage and severity assessment within 5 business days
- Resolution update within 14 days for confirmed vulnerabilities

## Scope

**In scope:**
- The `wardex` CLI binary and all packages under `pkg/`
- GitHub Actions workflows in this repository
- The release pipeline (goreleaser, cosign signing, SBOM generation)
- Cryptographic operations: HMAC-SHA256 acceptance signatures, Ed25519 trust store keys, audit log integrity

**Out of scope:**
- Vulnerabilities in downstream tools that Wardex ingests (Grype, Syft) — report to those projects
- Wardex used in configurations explicitly documented as insecure (e.g., `--strict` disabled in a non-isolated environment by operator choice)

## WARDEX_ACCEPT_SECRET Key Rotation

The `WARDEX_ACCEPT_SECRET` environment variable generates HMAC-SHA256 signatures for risk acceptances. To rotate:

1. Generate a new high-entropy secret (minimum 32 bytes, base64-encoded recommended).
2. Update `WARDEX_ACCEPT_SECRET` in your CI/CD runner environments and local profiles.
3. New acceptances sign with the new key. The `signature_version` field in acceptance records traces which key produced which record.
4. Existing acceptances signed with the old key remain valid and verifiable if the old key is retained. If the old key is discarded, those acceptances cannot be re-verified — accept this trade-off consciously.

## Security Practices

- Dependencies scanned weekly by Dependabot (gomod + github-actions)
- Static analysis: `staticcheck`, `gosec`, `govulncheck` on every PR
- Race condition detection: `go test -race` on every PR
- GitHub Actions pinned to SHA256 commits, not tags
- Release binaries signed with `cosign`; SBOM generated in CycloneDX format via goreleaser
- Trust store and sealed config use Ed25519 keys; audit logs are HMAC-SHA256 signed and append-only
```

---

### 2.5 `Makefile` — Adicionar target `security`

**Severidade:** Média  
**Razão:** Um developer que corra `make lint` localmente não executa `govulncheck` nem `gosec`. A discrepância entre o que a CI corre e o que o developer corre localmente cria uma janela onde problemas de segurança passam no desenvolvimento mas são capturados (tardiamente) só na CI.

**Alteração:**

```makefile
.PHONY: all build test lint security clean

BINARY := wardex
PKG    := ./...

all: build

build:
	go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) .

test:
	go test -v -race -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out

lint:
	golangci-lint run $(PKG)

security:
	govulncheck $(PKG)
	gosec $(PKG)

clean:
	rm -rf bin/ coverage.out
```

`govulncheck` e `gosec` devem estar instalados localmente. O target não instala as ferramentas — responsabilidade do developer, documentada no `CONTRIBUTING.md` se existir, ou num `doc/development.md` a criar.

---

## 3. O que este patch não cobre

Dois itens da avaliação ficam deliberadamente fora do v2.0.1:

**`govulncheck` sem verificação de integridade do binário.** O risco é baixo dado que é um módulo `golang.org/x` distribuído pelo proxy oficial. A solução correcta envolve ou uma GitHub Action dedicada com SHA pinned, ou verificação de checksum após `go install`. Nenhuma das duas é trivial de implementar correctamente sem testar contra o ambiente de CI real. Deferido para v2.1.

**SLSA provenance no goreleaser.** Requer configuração adicional no goreleaser e possivelmente uma GitHub Action dedicada (`slsa-framework/slsa-github-generator`). Tem impacto no pipeline de release que merece um ciclo de teste independente. Deferido para v2.1.

---

## 4. Testes e verificação

Não há testes unitários novos — este patch altera configuração e documentação, não código Go. A verificação é feita por inspecção e por observação do comportamento da CI após merge.

**Checklist de verificação antes de merge:**

- [ ] SHA do `cla.yml` verificado contra o commit real da tag v2.6.1
- [ ] Workflow CLA testado com um PR de teste após a alteração
- [ ] `gosec ./...` corrido localmente sem a exclusão G304; findings avaliados e resolvidos
- [ ] `golangci-lint run ./...` passa localmente com a nova configuração
- [ ] `make security` corre sem erros num ambiente de desenvolvimento limpo
- [ ] `SECURITY.md` — link do PGP key verificado como acessível publicamente

---

## 5. Notas de upgrade

Nenhuma alteração de interface, protocolo ou formato de dados. Pipelines existentes que usem o Wardex não requerem qualquer ajuste. O único impacto visível para utilizadores externos é o `SECURITY.md` actualizado com contacto e scope correctos.

Para maintainers: após merge, confirmar que a CI passa em verde em todos os três jobs (`test`, `lint`, `security`) antes de publicar a release tag.
