# Spec Técnica — Wardex / pkg/accept
**Risk Acceptance Workflow — Accountability Undeniable**

> **Nota de arquitectura:** este documento especifica o package `pkg/accept/` do módulo
> `github.com/had-nu/wardex`. Não é um projecto separado. Os subcomandos descritos aqui
> são invocados como `wardex accept <subcomando>` a partir do binário único do wardex.
> Não existe `wardex-accept` como binário ou módulo Go independente.

---

## 1. Visão Geral

O package `pkg/accept/` implementa o workflow formal de aceitação de risco para decisões
de release bloqueadas pelo release gate do wardex. Quando o wardex emite `exit 10`, o
operador usa `wardex accept request` para formalizar a aceitação: **explícita, nominada,
justificada, temporalmente limitada e criptograficamente assinada** — tornando impossível
contornar o gate de forma silenciosa.

**Objetivo central:** eliminar a aceitação implícita de risco. Qualquer avanço sobre um
release bloqueado deve deixar um rastro auditável, irrefutável e versionável — quem
aceitou, quando, porquê, e até quando.

**Premissa de design:** o risco humano de contornar controlos é tão real quanto o risco
técnico da vulnerabilidade. O `pkg/accept/` não impede que o dono do risco avance — mas
torna o avanço um acto formal, consciente e rastreável, não um atalho silencioso.

**Premissa de segurança:** a accountability não pode depender de steps externos opcionais.
Toda verificação de integridade é uma pré-condição interna das operações de leitura —
não um comando separado que pode ser omitido ou comentado num pipeline YAML.

**Relação com o wardex:** o `pkg/accept/store` é invocado internamente pelo wardex
sempre que `release_gate.enabled: true` no config. A verificação de integridade das
aceitações é uma pré-condição do fluxo principal — não uma feature opcional. Os
subcomandos `wardex accept` são a interface de gestão que o operador usa; os packages
internos são o que o wardex usa directamente.

---

## 2. Princípios de Accountability

Estes princípios guiam todas as decisões de design e não podem ser comprometidos por
conveniência de implementação:

**P1 — Nominação obrigatória:** toda aceitação tem um responsável identificável. Não
existe aceitação anónima ou de sistema.

**P2 — Justificativa substantiva:** a justificativa não pode ser vazia, genérica ou
inferior a um mínimo de caracteres configurável. "ok" não é uma justificativa.

**P3 — Temporalidade forçada:** toda aceitação tem prazo de validade. Aceitações
perpétuas não existem. O prazo máximo é configurável pela organização.

**P4 — Imutabilidade do registo:** após gravada, uma aceitação não pode ser editada
manualmente sem invalidar a assinatura. Adulteração é detectada automaticamente e
bloqueia o pipeline.

**P5 — Visibilidade imediata:** no momento em que uma aceitação é criada, as partes
interessadas são notificadas. Não há aceitações silenciosas.

**P6 — Rastreabilidade de contexto:** a aceitação regista não só a decisão mas o
contexto técnico completo no momento da decisão — risk score, breakdown, controles
compensatórios activos. Não é possível alegar desconhecimento do risco aceite.

**P7 — Verificação interna não delegável:** a integridade das aceitações é verificada
como pré-condição interna do `store.Load` — não como step externo opcional. Nenhuma
operação de leitura ocorre sem verificação prévia de integridade.

**P8 — Configuração auditada:** alterações ao `wardex-config.yaml` (especialmente ao
`risk_appetite`) são eventos rastreáveis. O hash do config é registado no audit log a
cada execução. Elevar o `risk_appetite` para contornar o gate é detectável.

**P9 — Secret nunca em texto claro no repositório:** a ferramenta recusa execução se
o signing secret vier de valor literal no ficheiro de config. O secret só é aceite via
variável de ambiente ou ficheiro externo ao repositório.

**P10 — Audit log como fonte de verdade primária:** o YAML é o estado operacional; o
audit log JSONL é o registo histórico imutável. A consistência entre os dois é verificada
activamente — redução de entradas no YAML sem registo no log é tratada como adulteração.

**P11 — Âncora de verificação independente:** a verificação HMAC local detecta adulteração
mas depende da chave de assinatura — que pertence à organização auditada. Para que um
auditor externo possa verificar a integridade de forma independente, cada evento do audit
log é reencaminhado em tempo real para um sistema de log centralizado externo. Este sistema
— fora do controlo da organização no contexto da auditoria — é a âncora irrefutável.
Divergência entre o log local e o sistema externo é prova de adulteração sem necessidade
de partilhar a chave de assinatura com o auditor.

---

## 3. Requisitos Funcionais

### RF-01 — Leitura do GateReport do Wardex

- Lê o output JSON do Wardex (`--output json`) como fonte de verdade sobre o que foi
  bloqueado.
- Valida que o GateReport é autêntico: verifica o hash SHA256 do ficheiro para detectar
  adulteração entre o momento do bloco e o momento da aceitação.
- Extrai automaticamente todos os CVEs com `decision: block` e os apresenta ao operador.
- Rejeita GateReports com timestamp superior a `max_report_age` (configurável, default:
  24h) — impede aceitação de relatórios desactualizados.
- O hash do GateReport é gravado em cada aceitação como `report_hash`. O Wardex verifica
  este hash ao consumir aceitações — se o GateReport actual diverge do que originou a
  aceitação (por mudança de contexto ou novo scan), a aceitação é invalidada.

### RF-02 — Verificação Interna Não Delegável (P7)

A verificação de integridade das aceitações **não é um subcomando externo** que o
operador pode omitir. É uma pré-condição interna invocada automaticamente pelo
`store.Load` antes de qualquer leitura:

```
store.Load(path)
  └── verifier.VerifyAll(acceptances, key)
        ├── assinatura inválida → ErrTampered → exit 3 imediato
        ├── entrada expirada → marcada como inválida, não como erro fatal
        └── todas válidas → prossegue
```

O Wardex, ao carregar `wardex-acceptances.yaml`, chama `store.Load` que internamente
executa `verifier.VerifyAll`. Se adulteração for detectada, o Wardex emite `exit 3`
independentemente de qualquer configuração do operador. Este comportamento não é
configurável.

Adicionalmente, o Wardex verifica na inicialização:
- O hash do `wardex-config.yaml` contra o último valor registado no audit log.
- Que `--gate` está presente quando `release_gate.enabled: true` no config.
- Que o signing secret não é um valor literal (P9).

### RF-03 — Auditoria do Config (P8)

A cada execução do Wardex e do Wardex Accept, o hash SHA256 do `wardex-config.yaml` é
calculado e comparado com o último valor registado no audit log:

```jsonl
{"ts":"2025-10-14T10:00:00Z","event":"config.loaded","config_hash":"sha256:abc123...","risk_appetite":6.0}
{"ts":"2025-10-15T09:00:00Z","event":"config.changed","config_hash":"sha256:xyz789...","prev_hash":"sha256:abc123...","risk_appetite":8.5,"changed_fields":["release_gate.risk_appetite"]}
```

- Mudanças no config são eventos `config.changed` no audit log com os campos alterados.
- Mudança no `risk_appetite` dispara notificação às partes interessadas (mesmo canal que
  `acceptance.created`).
- O evento `config.changed` não bloqueia a execução — mas é irremovível do audit log e
  visível em qualquer revisão de auditoria.

### RF-04 — Validação do Secret (P9)

Na inicialização, a ferramenta valida a origem do signing secret:

```go
// Ordem de precedência:
// 1. Variável de ambiente WARDEX_ACCEPT_SECRET (preferido)
// 2. Ficheiro externo referenciado por signing_secret_file no config
// 3. Valor literal em signing_secret no config → REJEITADO com erro fatal

// ErrLiteralSecret é emitido se o secret vier de valor literal no config.
// Mensagem: "signing secret must not be a literal value in config;
//            use WARDEX_ACCEPT_SECRET env var or signing_secret_file"
var ErrLiteralSecret = errors.New("...")
```

- A ferramenta detecta valores literais verificando a ausência do prefixo `${` e a
  ausência de `signing_secret_file`. Se nenhum dos dois está presente, recusa execução.
- Esta validação corre antes de qualquer operação de leitura ou escrita.

### RF-05 — Consistência entre YAML e Audit Log (P10)

O Wardex Accept mantém um contador de entradas no audit log (`acceptance.created`) e
compara com o número de entradas no `wardex-acceptances.yaml`:

```
entradas_yaml < eventos_created_no_log → ErrStoreInconsistent → exit 3
```

- Apagar o ficheiro YAML e recriar é detectável porque o audit log regista cada
  `acceptance.created` antes de a entrada ser gravada no YAML.
- A verificação de consistência é parte do `store.Load` — corre automaticamente antes
  de qualquer leitura.
- Na primeira execução (ambos os ficheiros inexistentes), a contagem é 0 = 0 e passa.

### RF-06 — Gate Obrigatório quando Habilitado

Quando `release_gate.enabled: true` no `wardex-config.yaml`, o flag `--gate` é
obrigatório no Wardex. Ausência do flag com gate habilitado emite `exit 1` com mensagem:

```
error: release_gate is enabled in config but --gate flag is missing.
       provide a vulnerability file: wardex --gate vuln-scan.yaml ...
       to run without gate evaluation, set release_gate.enabled: false in config
       (config change will be logged in audit trail)
```

A mensagem inclui deliberadamente o aviso de que desabilitar o gate é um evento auditado.

### RF-07 — Subcomando `wardex-accept request`

Inicia o workflow de aceitação para um ou mais CVEs bloqueados.

```bash
wardex-accept request \
  --report gate-report.json \
  --cve CVE-2024-1234 \
  --accepted-by "maria.silva@empresa.com" \
  --justification "Componente não reachable em produção até patch v2.2" \
  --expires 2025-10-28 \
  --ticket "JIRA-4821"
```

- `--cve` aceita múltiplos valores para aceitações em lote.
- `--accepted-by` deve ser um endereço de email válido.
- `--justification` tem comprimento mínimo configurável (default: 80 caracteres). Rejeita
  justificativas genéricas por lista de termos proibidos configurável.
- `--expires` é obrigatório. Não aceita datas superiores a `max_acceptance_days`
  (configurável, default: 30 dias).
- `--ticket` é opcional mas recomendado.
- Antes de gravar, apresenta um resumo de confirmação com o breakdown completo do risco
  e pede confirmação explícita (`y/N`). Default é `N`.
- O audit log recebe o evento `acceptance.created` **antes** da entrada ser gravada no
  YAML. Se a gravação no YAML falhar, o evento fica no log como `acceptance.write_failed`
  — mantendo consistência detectável.

### RF-08 — Geração da Aceitação com Assinatura

Após confirmação, gera uma entrada no arquivo `wardex-acceptances.yaml`:

```yaml
acceptances:
  - id: "acc-20251014-001"
    cve_id: "CVE-2024-1234"
    component: "com.example:auth-lib:2.1.0"
    release_risk_at_acceptance: 8.7
    risk_appetite: 6.0
    accepted_by: "maria.silva@empresa.com"
    accepted_at: "2025-10-14T15:32:00Z"
    expires_at: "2025-10-28T00:00:00Z"
    justification: "Componente não reachable em produção até patch da v2.2 — prazo acordado com equipa de infra"
    ticket_ref: "JIRA-4821"
    interactive: true                        # false se criado com --yes
    context_snapshot:
      cvss_base: 9.1
      epss_score: 0.84
      asset_criticality: 0.9
      exposure_factor: 0.95
      config_hash: "sha256:abc123..."        # Hash do wardex-config.yaml no momento da aceitação
      compensating_controls:
        - type: "waf"
          effectiveness: 0.35
        - type: "network_segmentation"
          effectiveness: 0.25
      breakdown_summary: "adjusted=7.64 × criticality=0.9 × exposure=0.95 - compensation=0.52 = 8.7"
    signature: "sha256:a3f1c2d4e5b6..."      # HMAC-SHA256 do conteúdo completo da entrada
    report_hash: "sha256:9b2e1f3c4d5a..."   # Hash do GateReport de origem
```

- `context_snapshot.config_hash` regista o hash do config no momento da aceitação.
  Se o config mudar após a aceitação (ex: `risk_appetite` elevado), o Wardex detecta
  a divergência e marca a aceitação como `stale` — requerendo re-confirmação.
- `interactive: false` é gravado quando `--yes` é usado, tornando automações auditáveis.
- `signature` é HMAC-SHA256 de todos os campos excepto o próprio campo `signature`.

### RF-09 — Verificação de Aceitações pelo Wardex

O Wardex, ao consumir `wardex-acceptances.yaml` para decidir se um CVE bloqueado tem
aceitação válida, executa internamente as seguintes verificações em sequência:

```
Para cada aceitação relevante:
  1. verifier.VerifySignature        → ErrTampered se falhar
  2. verifier.CheckExpiry            → inválida se expirada
  3. verifier.CheckReportHash        → inválida se GateReport actual diverge
  4. verifier.CheckConfigHash        → stale se config mudou desde a aceitação
  5. audit.CheckConsistency          → ErrStoreInconsistent se YAML < log
```

Apenas aceitações que passam todos os cinco checks são tratadas como válidas. Uma
aceitação `stale` (config mudou) é tratada como `partial` — o Wardex emite warning
mas não bloqueia, exigindo que o operador re-confirme a aceitação com o config actual.

### RF-10 — Subcomando `wardex-accept verify`

Verifica a integridade de todas as aceitações e a consistência com o audit log.
Disponível como comando explícito para uso em revisões manuais e relatórios.

```bash
wardex-accept verify [--acceptances wardex-acceptances.yaml]
```

Output detalhado por entrada:

```
[OK] acc-20251014-001  CVE-2024-1234  signature=ok  expiry=ok  report=ok  config=ok
[WARN]  acc-20251010-002  CVE-2024-0001  signature=ok  expiry=ok  report=ok  config=STALE
[BLOCK] acc-20251001-003  CVE-2024-5678  TAMPERED — signature mismatch
```

- Exit `0`: todas as entradas válidas.
- Exit `3`: adulteração detectada em pelo menos uma entrada.
- Exit `4`: inconsistência entre YAML e audit log.

### RF-11 — Subcomando `wardex-accept list`

Lista o estado actual de todas as aceitações.

```bash
wardex-accept list [--expired] [--active] [--stale] [--cve CVE-ID]
```

| ID               | CVE            | Risk  | Accepted By             | Expires    | Status     |
|------------------|----------------|-------|-------------------------|------------|------------|
| acc-20251014-001 | CVE-2024-1234  | 8.7   | maria.silva@empresa.com | 2025-10-28 | [OK] Active  |
| acc-20251013-002 | CVE-2024-0099  | 7.1   | joao.costa@empresa.com  | 2025-10-20 | [WARN] Stale   |
| acc-20251001-003 | CVE-2024-0001  | 7.2   | joao.costa@empresa.com  | 2025-10-10 | [BLOCK] Expired |

- `stale`: aceitação válida mas o config mudou desde a sua criação — requer re-confirmação.
- Aceitações expiradas e revogadas permanecem como registo histórico — nunca apagadas.
- `--output json` exporta a lista completa para integração com dashboards.

### RF-12 — Subcomando `wardex-accept revoke`

Revoga uma aceitação activa antes do prazo.

```bash
wardex-accept revoke \
  --id acc-20251014-001 \
  --revoked-by "carlos.mendes@empresa.com" \
  --reason "Patch disponível — vulnerabilidade resolvida em v2.2.1"
```

- A entrada não é apagada — é marcada com `status: revoked` com `revoked_by`,
  `revoked_at` e `revocation_reason`.
- Uma nova assinatura é gerada sobre o conteúdo actualizado.
- Notificação enviada às partes interessadas.

### RF-13 — Notificações

Toda aceitação, expiração iminente, revogação, adulteração e mudança de config dispara
notificação às partes interessadas.

**Eventos notificados:**

| Evento                  | Quando                                                          |
|-------------------------|-----------------------------------------------------------------|
| `acceptance.created`    | Imediatamente após gravação                                     |
| `acceptance.expiring`   | X dias antes do prazo (configurável, default: 3)               |
| `acceptance.expired`    | No momento em que o prazo é ultrapassado                        |
| `acceptance.revoked`    | Imediatamente após revogação                                    |
| `acceptance.stale`      | Quando o config muda e existem aceitações activas afectadas     |
| `verification.tampered` | Quando adulteração é detectada                                  |
| `store.inconsistent`    | Quando YAML e audit log divergem                                |
| `config.changed`        | Quando o hash do config muda entre execuções                    |

**Canais suportados:**

- **Webhook** (Slack, Teams, qualquer endpoint HTTP POST)
- **Email** via SMTP (opcional)

Falha de notificação **não** bloqueia a gravação da aceitação — é registada como
`notification.failed` no audit log. A accountability local não depende de serviços
externos.

### RF-14 — Subcomando `wardex-accept check-expiry`

Verifica aceitações a expirar em breve. Usado em pipelines agendadas (cron).

```bash
wardex-accept check-expiry --warn-before 3d
```

- Exit `0`: nenhuma aceitação a expirar no período.
- Exit `4`: uma ou mais aceitações expiram dentro de `--warn-before`.

### RF-15 — Reencaminhamento de Audit Log para Sistema Externo (P11)

Cada evento gravado no audit log local é reencaminhado em tempo real para um sistema
de log centralizado externo. Este reencaminhamento é a âncora de verificação independente
que permite a auditores externos comparar o log local com uma fonte que a organização
não controla — sem necessitar da chave de assinatura HMAC.

**O reencaminhamento é síncrono por defeito:** o evento é enviado para o sistema externo
antes de ser considerado gravado. Se o reencaminhamento falhar, o comportamento depende
da configuração `log_forwarding.on_failure`:

| Valor          | Comportamento                                                          |
|----------------|------------------------------------------------------------------------|
| `block`        | A operação falha. Nenhuma aceitação é criada sem confirmação externa.  |
| `warn`         | O evento é gravado localmente; falha registada como `forward.failed`.  |
| `best_effort`  | Igual a `warn` mas sem registo de falha — não recomendado em produção. |

O default é `warn`. `block` é recomendado em ambientes de alta criticidade onde a
rastreabilidade externa é um requisito de compliance não negociável.

**Backends suportados:**

| Backend       | Protocolo       | Casos de uso típicos                          |
|---------------|-----------------|-----------------------------------------------|
| `http`        | HTTP POST JSON  | Splunk HEC, Elastic, SIEM genérico            |
| `syslog`      | RFC 5424        | Syslog centralizado, rsyslog, syslog-ng       |
| `cloudwatch`  | AWS SDK         | AWS CloudWatch Logs                           |
| `gcp_logging` | GCP client lib  | Google Cloud Logging                          |

Cada backend é um adapter que implementa a interface `forwarder.Forwarder`:

```go
// pkg/forwarder/forwarder.go

// Forwarder é a interface que todos os backends implementam.
// Send deve ser idempotente — reenvios com o mesmo EventID não duplicam entradas
// em sistemas que suportam deduplicação por ID.
type Forwarder interface {
    Send(entry model.AuditEntry) error
    Name() string
}
```

**Estrutura do evento reencaminhado:**

O payload enviado ao sistema externo é o mesmo `AuditEntry` JSONL com dois campos
adicionais que identificam univocamente a origem:

```json
{
  "ts": "2025-10-14T15:32:00Z",
  "event": "acceptance.created",
  "id": "acc-20251014-001",
  "cve_id": "CVE-2024-1234",
  "actor": "maria.silva@empresa.com",
  "risk": 8.7,
  "expires": "2025-10-28T00:00:00Z",
  "interactive": true,
  "wardex_instance": "prod-pipeline-eu-west-1",
  "wardex_version": "0.3.1"
}
```

- `wardex_instance` identifica a instância de origem (configurável). Permite que
  organizações com múltiplas pipelines correlacionem eventos no sistema externo.
- `wardex_version` permite detectar regressões de comportamento entre versões.

**Verificação pelo auditor:**

Um auditor externo com acesso ao sistema centralizado (Splunk, CloudWatch, etc.) pode
executar uma query simples para obter todos os eventos `acceptance.created` e comparar
com o `wardex-acceptances.yaml` fornecido pela organização:

```
# Exemplo Splunk SPL
index=wardex source=wardex-accept event=acceptance.created
| table ts, id, cve_id, actor, risk, expires
| sort ts

# Exemplo CloudWatch Insights
fields ts, id, cve_id, actor, risk, expires
| filter event = "acceptance.created"
| sort ts asc
```

Qualquer ID presente no log externo mas ausente no YAML local — ou vice-versa — é
evidência de adulteração que não requer a chave HMAC para ser detectada.

**Subcomando de diagnóstico:**

```bash
wardex-accept verify-forwarding [--since 2025-10-01] [--backend splunk]
```

Compara o count de `acceptance.created` no log local com o count no sistema externo
para o período especificado. Útil para preparação de auditorias. Exit `0` se counts
coincidem; `4` se divergem.

---

## 4. Requisitos Não Funcionais

- **Linguagem:** Go 1.22+
- **Zero dependências externas para lógica de negócio** — assinatura HMAC, verificação,
  hashing e expiração em stdlib pura (`crypto/hmac`, `crypto/sha256`, `time`)
- **Dependências externas** apenas para I/O: YAML (`gopkg.in/yaml.v3`), CLI
  (`github.com/spf13/cobra`), terminal colorido (`github.com/charmbracelet/lipgloss`)
- **Portátil:** binário único sem servidor, base de dados ou runtime externo
- **Versionável:** `wardex-acceptances.yaml` e `wardex-accept-audit.log` são ficheiros
  de texto estruturado desenhados para viver no repositório Git
- **Fail-closed:** em caso de dúvida (adulteração, inconsistência, secret inválido), a
  ferramenta bloqueia e não prossegue. Nunca fail-open.
- **Verificação não delegável:** nenhuma operação de leitura ocorre sem verificação de
  integridade prévia — esta pré-condição não é configurável nem desactivável

---

## 5. Arquitetura de Pacotes

```
## 5. Arquitectura de Packages

`pkg/accept/` é um namespace de packages dentro do módulo `github.com/had-nu/wardex`.
Todos os packages aqui listados são importados internamente pelo wardex — não há módulo
separado, não há go.mod próprio, não há ciclo de versioning independente.

```
wardex/pkg/accept/
├── store/
│   ├── store.go           # Load (verify interno) + Append atómico
│   ├── append.go          # Escrita via ficheiro temporário + rename
│   ├── consistency.go     # Verifica YAML count vs audit log count
│   └── store_test.go
│
├── signer/
│   ├── signer.go          # Sign e Verify HMAC-SHA256
│   ├── key.go             # Resolução do secret: env → file → reject literal
│   └── signer_test.go
│
├── verifier/
│   ├── verifier.go        # VerifyAll: assinatura + expiry + report + config hash
│   ├── expiry.go          # CheckExpiry e CheckStale
│   ├── report.go          # CheckReportHash
│   ├── config.go          # CheckConfigHash
│   └── verifier_test.go
│
├── audit/
│   ├── audit.go           # Append-only JSONL log
│   ├── counter.go         # Conta eventos acceptance.created
│   └── audit_test.go
│
├── forwarder/
│   ├── forwarder.go       # Interface Forwarder + dispatcher
│   ├── http.go            # Backend HTTP POST JSON (Splunk HEC, Elastic, SIEM)
│   ├── syslog.go          # Backend RFC 5424
│   ├── cloudwatch.go      # Backend AWS CloudWatch Logs (build tag: cloudwatch)
│   ├── gcp.go             # Backend GCP Logging (build tag: gcp)
│   ├── noop.go            # Backend no-op para testes e dev local
│   └── forwarder_test.go
│
├── notifier/
│   ├── notifier.go        # Dispatcher: webhook + email
│   ├── webhook.go
│   ├── email.go
│   ├── template.go
│   └── notifier_test.go
│
├── configaudit/
│   ├── configaudit.go     # Hash do config + detecção de mudanças
│   ├── diff.go            # Campos alterados entre execuções
│   └── configaudit_test.go
│
├── reporter/
│   ├── reader.go          # Lê e valida GateReport JSON
│   ├── hasher.go          # SHA256 do GateReport e do wardex-config.yaml
│   └── reporter_test.go
│
└── validator/
    ├── validator.go       # Email, justificativa, prazo, secret origin
    ├── banned_phrases.go
    └── validator_test.go
```

Os modelos de dados partilhados (`Acceptance`, `ContextSnapshot`, `RevocationRecord`,
`AuditEntry`) vivem em `pkg/model/acceptance.go` — o mesmo package de modelos usado
pelos outros packages do wardex — garantindo consistência de tipos em todo o módulo.

---

## 6. Modelo de Dados Central

```go
// pkg/model/acceptance.go

// Acceptance representa uma aceitação formal de risco.
// Imutável após criação — qualquer alteração invalida Signature.
type Acceptance struct {
    ID                      string           // "acc-YYYYMMDD-NNN"
    CVEID                   string
    Component               string
    ReleaseRiskAtAcceptance float64
    RiskAppetite            float64
    AcceptedBy              string           // Email obrigatório
    AcceptedAt              time.Time
    ExpiresAt               time.Time
    Justification           string           // Mínimo configurável de caracteres
    TicketRef               string
    Interactive             bool             // false se criado com --yes
    ContextSnapshot         ContextSnapshot  // Preenchido automaticamente, imutável
    Status                  string           // "active" | "expired" | "revoked" | "stale"
    Revocation              *RevocationRecord
    Signature               string           // HMAC-SHA256 de todos os campos excepto Signature
    ReportHash              string           // SHA256 do GateReport de origem
}

// ContextSnapshot regista o estado técnico exacto no momento da aceitação.
// Não pode ser omitido nem editado pelo operador.
type ContextSnapshot struct {
    CVSSBase             float64
    EPSSScore            float64
    AssetCriticality     float64
    ExposureFactor       float64
    ConfigHash           string  // SHA256 do wardex-config.yaml no momento da aceitação
    CompensatingControls []CompensatingControlSnapshot
    BreakdownSummary     string  // Fórmula completa em texto para legibilidade de auditoria
}

type CompensatingControlSnapshot struct {
    Type          string
    Effectiveness float64
}

type RevocationRecord struct {
    RevokedBy string
    RevokedAt time.Time
    Reason    string
}
```

```go
// pkg/model/audit.go

// AuditEntry representa uma linha do audit log JSONL.
// Todos os campos são opcionais excepto Timestamp e Event.
type AuditEntry struct {
    Timestamp   time.Time `json:"ts"`
    Event       string    `json:"event"`
    ID          string    `json:"id,omitempty"`
    CVEID       string    `json:"cve_id,omitempty"`
    Actor       string    `json:"actor,omitempty"`
    Risk        float64   `json:"risk,omitempty"`
    Expires     string    `json:"expires,omitempty"`
    Status      string    `json:"status,omitempty"`
    Interactive bool      `json:"interactive,omitempty"`
    ConfigHash  string    `json:"config_hash,omitempty"`
    PrevHash    string    `json:"prev_hash,omitempty"`
    ChangedFields []string `json:"changed_fields,omitempty"`
    Detail      string    `json:"detail,omitempty"`
}
```

---

## 7. Interface dos Packages Principais

```go
// pkg/signer/signer.go

// Sign gera HMAC-SHA256 do conteúdo serializado da Acceptance.
func Sign(a model.Acceptance, key []byte) (string, error)

// Verify confirma que a assinatura é válida.
var ErrTampered = errors.New("acceptance signature invalid: content may have been tampered")
func Verify(a model.Acceptance, key []byte) error

// pkg/signer/key.go

// ResolveSecret resolve o signing secret pela ordem de precedência:
// 1. WARDEX_ACCEPT_SECRET env var
// 2. Ficheiro referenciado por signing_secret_file no config
// 3. ErrLiteralSecret se o config tem valor literal
var ErrLiteralSecret = errors.New("signing secret must not be a literal value in config; use WARDEX_ACCEPT_SECRET env var or signing_secret_file")
func ResolveSecret(cfg config.Config) ([]byte, error)
```

```go
// pkg/verifier/verifier.go

// Result representa o resultado da verificação de uma Acceptance.
type Result struct {
    Acceptance model.Acceptance
    Valid       bool
    Expired     bool
    Tampered    bool
    Stale       bool    // config mudou desde a aceitação
    ReportMismatch bool // GateReport actual diverge do original
    ExpiresIn  time.Duration
    Errors     []string
}

// VerifyAll verifica todas as aceitações: assinatura, expiry, report hash e config hash.
// É invocado internamente por store.Load — nunca diretamente pelo utilizador.
func VerifyAll(acceptances []model.Acceptance, key []byte,
    currentReportHash string, currentConfigHash string) ([]Result, bool)
```

```go
// pkg/store/store.go

// Load lê wardex-acceptances.yaml.
// Internamente executa, em sequência:
//   1. verifier.VerifyAll — ErrTampered se falhar
//   2. consistency.Check  — ErrStoreInconsistent se YAML < log
// Nenhuma leitura ocorre sem estas pré-condições passarem.
var ErrTampered          = errors.New("tampered acceptance detected")
var ErrStoreInconsistent = errors.New("store inconsistency: yaml entries < audit log events")
func Load(path string, key []byte, auditPath string,
    currentReportHash string, currentConfigHash string) ([]model.Acceptance, error)

// Append adiciona uma Acceptance atomicamente.
// Escreve para ficheiro temporário e renomeia — seguro em falha a meio.
func Append(path string, a model.Acceptance) error

// UpdateStatus actualiza status e RevocationRecord. Regenera assinatura.
func UpdateStatus(path string, id string, status string,
    revocation *model.RevocationRecord, key []byte) error
```

```go
// pkg/configaudit/configaudit.go

// Hash calcula o SHA256 do wardex-config.yaml.
func Hash(configPath string) (string, error)

// Check compara o hash actual com o último registado no audit log.
// Regista config.loaded (sem mudança) ou config.changed (com mudança e campos alterados).
// Notifica se risk_appetite foi alterado.
func Check(configPath string, auditPath string, notifier notifier.Notifier) (changed bool, err error)
```

```go
// pkg/audit/counter.go

// CountCreated conta o número de eventos acceptance.created no audit log.
// Usado por store.Load para verificar consistência com o YAML.
func CountCreated(auditPath string) (int, error)
```

---

## 8. Fluxo de Execução — `wardex-accept request`

```
wardex-accept request --report gate-report.json --cve CVE-2024-1234 ...
         │
         ▼ pkg/signer/key.go
[ResolveSecret — ErrLiteralSecret se secret vier de valor literal]
         │
         ▼ pkg/configaudit
[hash do wardex-config.yaml → regista config.loaded ou config.changed no audit log]
         │
         ▼ pkg/reporter
[valida autenticidade e idade do GateReport]
         │
         ├── adulterado ou expirado → ABORT
         │
         ▼ pkg/validator
[valida email, justificativa mínima, banned phrases, prazo máximo]
         │
         ├── validação falha → ABORT com mensagem específica
         │
         ▼ [apresenta resumo de confirmação com breakdown completo]
         │
         ├── operador recusa (N) → ABORT sem gravação
         │
         ▼ pkg/audit
[regista acceptance.created no audit log ANTES de gravar no YAML]
         │
         ▼ pkg/signer
[Sign — gera HMAC-SHA256 da entrada completa]
         │
         ▼ pkg/store
[Append atómico em wardex-acceptances.yaml]
         │
         ├── falha de escrita → regista acceptance.write_failed no audit log
         │
         ▼ pkg/notifier
[envia notificação acceptance.created]
         │
         ├── falha → notification.failed no audit log, não bloqueia
         │
         ▼
[exit 0]
```

---

## 9. Fluxo de Verificação Interna — `store.Load`

```
store.Load(path, key, auditPath, reportHash, configHash)
         │
         ▼ yaml.Unmarshal
[deserializa entradas]
         │
         ▼ audit.CountCreated(auditPath)
[conta eventos acceptance.created no log]
         │
         ├── len(yaml) < count(log) → ErrStoreInconsistent → exit 4
         │
         ▼ verifier.VerifyAll(acceptances, key, reportHash, configHash)
         │
         ├── Tampered=true em qualquer entrada → ErrTampered → exit 3
         ├── Expired=true → marca como inválida, não fatal
         ├── ReportMismatch=true → marca como inválida, não fatal
         └── Stale=true → marca como stale, emite warning
         │
         ▼
[retorna apenas aceitações válidas e não expiradas]
```

---

## 10. Integração com CI/CD

O pipeline com Wardex Accept não depende de steps externos para garantir integridade —
a verificação é interna. A estrutura mínima correcta é:

```yaml
# Exemplo GitHub Actions

jobs:
  security-gate:
    steps:
      # 1. Scanner de vulnerabilidades
      - name: Scan vulnerabilities
        run: trivy fs . --format json > vuln-scan.json

      # 2. Wardex gate — verifica internamente as aceitações antes de as consumir
      #    exit 0: limpo | exit 2: bloqueado sem aceitação | exit 3: adulteração
      - name: Run Wardex gate
        run: |
          wardex \
            --config wardex-config.yaml \
            --gate vuln-scan.json \
            --output json \
            --out-file gate-report.json \
            controls.yaml

      # 3. Se exit 2, tentar aceitação manual (fora da pipeline automática)
      #    A pipeline falha — o operador deve correr wardex-accept request localmente
      #    e commitar wardex-acceptances.yaml antes do próximo run

      # 4. Verificar expiração iminente (cron separado recomendado)
      - name: Check upcoming expirations
        if: always()
        run: wardex-accept check-expiry --warn-before 3d
        continue-on-error: true   # exit 4 é warning, não bloqueante
```

**Nota sobre `--yes` em pipelines:** o flag `--yes` existe para automações onde a
aprovação aconteceu num sistema externo (ex: aprovação em sistema de ITSM). O
`--accepted-by` continua obrigatório e `interactive: false` é gravado no audit log.
O uso de `--yes` em pipelines automáticas sem aprovação prévia documentada é um
anti-pattern que fica visível em qualquer revisão de auditoria.

**Exit codes:**

| Code | Significado                                                   |
|------|---------------------------------------------------------------|
| 0    | Operação concluída com sucesso                                |
| 1    | Erro de configuração, input inválido, ou secret literal       |
| 2    | CVEs bloqueados sem aceitação válida                          |
| 3    | Adulteração detectada em wardex-acceptances.yaml              |
| 4    | Inconsistência entre YAML e audit log / expiração iminente    |

---

## 11. Arquivo de Configuração

```yaml
# wardex-accept-config.yaml

# Secret de assinatura — NUNCA como valor literal em produção
# Preferido: variável de ambiente WARDEX_ACCEPT_SECRET
# Alternativa: ficheiro externo ao repositório
signing_secret_file: "/run/secrets/wardex-accept-secret"  # ou omitir e usar env var

# Limites de negócio
limits:
  max_acceptance_days: 30
  min_justification_chars: 80
  max_report_age_hours: 24

# Justificativas genéricas rejeitadas (case-insensitive)
banned_justification_phrases:
  - "ok"
  - "approved"
  - "wfm"
  - "looks good"
  - "fine"
  - "yes"
  - "accept"

# Notificações
notifications:
  warn_before_expiry_days: 3
  notify_on_config_change: true   # notifica mudanças de risk_appetite e outros campos críticos

  channels:
    - type: "webhook"
      url: "${WARDEX_SLACK_WEBHOOK}"
      events:
        - "acceptance.created"
        - "acceptance.expiring"
        - "acceptance.expired"
        - "acceptance.stale"
        - "acceptance.revoked"
        - "verification.tampered"
        - "store.inconsistent"
        - "config.changed"
      template_dir: "./templates"

    - type: "email"
      smtp_host: "smtp.empresa.com"
      smtp_port: 587
      from: "wardex-accept@empresa.com"
      to:
        - "security-team@empresa.com"
      events:
        - "verification.tampered"
        - "store.inconsistent"
        - "config.changed"

# Paths
paths:
  acceptances: "wardex-acceptances.yaml"
  audit_log:   "wardex-accept-audit.log"
  gate_report: "gate-report.json"

# Reencaminhamento de audit log para sistema externo (P11)
# Permite auditoria independente sem partilha da chave de assinatura HMAC
log_forwarding:
  enabled: true
  on_failure: "warn"          # "block" | "warn" | "best_effort"
                              # Recomendado "block" em ambientes de alta criticidade
  wardex_instance: "prod-pipeline-eu-west-1"   # Identificador desta instância

  backends:
    - type: "http"
      # Splunk HEC
      url: "${SPLUNK_HEC_URL}"
      headers:
        Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
      timeout_seconds: 5

    # Alternativa: AWS CloudWatch
    # - type: "cloudwatch"
    #   region: "eu-west-1"
    #   log_group: "/wardex/accept/prod"
    #   log_stream: "audit"

    # Alternativa: syslog centralizado
    # - type: "syslog"
    #   address: "syslog.empresa.com:514"
    #   protocol: "tcp"
    #   facility: "local0"
```

---

## 12. Testes

### Unitários obrigatórios

| Ficheiro                | O que testar                                                                                                 |
|-------------------------|--------------------------------------------------------------------------------------------------------------|
| `signer_test.go`        | Sign + Verify round-trip; Verify detecta alteração de qualquer campo individual; chaves diferentes produzem assinaturas diferentes |
| `key_test.go`           | Env var tem precedência sobre ficheiro; valor literal no config retorna ErrLiteralSecret; ausência de qualquer fonte retorna erro |
| `verifier_test.go`      | Expirada → Expired=true; adulterada → Tampered=true; report diverge → ReportMismatch=true; config mudou → Stale=true; válida → Valid=true |
| `store_test.go`         | Append atómico (simula falha a meio); Load invoca verify internamente; ErrTampered propaga de Load; ErrStoreInconsistent quando YAML < log |
| `consistency_test.go`   | count(yaml) == count(log) → ok; count(yaml) < count(log) → ErrStoreInconsistent; log vazio + yaml vazio → ok |
| `configaudit_test.go`   | Hash estável para mesmo ficheiro; config.changed detecta alteração de risk_appetite; config.loaded quando sem mudança |
| `validator_test.go`     | Email inválido rejeitado; justificativa curta rejeitada; prazo máximo excedido rejeitado; banned phrases rejeitadas; phrase parcial não rejeita |
| `reporter_test.go`      | GateReport adulterado detectado; GateReport expirado rejeitado; extracção correcta de CVEs bloqueados        |
| `notifier_test.go`      | Webhook enviado com payload correcto; falha de webhook não propaga erro fatal; template renderizado           |
| `audit_test.go`         | Entradas são append-only; formato JSONL válido; CountCreated conta apenas eventos corretos; timestamps em UTC |
| `forwarder_test.go`     | HTTP backend envia payload correcto com headers; on_failure=block retorna erro quando backend falha; on_failure=warn regista forward.failed e não bloqueia; noop backend não faz I/O; wardex_instance e wardex_version presentes no payload |

### Testes de regressão críticos

```go
// P4 + P7 — Adulteração detectada internamente no Load, não como step externo.
func TestTamperDetectedOnLoad(t *testing.T) {
    dir := t.TempDir()
    key := []byte("test-secret-key-32-bytes-padding!")
    path := filepath.Join(dir, "acceptances.yaml")
    auditPath := filepath.Join(dir, "audit.log")

    a := model.Acceptance{
        ID:            "acc-20251014-001",
        CVEID:         "CVE-2024-1234",
        AcceptedBy:    "maria@empresa.com",
        Justification: "Componente não reachable em produção até patch v2.2 — prazo confirmado",
        ExpiresAt:     time.Now().Add(72 * time.Hour),
        ReleaseRiskAtAcceptance: 8.7,
    }
    sig, _ := signer.Sign(a, key)
    a.Signature = sig

    // Grava entrada legítima
    _ = store.Append(path, a)
    _ = audit.Log(auditPath, model.AuditEntry{Event: "acceptance.created", ID: a.ID})

    // Adultera directamente o ficheiro YAML
    content, _ := os.ReadFile(path)
    tampered := strings.Replace(string(content), "8.7", "2.1", 1)
    _ = os.WriteFile(path, []byte(tampered), 0644)

    // Load deve detectar adulteração e retornar ErrTampered — sem step externo
    _, err := store.Load(path, key, auditPath, "report-hash", "config-hash")
    if !errors.Is(err, store.ErrTampered) {
        t.Errorf("adulteração não detectada em Load: got %v", err)
    }
}

// P10 — Inconsistência entre YAML e log detectada no Load.
func TestStoreInconsistencyDetectedOnLoad(t *testing.T) {
    dir := t.TempDir()
    key := []byte("test-secret-key-32-bytes-padding!")
    path := filepath.Join(dir, "acceptances.yaml")
    auditPath := filepath.Join(dir, "audit.log")

    // Regista 2 eventos no audit log
    _ = audit.Log(auditPath, model.AuditEntry{Event: "acceptance.created", ID: "acc-001"})
    _ = audit.Log(auditPath, model.AuditEntry{Event: "acceptance.created", ID: "acc-002"})

    // Mas YAML tem apenas 1 entrada (simula apagar e recriar)
    a := model.Acceptance{ID: "acc-002", CVEID: "CVE-B", AcceptedBy: "x@y.com",
        ExpiresAt: time.Now().Add(24 * time.Hour)}
    sig, _ := signer.Sign(a, key)
    a.Signature = sig
    _ = store.Append(path, a)

    _, err := store.Load(path, key, auditPath, "", "")
    if !errors.Is(err, store.ErrStoreInconsistent) {
        t.Errorf("inconsistência não detectada: got %v", err)
    }
}

// P9 — Secret literal no config é rejeitado antes de qualquer operação.
func TestLiteralSecretRejected(t *testing.T) {
    cfg := config.Config{SigningSecret: "my-literal-secret"} // sem ${...} ou ficheiro
    _, err := signer.ResolveSecret(cfg)
    if !errors.Is(err, signer.ErrLiteralSecret) {
        t.Errorf("secret literal não rejeitado: got %v", err)
    }
}

// P8 — Mudança de risk_appetite é detectada e registada.
func TestConfigChangeDetected(t *testing.T) {
    dir := t.TempDir()
    auditPath := filepath.Join(dir, "audit.log")
    configPath := filepath.Join(dir, "wardex-config.yaml")

    // Config inicial
    _ = os.WriteFile(configPath, []byte("release_gate:\n  risk_appetite: 6.0\n"), 0644)
    _ = configaudit.Check(configPath, auditPath, nil)

    // Altera risk_appetite
    _ = os.WriteFile(configPath, []byte("release_gate:\n  risk_appetite: 9.5\n"), 0644)
    changed, err := configaudit.Check(configPath, auditPath, nil)

    if err != nil {
        t.Fatal(err)
    }
    if !changed {
        t.Error("mudança de config não detectada")
    }

    // Verifica que o evento está no audit log
    entries := readAuditLog(t, auditPath)
    hasConfigChanged := false
    for _, e := range entries {
        if e.Event == "config.changed" {
            hasConfigChanged = true
            break
        }
    }
    if !hasConfigChanged {
        t.Error("evento config.changed não registado no audit log")
    }
}

// P4 — Qualquer campo alterado invalida a assinatura.
func TestAnyFieldAlterationDetected(t *testing.T) {
    key := []byte("test-secret-key-32-bytes-padding!")
    base := model.Acceptance{
        ID:            "acc-001",
        CVEID:         "CVE-2024-1234",
        AcceptedBy:    "maria@empresa.com",
        Justification: "Justificativa longa o suficiente para passar validação mínima de caracteres",
        ExpiresAt:     time.Now().Add(72 * time.Hour),
        ReleaseRiskAtAcceptance: 8.7,
    }
    sig, _ := signer.Sign(base, key)
    base.Signature = sig

    alterations := []model.Acceptance{
        func() model.Acceptance { a := base; a.AcceptedBy = "outro@empresa.com"; return a }(),
        func() model.Acceptance { a := base; a.ReleaseRiskAtAcceptance = 2.0; return a }(),
        func() model.Acceptance { a := base; a.ExpiresAt = time.Now().Add(9999 * time.Hour); return a }(),
        func() model.Acceptance { a := base; a.Justification = "alterada"; return a }(),
    }

    for i, tampered := range alterations {
        if err := signer.Verify(tampered, key); !errors.Is(err, signer.ErrTampered) {
            t.Errorf("alteração %d não detectada: got %v", i, err)
        }
    }
}
```

---

## 13. Subcomandos CLI

Os subcomandos abaixo são parte do binário `wardex`, sob o namespace `accept`.
Não existe um binário `wardex-accept` separado.

```
wardex accept <command> [flags]

Commands:
  request          Cria uma nova aceitação de risco para CVEs bloqueados
  verify           Verifica integridade de todas as aceitações (revisão manual)
  verify-gate      Verifica se CVEs bloqueados num GateReport têm aceitação válida
  verify-forwarding Compara log local com sistema externo
  list             Lista aceitações com estado actual
  revoke           Revoga uma aceitação activa
  check-expiry     Verifica aceitações a expirar em breve

Flags globais (herdadas do wardex):
  --config   string   Caminho para wardex-config.yaml (default: ./wardex-config.yaml)
  --verbose           Output detalhado no stderr

wardex accept request:
  --report        string   GateReport JSON gerado pelo wardex (obrigatório)
  --cve           string   CVE ID; repetível para múltiplos CVEs
  --accepted-by   string   Email do responsável (obrigatório)
  --justification string   Justificativa substantiva (mínimo configurável)
  --expires       string   Data de expiração: ISO 8601 ou relativa (ex: 30d)
  --ticket        string   Referência externa opcional
  --yes                    Salta confirmação interactiva; interactive=false no audit log

wardex accept list:
  --active               Apenas aceitações activas
  --expired              Apenas aceitações expiradas
  --stale                Apenas aceitações stale (config mudou)
  --cve         string   Filtra por CVE ID
  --output      string   table|json|csv (default: table)

wardex accept revoke:
  --id          string   ID da aceitação (obrigatório)
  --revoked-by  string   Email do responsável (obrigatório)
  --reason      string   Motivo da revogação (obrigatório)

wardex accept check-expiry:
  --warn-before string   Período de aviso: ex. 3d, 72h (default: 3d)

wardex accept verify-forwarding:
  --since   string   Período: ISO 8601 ou relativo (ex: 2025-10-01, 30d)
  --backend string   Backend a verificar (default: todos os configurados)
```

---

## 14. Execução Esperada

O `pkg/accept/` não tem instalação própria. É instalado como parte do wardex:

```bash
go install github.com/had-nu/wardex/cmd/wardex@latest

# Workflow típico após BLOCK do wardex:

# 1. Ver o que foi bloqueado e o estado das aceitações existentes
wardex accept list

# 2. Criar aceitação — verify interno corre antes de qualquer leitura
wardex accept request \
  --report gate-report.json \
  --cve CVE-2024-1234 \
  --accepted-by "maria.silva@empresa.com" \
  --justification "Componente auth-lib não reachable no path de produção até release v2.2 — patch confirmado com infra, deadline 28 Out" \
  --expires 30d \
  --ticket "JIRA-4821"

# 3. Re-correr o wardex — verifica internamente antes de consumir aceitações
wardex --config wardex-config.yaml --gate vuln-scan.yaml controls.yaml

# 4. Verificar expiração iminente (recomendado como cron diário)
wardex accept check-expiry --warn-before 3d

# 5. Revogar quando o patch chegar
wardex accept revoke \
  --id acc-20251014-001 \
  --revoked-by "maria.silva@empresa.com" \
  --reason "Patch v2.2.1 deployado — vulnerabilidade resolvida"

# Revisão manual de integridade (para auditorias)
wardex accept verify

# Comparar log local com sistema externo
wardex accept verify-forwarding --since 30d

# Testes — cobre pkg/accept/ junto com todos os outros packages
go test ./... -race -count=1
go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out
```

---

## 15. Dependências Externas

`pkg/accept/` não tem `go.mod` próprio — as dependências abaixo são parte do
`go.mod` do módulo `github.com/had-nu/wardex` e já estão listadas na spec principal.
Reproduzidas aqui para referência de implementação do package.

| Pacote                              | Utilizado em                          |
|-------------------------------------|---------------------------------------|
| `gopkg.in/yaml.v3`                  | `accept/store`, `accept/reporter`     |
| `github.com/charmbracelet/lipgloss` | subcomandos `wardex accept` (CLI)     |
| `github.com/aws/aws-sdk-go-v2`      | `accept/forwarder/cloudwatch.go` (build tag: `cloudwatch`) |
| `cloud.google.com/go/logging`       | `accept/forwarder/gcp.go` (build tag: `gcp`)               |

Sem dependências externas em `accept/signer`, `accept/verifier`, `accept/store`,
`accept/validator`, `accept/audit`, `accept/configaudit`. HMAC-SHA256 e SHA256
via `crypto/hmac` e `crypto/sha256` da stdlib exclusivamente.

---

## 16. Notas de Implementação

**A verificação é interna e não delegável (P7):** a decisão de design mais importante
desta ferramenta. `store.Load` não existe sem `verifier.VerifyAll` como pré-condição.
Não há flag para desactivar esta verificação. Não há modo de leitura sem verificação.
Qualquer tentativa de contornar o verify implica não usar a ferramenta — e nesse caso
não há aceitações válidas para consumir.

**O audit log regista antes de gravar (P10):** o evento `acceptance.created` é escrito
no audit log antes da entrada ser gravada no YAML. Se a gravação falhar, o log tem
`acceptance.write_failed`. Isso garante que o log nunca tem menos eventos do que o
YAML — a direcção de inconsistência detectável é sempre YAML < log, nunca o contrário.

**Secret literal é recusado no startup (P9):** a validação corre antes de qualquer I/O.
Uma configuração com secret literal nunca chega a ler ficheiros — falha imediatamente
com mensagem clara. Isso previne deployments inseguros por omissão.

**Config hash no context_snapshot (P8):** gravar o hash do config no momento da aceitação
permite ao Wardex detectar se a aceitação foi criada com um `risk_appetite` diferente do
actual. Se alguém cria uma aceitação com `risk_appetite: 6.0`, eleva para `9.5`, e re-corre
o Wardex, as aceitações existentes ficam marcadas como `stale` — o contorno é detectável.

**`stale` não é `invalid` (compromisso deliberado):** aceitações stale emitem warning mas
não bloqueiam. A decisão de bloquear aceitações stale seria mais segura mas criaria falsos
positivos em mudanças de config não relacionadas com `risk_appetite`. O compromisso é:
stale é visível, notificado, e requer re-confirmação explícita — mas não pára o pipeline
automaticamente. Esta decisão deve ser documentada na política de segurança da organização.

**O audit log é o único estado irrecuperável:** o YAML pode ser recriado (com detecção).
O audit log não pode ser recriado sem detecção — é a única fonte de verdade que não tem
equivalente recuperável. Deve ser tratado como artefacto de compliance de primeira classe:
preservado, imutável, idealmente centralizado em sistema de log management externo.

**Reencaminhamento externo como âncora de auditoria independente (P11):** a verificação
HMAC local resolve o problema de adulteração interna — qualquer edição ao YAML é detectada
pela ferramenta. Mas cria um problema de auditoria externa: a chave pertence à organização
auditada, que poderia em teoria forjar assinaturas. O reencaminhamento para sistema externo
resolve este problema sem partilhar a chave. O auditor compara o log local com o sistema
externo — que a organização não controla no contexto da auditoria — e qualquer divergência
é prova de adulteração. As duas camadas são complementares: HMAC para detecção imediata
e automática; sistema externo para verificação independente por terceiros.

**`on_failure: block` vs `warn` — uma decisão de política, não técnica:** a escolha entre
bloquear ou avisar quando o reencaminhamento falha é uma decisão que a organização deve
tomar conscientemente e documentar na sua política de segurança. `block` é mais seguro mas
introduz uma dependência de disponibilidade do sistema externo no caminho crítico de
aceitação de risco. `warn` mantém a operação local mas reduz a força da garantia de
auditabilidade externa. Nenhum dos valores é o correcto por defeito para todas as
organizações — o default `warn` é conservador para adopção, mas organizações com
requisitos de compliance rigorosos devem migrar para `block`.

**Contribuição futura — assinatura com chave pública (Opção B):** a alternativa
arquitecturalmente mais correcta para auditabilidade independente seria substituir
HMAC-SHA256 por ECDSA — a organização assina com chave privada, o auditor verifica com
chave pública sem necessitar da chave de assinatura. Esta abordagem elimina completamente
a dependência de um sistema externo para verificação independente. Está identificada como
contribuição futura da comunidade: a interface `signer.Signer` foi desenhada para suportar
esta substituição sem alterações ao `store`, `verifier` ou `audit`. Um contribuidor que
implemente `pkg/signer/ecdsa.go` satisfazendo a interface existente terá a feature
funcional sem tocar no resto da codebase.

---

## 17. Instruções de Actualização da Documentação

Esta secção descreve o que deve ser adicionado ao ficheiro de documentação existente
do projecto para cobrir a feature de reencaminhamento externo (RF-15 / P11). As
instruções são deliberadamente detalhadas para que a documentação reflicta não só o
*como* mas o *porquê* — a motivação técnica e o impacto no negócio são tão importantes
quanto as instruções de configuração.

---

### 17.1 — Nova secção: "Independent Audit Verification"

Adicionar após a secção existente sobre o audit log local. O tom deve ser o de explicar
a um auditor externo o que pode verificar e como, sem assumir conhecimento da codebase.

**O que escrever:**

Começar por explicar o problema que a feature resolve: a verificação HMAC local é
eficaz para detectar adulteração automática em pipeline, mas depende de uma chave que
pertence à organização. Um auditor externo que receba o ficheiro
`wardex-acceptances.yaml` e o `wardex-accept-audit.log` não consegue validar as
assinaturas de forma independente — precisaria da chave, criando um conflito de
interesse inerente a qualquer auditoria.

Explicar que o reencaminhamento para sistema externo resolve este conflito: cada evento
é enviado para um sistema que a organização não controla no contexto da auditoria
(Splunk gerido por terceiros, CloudWatch com acesso controlado por IAM independente,
etc.). O auditor acede directamente ao sistema externo e compara com os ficheiros
locais fornecidos pela organização.

Documentar o procedimento de verificação do auditor em três passos:

**Passo 1 — Obter o count de eventos do sistema externo.** Fornecer a query exacta
para cada backend suportado (SPL para Splunk, Insights para CloudWatch, etc.) filtrada
por `event = "acceptance.created"` e pelo período de auditoria. O resultado é o número
de aceitações que deveriam existir.

**Passo 2 — Comparar com o ficheiro local.** Contar as entradas em
`wardex-acceptances.yaml` (linhas com `- id:`) e em `wardex-accept-audit.log` (linhas
com `"acceptance.created"`). Os três números devem coincidir. Qualquer discrepância é
evidência de adulteração — especificar as direcções possíveis e o que cada uma implica:

- `externo > local`: entradas foram apagadas do ficheiro local após criação.
- `local > externo`: entradas foram criadas sem reencaminhamento, ou o reencaminhamento
  foi desactivado temporariamente — verificar eventos `forward.failed` no log local.
- `yaml < log`: entradas foram apagadas do YAML mas o log local permanece — a
  ferramenta detecta isto automaticamente como `ErrStoreInconsistent`.

**Passo 3 — Verificar campos críticos.** Para uma amostra de aceitações, comparar os
campos `cve_id`, `actor`, `risk`, `expires` entre o sistema externo e o YAML local.
Divergência em qualquer campo é evidência de adulteração do YAML após reencaminhamento.

Terminar com uma nota sobre o `wardex-accept verify-forwarding` — que automatiza este
processo para períodos configuráveis e pode ser usado pela própria organização como
preparação para auditorias.

---

### 17.2 — Actualização da secção "Security Model"

Se a documentação tiver uma secção sobre o modelo de segurança da ferramenta, adicionar
um parágrafo que explique as duas camadas de protecção e o que cada uma mitiga:

**Camada 1 — HMAC local:** mitiga adulteração não detectada em pipeline. Qualquer
processo ou pessoa que edite `wardex-acceptances.yaml` directamente vê o pipeline falhar
com `exit 3` na próxima execução. Mitiga o risco de contorno silencioso por actores
internos com acesso ao sistema de CI/CD.

**Camada 2 — Sistema externo:** mitiga o risco de que a organização auditada manipule
os registos antes de uma auditoria externa. Também mitiga perda acidental ou deliberada
do log local — os eventos existem independentemente no sistema externo. Para organizações
sujeitas a regulação (PCI-DSS, ISO 27001, SOC 2), esta camada é o que transforma o
Wardex Accept de ferramenta operacional em evidência de auditoria credível.

Documentar explicitamente o que a ferramenta **não** mitiga: um actor com acesso
simultâneo ao sistema de CI/CD e ao sistema de log externo (ex: administrador de
plataforma com permissões totais em ambos) poderia em teoria eliminar evidências em
ambos os sistemas. Esta é a ameaça residual que a Opção B (assinatura ECDSA com chave
pública) endereçaria no futuro — e que por agora requer controlos organizacionais
(separação de funções, acesso auditado ao sistema de log externo).

---

### 17.3 — Actualização da secção "Configuration Reference"

Na documentação da configuração, a secção `log_forwarding` deve incluir:

Para cada campo, documentar não só o que faz mas a implicação de segurança da escolha.
Em particular:

`on_failure: block` — documentar que esta opção introduz uma dependência de
disponibilidade do sistema externo no caminho crítico. Se o sistema externo estiver
indisponível, nenhuma aceitação pode ser criada. Para organizações com requisitos de
continuidade de negócio, avaliar se esta dependência é aceitável ou se `warn` com
alertas de `forward.failed` é o compromisso correcto.

`wardex_instance` — documentar que este campo é o que permite correlacionar eventos
de múltiplas pipelines no sistema externo. Organizações com mais de uma pipeline de
produção devem usar valores distintos e manter um registo dos valores em uso — um
valor incorrecto impossibilita a correlação correcta durante auditoria.

Incluir as queries de verificação para cada backend suportado, referenciando o
procedimento descrito em 17.1. A documentação deve ser suficiente para que um auditor
sem acesso à equipa técnica consiga executar a verificação de forma autónoma.

---

### 17.4 — Nota sobre a Opção B como contribuição da comunidade

Adicionar uma secção curta "Roadmap / Future Work" ou equivalente no ficheiro de
documentação (README ou CONTRIBUTING) com o seguinte conteúdo:

Descrever que a abordagem actual de reencaminhamento externo resolve o problema de
auditabilidade independente mas introduz uma dependência operacional. A solução
arquitecturalmente superior — assinatura com chave pública ECDSA — eliminaria esta
dependência: qualquer auditor com a chave pública poderia verificar qualquer assinatura
sem acesso ao sistema externo e sem a chave privada.

Especificar o que um contribuidor precisa de implementar: `pkg/signer/ecdsa.go`
satisfazendo a interface `signer.Signer` existente. Não são necessárias alterações ao
`store`, `verifier`, `audit` ou a qualquer outro package — a interface foi desenhada
para suportar esta extensão. Incluir um link para a interface no código e para a issue
de tracking no repositório.
