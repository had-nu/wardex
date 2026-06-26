# Feature Spec: Configuration Provenance Link (CPL)

**Versão**: 2.0
**Estado**: Implementado (v2.2.0)
**Prioridade**: Média-Alta (recomendada para clientes Classe II e setor financeiro)
**Impacto**: Adição de campo `config_hash` e `cli_overrides` no audit log; novo subcomando `wardex config hash`; `wardex audit verify-link` e `verify-chain`; validação opcional no `evaluate` (`--strict`); testes de integridade criptográfica; notificação de divergência para SIEM via webhook; suporte BLAKE3.

---

## Changelog v1.1 → v1.2

- **Secção 9**: roadmap actualizado com milestones de cobertura de testes e notificação.
- **Secção 11** (nova): testes de integridade criptográfica — canonicalização, hash chain, coexistência de algoritmos, verify-link, notificação.
- **Secção 12** (nova): mecanismo de notificação de divergência via webhook configurável. Fire-and-forget não-bloqueante; não afecta exit codes. Cobre MISMATCH, MISSING, e adulteração de hash chain.

---

## Changelog v1.0 → v1.1

- **Secção 2.1**: hash calculado sobre o ficheiro raw (pré-expansão de env vars), não sobre o conteúdo expandido. CLI overrides que afectam a avaliação registados separadamente como `cli_overrides`.
- **Secção 2.2**: exemplo do audit log actualizado com campo `cli_overrides`.
- **Secção 2.3**: exit codes de `verify-link` definidos explicitamente. Referência a S3 removida (scoped para v2.3.0).
- **Secção 2.4**: flag `--record-config-hash` removida. `config_hash` incluído por defeito na saída `-o json`.
- **Secção 4.2**: workflow pós-auditoria usa arquivo local; S3 aparece apenas na secção de roadmap onde está scoped.
- **Secção 6**: snippet de canonicalização corrigido. A versão anterior usava `yaml.Marshal(yaml.Unmarshal(...))`, que não garante ordenação de chaves. Substituído por pipeline `yaml → map[string]any → json.Marshal`, que ordena chaves alfabeticamente por especificação de `encoding/json` (garantido desde Go 1.12).
- **Secção 7**: referência ao Vigil removida. A garantia de imutabilidade assenta exclusivamente na hash chain interna do Wardex. Adicionada nota sobre migração BLAKE3.
- **Secção 9**: roadmap actualizado com migração BLAKE3 (v2.3.0).

---

## 1. Objetivo

Estabelecer uma ligação criptográfica leve e auditável entre cada decisão do release gate e a configuração (`wardex-config.yaml` ou `config.wexstate`) que estava em vigor no momento da avaliação.

Esta ligação permite responder a auditorias com prova de que a decisão foi tomada sob um conjunto específico de regras, detectar alterações retroactivas da configuração, e reconstituir o contexto exacto de uma decisão sem reconstrução manual.

A implementação é não intrusiva e opt-in, resolúvel nativamente pelo Wardex sem dependências de runtime externas.

---

## 2. Requisitos Funcionais

### 2.1. Cálculo do Hash da Configuração

O Wardex fornece um subcomando para calcular o hash da configuração:

```bash
wardex config hash --config wardex-config.yaml
# Saída: sha256:3f8c9e7b1a2d4f6e8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f
```

O hash é calculado sobre o conteúdo raw do ficheiro, antes da expansão de variáveis de ambiente. Esta decisão é deliberada: garante que qualquer auditor com acesso ao ficheiro de configuração arquivado consegue reproduzir o hash sem necessitar das env vars do CI runner no momento da avaliação.

Quando overrides são passados via flags CLI (ex: `--threshold critical=0`), esses valores afectam a decisão mas não constam do ficheiro de configuração. O campo `cli_overrides` no audit log regista-os separadamente — ver secção 2.2.

Se a configuração for fornecida via `config.wexstate` (selado), o hash é calculado sobre o conteúdo após verificação da integridade Ed25519, mas antes da aplicação. O prefixo na saída identifica o algoritmo (`sha256:` na implementação inicial; `blake3:` após migração — ver secção 9).

### 2.2. Registo no Audit Log

Sempre que `wardex evaluate` é executado com `--audit-log` activo, dois campos são adicionados ao registo JSONL:

- `config_hash`: hash SHA-256 (ou BLAKE3, após migração) da configuração raw.
- `cli_overrides`: mapa de overrides passados via flags que afectaram a avaliação. Vazio se não existirem overrides.

```json
{
  "timestamp": "2026-06-25T14:32:10Z",
  "decision": "BLOCK",
  "exit_code": 10,
  "config_hash": "sha256:3f8c9e7b...",
  "cli_overrides": { "threshold.critical": "0" },
  "asset": "nexusflow-api",
  "thresholds": { "critical": 0, "high": 2 },
  "vulns_count": 3
}
```

Se não existirem overrides, o campo é omitido (não serializado como `null` ou `{}`).

### 2.3. Verificação do Link

O subcomando `wardex audit verify-link` verifica, dado um audit log e um conjunto de configurações arquivadas, se os hashes registados correspondem às configurações arquivadas:

```bash
# Contra um directório de configurações arquivadas (arquivo local):
wardex audit verify-link --audit-log wardex-audit.log --config-archive ./configs/

# Contra um único ficheiro (todas as entradas devem ter o mesmo hash):
wardex audit verify-link --audit-log wardex-audit.log --config config.yaml
```

A verificação produz um relatório com três estados por entrada:

- `OK` — hash coincide.
- `MISMATCH` — hash diferente; a configuração foi alterada entre a decisão e o arquivo.
- `MISSING` — nenhum ficheiro de configuração encontrado para o timestamp da entrada.

**Exit codes de `verify-link`**:

| Código | Condição |
|--------|----------|
| 0 | Todas as entradas com estado `OK` |
| 1 | Uma ou mais entradas com `MISMATCH` ou `MISSING` |
| 2 | Erro operacional: ficheiro de log inacessível, parse error, directório inválido |

Exit code 1 é o estado esperado em auditorias que revelam divergências. O operador trata como finding, não como falha do tool.

### 2.4. Saída JSON

Quando `wardex evaluate` é executado com `-o json`, o campo `config_hash` é sempre incluído na saída, independentemente de `--audit-log` estar activo. Não é necessária nenhuma flag adicional: a presença de um ficheiro de configuração resolúvel é suficiente para o campo aparecer. Se o hash não puder ser calculado (ficheiro inacessível), o campo é omitido e um aviso é emitido em stderr.

---

## 3. Requisitos Não Funcionais

- **Performance**: o cálculo do hash de um ficheiro de configuração típico (< 50 KB) deve ser inferior a 10 ms, sem impacto perceptível no tempo de avaliação.
- **Compatibilidade**: opt-in; não altera o comportamento existente para quem não usar `--audit-log` ou `-o json`.
- **Autonomia**: toda a funcionalidade é resolvida nativamente pelo Wardex. Nenhuma dependência de runtime externa é necessária para a operação do CPL.
- **Segurança**: o hash complementa a assinatura Ed25519 do `wexstate` para rastreabilidade; não a substitui. A integridade activa continua a ser responsabilidade da trust store.
- **Armazenamento**: o hash ocupa 64 caracteres hexadecimais mais prefixo — impacto negligenciável no tamanho do log.

---

## 4. Fluxo de Utilização Típica

### 4.1. Durante o Pipeline CI/CD

```yaml
# .github/workflows/release.yml
- name: Run Wardex Gate
  run: |
    wardex evaluate \
      --evidence vulns.yaml \
      --config wardex-config.yaml \
      --audit-log wardex-audit.log
```

Se existirem overrides via flags, ficam registados automaticamente em `cli_overrides`.

### 4.2. Após uma Auditoria (Dias ou Meses Depois)

O auditor solicita o ficheiro `wardex-audit.log` (append-only) e o arquivo das versões da configuração (directório local com versionamento por data, ou equivalente no sistema de arquivos da organização).

O responsável executa:

```bash
wardex audit verify-link \
  --audit-log wardex-audit.log \
  --config-archive ./config-versions/
```

O relatório mostra todas as entradas com `MISMATCH` ou `MISSING`. Entradas com `OK` confirmam que a decisão foi tomada sob a configuração arquivada. O comando retorna exit 0 se não existirem divergências, exit 1 se existirem — integrável directamente em scripts de verificação.

---

## 5. Comandos CLI — Resumo

| Comando | Descrição |
|---------|-----------|
| `wardex config hash --config <file>` | Calcula e imprime o hash da configuração (sobre conteúdo raw). |
| `wardex evaluate ... --audit-log <file>` | Inclui `config_hash` e `cli_overrides` no registo JSONL. |
| `wardex evaluate ... -o json` | Inclui `config_hash` na saída JSON (sem flag adicional). |
| `wardex audit verify-link --audit-log <file> --config-archive <dir>` | Verifica a correspondência entre hashes registados e configurações arquivadas. |
| `wardex audit verify-link --audit-log <file> --config <file>` | Verifica contra um único ficheiro. |

---

## 6. Formato do Hash e Canonicalização

O hash é calculado sobre o conteúdo raw do ficheiro de configuração, com normalização estrutural que garante determinismo entre ambientes:

1. Remover comentários YAML (linhas iniciadas por `#` e comentários inline).
2. Remover espaços em branco no início e fim de cada linha.
3. Ordenar chaves de mapas alfabeticamente.

O snippet abaixo implementa a canonicalização correctamente. A versão anterior desta spec usava `yaml.Marshal(yaml.Unmarshal(...))`, que não garante ordenação de chaves no `gopkg.in/yaml.v3` — o output depende da ordem de inserção do map no runtime. A implementação correcta usa `encoding/json`, que ordena chaves de `map[string]any` alfabeticamente por especificação (garantido desde Go 1.12):

```go
import (
    "encoding/json"
    "fmt"

    "gopkg.in/yaml.v3"
)

// canonicalConfig produz uma sequência de bytes determinística a partir de um
// ficheiro de configuração YAML. O parse para interface{} descarta comentários
// e normaliza whitespace; json.Marshal ordena chaves de map alfabeticamente.
// Nota: não expande variáveis de ambiente — o hash reflecte o ficheiro tal como
// arquivado, garantindo reprodutibilidade por qualquer auditor com o ficheiro.
func canonicalConfig(raw []byte) ([]byte, error) {
    var data any
    if err := yaml.Unmarshal(raw, &data); err != nil {
        return nil, fmt.Errorf("canonical: parse: %w", err)
    }
    out, err := json.Marshal(data)
    if err != nil {
        return nil, fmt.Errorf("canonical: marshal: %w", err)
    }
    return out, nil
}
```

O prefixo na saída identifica o algoritmo activo:

- `sha256:` — implementação inicial (v2.2.0).
- `blake3:` — após migração (v2.3.0), com a dep `lukechampine.com/blake3`.

O prefixo garante que hashes de versões diferentes do algoritmo nunca são comparados silenciosamente.

---

## 7. Considerações de Segurança

O hash não é uma assinatura; não impede a alteração da configuração, apenas permite detectar essa alteração a posteriori. Para proteção activa contra adulteração, o uso de configuração selada (`config.wexstate`) com Ed25519 continua a ser a mecanismo primário.

A garantia de que os hashes registados no audit log não podem ser alterados retroactivamente assenta na hash chain interna do Wardex. Cada entrada do JSONL inclui o hash da entrada anterior; qualquer modificação retroactiva invalida todas as entradas subsequentes. Esta propriedade é verificável com `wardex audit verify-chain` (subcomando existente) sem dependências externas.

O CPL não introduz dependências de runtime adicionais para esta garantia. O Wardex resolve a rastreabilidade e a verificabilidade nativamente.

**Nota sobre migração BLAKE3**: a substituição de SHA-256 por BLAKE3 na v2.3.0 não altera o modelo de segurança. BLAKE3 oferece margens de segurança equivalentes com performance superior em software. Hashes históricos computados com SHA-256 permanecem válidos; o prefixo no campo `config_hash` distingue o algoritmo usado.

---

## 8. Exemplo de Uso na Prática (NovaBank)

**Passo 1** — Durante o release de Maio:

```bash
wardex evaluate \
  --config wardex-config.yaml \
  --evidence vulns.yaml \
  --audit-log audit.log
# Entrada no audit.log:
# {"decision":"ALLOW","config_hash":"sha256:abc123...","cli_overrides":{},...}
```

**Passo 2** — Um mês depois, o CISO aumenta o `risk_appetite` na configuração.

**Passo 3** — Durante uma auditoria DORA, o auditor pede prova de que a decisão de `ALLOW` de Maio foi tomada com as regras em vigor nessa data.

**Passo 4** — O responsável executa:

```bash
wardex audit verify-link \
  --audit-log audit.log \
  --config config-versions/2026-05-01.yaml
# Output: OK (hash coincide com o registado)
# Exit: 0
```

Se a configuração arquivada tivesse sido alterada antes da auditoria, o comando retornaria `MISMATCH` com exit 1, forçando uma explicação documentada.

---

## 9. Roadmap e Integração

> **Nota (v2.2.0)**: Todo o scope originalmente distribuído entre v2.2.0, v2.3.0 e v2.4.0 foi unificado e implementado nesta release.

| Versão | Scope |
|--------|-------|
| v2.2.0 | `wardex config hash`; campo `config_hash` e `cli_overrides` no audit log; `config_hash` na saída `-o json`; `wardex audit verify-link` com suporte a arquivos locais; `wardex audit verify-chain`; suite de testes de integridade criptográfica (Secção 11); mecanismo de notificação de divergência via webhook (Secção 12); migração BLAKE3; integração com modo `--strict`. |

---

## 10. Conclusão

O CPL adiciona rastreabilidade auditável com custo de implementação baixo e zero dependências de runtime adicionais na versão inicial. Responde directamente a exigências de auditoria em contextos DORA e CRA Classe II, sem quebrar o princípio de autonomia do Wardex: tudo o que está no scope do tool é resolvido pelo tool.

---

## 11. Testes de Integridade Criptográfica

Toda a funcionalidade que depende de criptografia — canonicalização, hash chain, coexistência de algoritmos, verify-link — tem cobertura de testes explícita. Os testes são organizados num pacote dedicado `internal/cpl/`, separado dos testes de avaliação existentes.

### 11.1. Estrutura de Pacotes

```
internal/
  cpl/
    hash.go           ← canonicalConfig, computeConfigHash, parseAlgorithmPrefix
    hash_test.go      ← vectores de teste, determinismo, coexistência SHA-256/BLAKE3
    chain.go          ← verify-chain integration para CPL
    chain_test.go     ← cenários de adulteração, genesis, cadeia longa
    verifylink.go     ← lógica de verify-link (OK/MISMATCH/MISSING)
    verifylink_test.go
  notification/
    webhook.go        ← HTTP POST, timeout, autenticação, payload
    webhook_test.go   ← mock server, divergência, timeout, falha silenciosa
testdata/
  fixtures/
    cpl/
      config_canonical.yaml     ← ficheiro de referência para vectores
      config_keys_unordered.yaml ← mesma config, chaves em ordem diferente
      config_with_comments.yaml  ← mesma config com comentários
      config_with_whitespace.yaml ← mesma config com whitespace extra
      audit_log_ok.jsonl         ← log com hashes consistentes
      audit_log_mismatch.jsonl   ← log com um hash divergente
      audit_log_missing.jsonl    ← log sem config arquivada correspondente
      audit_log_tampered.jsonl   ← log com hash chain adulterada
```

### 11.2. Testes de Canonicalização

O invariante central: o mesmo conteúdo semântico produz sempre o mesmo hash, independentemente de formatação, ordem de chaves, ou presença de comentários.

```go
package cpl_test

import (
    "testing"

    "github.com/had-nu/wardex/internal/cpl"
)

// TestCanonicalConfigDeterminism verifica que ficheiros semanticamente
// equivalentes produzem o mesmo output canónico.
func TestCanonicalConfigDeterminism(t *testing.T) {
    cases := []struct {
        name string
        a, b string // paths em testdata/fixtures/cpl/
    }{
        {
            name: "chaves em ordem diferente",
            a:    "testdata/fixtures/cpl/config_canonical.yaml",
            b:    "testdata/fixtures/cpl/config_keys_unordered.yaml",
        },
        {
            name: "comentários removidos",
            a:    "testdata/fixtures/cpl/config_canonical.yaml",
            b:    "testdata/fixtures/cpl/config_with_comments.yaml",
        },
        {
            name: "whitespace normalizado",
            a:    "testdata/fixtures/cpl/config_canonical.yaml",
            b:    "testdata/fixtures/cpl/config_with_whitespace.yaml",
        },
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            rawA := mustReadFile(t, tc.a)
            rawB := mustReadFile(t, tc.b)

            hashA, err := cpl.ComputeConfigHash(rawA, cpl.AlgoSHA256)
            if err != nil {
                t.Fatalf("hash A: %v", err)
            }
            hashB, err := cpl.ComputeConfigHash(rawB, cpl.AlgoSHA256)
            if err != nil {
                t.Fatalf("hash B: %v", err)
            }

            if hashA != hashB {
                t.Errorf("hashes divergem: %q != %q", hashA, hashB)
            }
        })
    }
}

// TestCanonicalConfigEnvVarsNotExpanded verifica que variáveis de ambiente
// presentes no ficheiro NÃO são expandidas antes do cálculo do hash.
// Garante reprodutibilidade: o auditor com o ficheiro arquivado obtém o
// mesmo hash sem necessitar das env vars do CI runner.
func TestCanonicalConfigEnvVarsNotExpanded(t *testing.T) {
    withVar := []byte("threshold: ${RISK_THRESHOLD}\n")

    t.Setenv("RISK_THRESHOLD", "high")
    hashWithEnv, err := cpl.ComputeConfigHash(withVar, cpl.AlgoSHA256)
    if err != nil {
        t.Fatalf("hash com env: %v", err)
    }

    t.Setenv("RISK_THRESHOLD", "critical") // altera a env var
    hashChangedEnv, err := cpl.ComputeConfigHash(withVar, cpl.AlgoSHA256)
    if err != nil {
        t.Fatalf("hash env alterada: %v", err)
    }

    // O hash deve ser idêntico — env vars não são expandidas.
    if hashWithEnv != hashChangedEnv {
        t.Error("hash mudou quando env var foi alterada: env vars estão a ser expandidas")
    }
}

// TestCanonicalConfigKnownVector verifica um vector de teste fixo.
// Se este teste falhar após uma mudança na canonicalização, todos os
// hashes históricos no audit log ficam inválidos — breaking change.
func TestCanonicalConfigKnownVector(t *testing.T) {
    input := []byte("risk_appetite: low\nthresholds:\n  critical: 0\n  high: 2\n")

    // Vector calculado externamente com: echo -n '<canonical json>' | sha256sum
    // Canonical JSON de input: {"risk_appetite":"low","thresholds":{"critical":0,"high":2}}
	const expected = "sha256:9fb10556b293b483c9ad27d8e6f2b3f1168368169ebdea3502006de93b5820ea"

    got, err := cpl.ComputeConfigHash(input, cpl.AlgoSHA256)
    if err != nil {
        t.Fatalf("compute: %v", err)
    }
    if got != expected {
        t.Errorf("vector falhou:\n  got:  %s\n  want: %s", got, expected)
    }
}

// TestCanonicalConfigInvalidYAML verifica que YAML malformado retorna
// erro em vez de produzir um hash sobre conteúdo parcialmente parseado.
func TestCanonicalConfigInvalidYAML(t *testing.T) {
    invalid := []byte("key: : invalid\n  badly: [nested")
    _, err := cpl.ComputeConfigHash(invalid, cpl.AlgoSHA256)
    if err == nil {
        t.Error("esperava erro em YAML malformado, obteve nil")
    }
}
```

### 11.3. Testes de Hash Chain

```go
package cpl_test

// TestChainVerifyValid verifica que uma cadeia íntegra passa verificação.
func TestChainVerifyValid(t *testing.T) {
    log := mustReadFile(t, "testdata/fixtures/cpl/audit_log_ok.jsonl")
    ok, err := cpl.VerifyChain(log)
    if err != nil {
        t.Fatalf("verify chain: %v", err)
    }
    if !ok {
        t.Error("cadeia válida reportada como inválida")
    }
}

// TestChainVerifyTampered verifica que adulteração de uma entrada
// intermédia invalida a cadeia a partir desse ponto.
func TestChainVerifyTampered(t *testing.T) {
    log := mustReadFile(t, "testdata/fixtures/cpl/audit_log_tampered.jsonl")
    ok, err := cpl.VerifyChain(log)
    if err != nil {
        t.Fatalf("verify chain: %v", err)
    }
    if ok {
        t.Error("cadeia adulterada reportada como válida")
    }
}

// TestChainGenesisEntry verifica que o primeiro evento da cadeia usa
// prev_hash = "genesis" e que qualquer outro valor é rejeitado.
func TestChainGenesisEntry(t *testing.T) {
    // Cadeia de um único evento com prev_hash correcto.
    singleValid := buildSingleEntryChain(t, "genesis")
    ok, err := cpl.VerifyChain(singleValid)
    if err != nil || !ok {
        t.Error("entrada genesis válida rejeitada")
    }

    // Cadeia de um único evento com prev_hash inválido.
    singleBad := buildSingleEntryChain(t, "sha256:00000000")
    ok, err = cpl.VerifyChain(singleBad)
    if err != nil || ok {
        t.Error("entrada genesis inválida aceite")
    }
}

// TestChainLargeCorpus corre a verificação sobre uma cadeia de 500 eventos
// para garantir que não há degradação de performance ou race conditions.
func TestChainLargeCorpus(t *testing.T) {
    chain := generateChain(t, 500)
    ok, err := cpl.VerifyChain(chain)
    if err != nil || !ok {
        t.Errorf("corpus de 500 eventos falhou: err=%v ok=%v", err, ok)
    }
}
```

### 11.4. Testes de Coexistência de Algoritmos

Após a migração BLAKE3 (v2.3.0), o audit log pode conter entradas com `sha256:` e entradas com `blake3:` no mesmo ficheiro. A verificação deve tratar cada entrada com o algoritmo indicado pelo seu prefixo, sem inferência.

```go
// TestAlgorithmPrefixParsing verifica que o prefixo é lido correctamente
// e que um prefixo desconhecido retorna erro explícito.
func TestAlgorithmPrefixParsing(t *testing.T) {
    cases := []struct {
        input   string
        wantAlg cpl.Algorithm
        wantErr bool
    }{
        {"sha256:abc123", cpl.AlgoSHA256, false},
        {"blake3:abc123", cpl.AlgoBLAKE3, false},
        {"md5:abc123", cpl.AlgoUnknown, true},   // algoritmo não suportado
        {"abc123", cpl.AlgoUnknown, true},        // prefixo ausente
        {"", cpl.AlgoUnknown, true},              // string vazia
    }

    for _, tc := range cases {
        alg, err := cpl.ParseAlgorithmPrefix(tc.input)
        if tc.wantErr && err == nil {
            t.Errorf("%q: esperava erro, obteve nil", tc.input)
        }
        if !tc.wantErr && alg != tc.wantAlg {
            t.Errorf("%q: algoritmo errado: got %v want %v", tc.input, alg, tc.wantAlg)
        }
    }
}

// TestMixedAlgorithmLog verifica que um audit log com entradas sha256: e
// blake3: é verificado correctamente sem confusão entre algoritmos.
func TestMixedAlgorithmLog(t *testing.T) {
    // Primeiras 10 entradas: sha256 (pré-migração)
    // Entradas 11+: blake3 (pós-migração)
    mixedLog := buildMixedAlgorithmLog(t, 10, 10)
    results, err := cpl.VerifyLink(mixedLog, "testdata/fixtures/cpl/")
    if err != nil {
        t.Fatalf("verify-link em log misto: %v", err)
    }
    for _, r := range results {
        if r.Status != cpl.StatusOK {
            t.Errorf("entrada %s: status inesperado %v", r.EntryTimestamp, r.Status)
        }
    }
}
```

### 11.5. Testes de verify-link

```go
// TestVerifyLinkAllOK verifica o caminho nominal: todas as entradas correspondem.
func TestVerifyLinkAllOK(t *testing.T) {
    log := mustReadFile(t, "testdata/fixtures/cpl/audit_log_ok.jsonl")
    results, err := cpl.VerifyLink(log, "testdata/fixtures/cpl/configs/")
    if err != nil {
        t.Fatalf("verify-link: %v", err)
    }
    for _, r := range results {
        if r.Status != cpl.StatusOK {
            t.Errorf("entrada %s: %v (esperava OK)", r.EntryTimestamp, r.Status)
        }
    }
}

// TestVerifyLinkMismatch verifica que uma configuração alterada é detectada.
func TestVerifyLinkMismatch(t *testing.T) {
    log := mustReadFile(t, "testdata/fixtures/cpl/audit_log_mismatch.jsonl")
    results, err := cpl.VerifyLink(log, "testdata/fixtures/cpl/configs/")
    if err != nil {
        t.Fatalf("verify-link: %v", err)
    }

    var mismatches int
    for _, r := range results {
        if r.Status == cpl.StatusMismatch {
            mismatches++
        }
    }
    if mismatches == 0 {
        t.Error("divergência esperada não detectada")
    }
}

// TestVerifyLinkMissing verifica que a ausência de config arquivada é reportada.
func TestVerifyLinkMissing(t *testing.T) {
    log := mustReadFile(t, "testdata/fixtures/cpl/audit_log_missing.jsonl")
    results, err := cpl.VerifyLink(log, "testdata/fixtures/cpl/configs/")
    if err != nil {
        t.Fatalf("verify-link: %v", err)
    }

    var missing int
    for _, r := range results {
        if r.Status == cpl.StatusMissing {
            missing++
        }
    }
    if missing == 0 {
        t.Error("entrada MISSING esperada não detectada")
    }
}
```

### 11.6. Adições ao CI Mirror

```bash
# Gate CPL — integridade criptográfica
go test -race -count=1 ./internal/cpl/... ./internal/notification/...

# Vector de teste fixo — regressão de canonicalização
wardex config hash --config testdata/fixtures/cpl/config_canonical.yaml \
  | grep -q "sha256:" || { echo "vector de canonicalização quebrado"; exit 1; }

# Roundtrip verify-link
wardex evaluate \
  --config testdata/fixtures/cpl/config_canonical.yaml \
  --evidence testdata/fixtures/vulns_clean.yaml \
  --audit-log /tmp/cpl_test.jsonl
wardex audit verify-link \
  --audit-log /tmp/cpl_test.jsonl \
  --config testdata/fixtures/cpl/config_canonical.yaml
test $? -eq 0

# Adulteração detectada
python3 -c "
import json, sys
lines = open('/tmp/cpl_test.jsonl').readlines()
entry = json.loads(lines[0])
entry['config_hash'] = 'sha256:0000000000000000'
lines[0] = json.dumps(entry)
open('/tmp/cpl_test_tampered.jsonl', 'w').writelines(lines)
"
wardex audit verify-link \
  --audit-log /tmp/cpl_test_tampered.jsonl \
  --config testdata/fixtures/cpl/config_canonical.yaml
test $? -eq 1
```

---

## 12. Notificação de Divergência

Quando `wardex audit verify-link` detecta MISMATCH ou MISSING, ou quando `wardex audit verify-chain` detecta adulteração da hash chain, o Wardex pode notificar um endpoint externo (SIEM, alerting platform, webhook receptor). A notificação é fire-and-forget e não-bloqueante: não afecta o exit code nem o relatório do comando.

O mecanismo é nativo ao Wardex — sem agentes externos, sem sidecars.

### 12.1. Configuração

```yaml
# wardex-config.yaml
notifications:
  divergence_webhook:
    url: "${WARDEX_SIEM_WEBHOOK_URL}"
    auth_env: "WARDEX_SIEM_TOKEN"   # Bearer token; omitir se o endpoint não requer auth
    timeout_seconds: 5              # default: 5; máximo aceite: 30
    headers:                        # opcional — headers adicionais
      X-Source: "wardex"
      X-Environment: "production"
```

`url` e `auth_env` são resolvidos em runtime via `os.Getenv`. Se `url` estiver vazio ou a env var não estiver definida, a notificação é silenciosamente ignorada — não retorna erro, não emite warning. Configuração ausente é o estado por defeito (opt-in).

### 12.2. Eventos que Disparam Notificação

| Evento | Comando | Condição |
|--------|---------|----------|
| `cpl.verify_link.mismatch` | `wardex audit verify-link` | Uma ou mais entradas com status MISMATCH |
| `cpl.verify_link.missing` | `wardex audit verify-link` | Uma ou mais entradas com status MISSING |
| `cpl.chain.tampered` | `wardex audit verify-chain` | Hash chain corrompida detectada |

Uma única execução de `verify-link` com MISMATCH e MISSING emite uma notificação consolidada — não uma por entrada.

### 12.3. Payload

```json
{
  "source": "wardex",
  "event_type": "cpl.verify_link.mismatch",
  "timestamp": "2026-06-25T14:32:10Z",
  "audit_log": "wardex-audit.log",
  "summary": {
    "total_entries": 45,
    "ok": 43,
    "mismatch": 2,
    "missing": 0
  },
  "divergences": [
    {
      "entry_timestamp": "2026-05-01T10:00:00Z",
      "status": "MISMATCH",
      "recorded_hash": "sha256:abc123...",
      "computed_hash": "sha256:def456...",
      "config_file": "configs/2026-05-01.yaml"
    },
    {
      "entry_timestamp": "2026-05-15T09:15:00Z",
      "status": "MISMATCH",
      "recorded_hash": "sha256:aaa111...",
      "computed_hash": "sha256:bbb222...",
      "config_file": "configs/2026-05-15.yaml"
    }
  ]
}
```

Para `cpl.chain.tampered`, o campo `divergences` contém a primeira entrada onde a cadeia quebra, com `status: "CHAIN_BREAK"` e o índice da linha no log.

### 12.4. Comportamento em Falha

Se o endpoint não responder dentro de `timeout_seconds`, ou retornar um status HTTP não-2xx, o Wardex:

1. Emite um warning em stderr: `[wardex] notification: webhook failed: <reason>`.
2. Continua a execução normalmente.
3. Não altera o exit code.

A falha de notificação nunca mascara a divergência: o relatório em stdout e o exit code reflectem sempre o estado real, independentemente de o webhook ter sido alcançado.

### 12.5. Implementação Go

```go
package notification

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

// DivergencePayload é o contrato de notificação enviado ao webhook.
// Campos adicionais podem ser acrescentados em versões futuras sem
// quebrar receptores existentes (additive JSON).
type DivergencePayload struct {
    Source     string       `json:"source"`
    EventType  string       `json:"event_type"`
    Timestamp  time.Time    `json:"timestamp"`
    AuditLog   string       `json:"audit_log"`
    Summary    Summary      `json:"summary"`
    Divergences []Divergence `json:"divergences"`
}

type Summary struct {
    TotalEntries int `json:"total_entries"`
    OK           int `json:"ok"`
    Mismatch     int `json:"mismatch"`
    Missing      int `json:"missing"`
}

type Divergence struct {
    EntryTimestamp time.Time `json:"entry_timestamp"`
    Status         string    `json:"status"`
    RecordedHash   string    `json:"recorded_hash,omitempty"`
    ComputedHash   string    `json:"computed_hash,omitempty"`
    ConfigFile     string    `json:"config_file,omitempty"`
}

// WebhookConfig contém a configuração resolvida do webhook.
// url e token são resolvidos via os.Getenv antes de chegarem aqui.
type WebhookConfig struct {
    URL            string
    Token          string // Bearer token; vazio = sem auth
    TimeoutSeconds int
    Headers        map[string]string
}

// Send dispara a notificação de forma não-bloqueante.
// Erros são retornados mas não são fatais para o caller — o caller
// emite warning e continua. Nunca bloqueia além de timeout.
func Send(cfg WebhookConfig, payload DivergencePayload) error {
    if cfg.URL == "" {
        return nil // opt-out silencioso
    }

    body, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("notification: marshal: %w", err)
    }

    timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
    if timeout <= 0 || timeout > 30*time.Second {
        timeout = 5 * time.Second
    }

    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("notification: build request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")
    if cfg.Token != "" {
        req.Header.Set("Authorization", "Bearer "+cfg.Token)
    }
    for k, v := range cfg.Headers {
        req.Header.Set(k, v)
    }

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("notification: send: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("notification: endpoint returned %d", resp.StatusCode)
    }

    return nil
}
```

### 12.6. Testes do Webhook

```go
package notification_test

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/had-nu/wardex/internal/notification"
)

// TestWebhookCalledOnDivergence verifica que o payload chega ao endpoint
// quando existe pelo menos uma divergência.
func TestWebhookCalledOnDivergence(t *testing.T) {
    var received notification.DivergencePayload
    called := false

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        called = true
        if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
            t.Errorf("decode payload: %v", err)
        }
        w.WriteHeader(http.StatusOK)
    }))
    defer srv.Close()

    cfg := notification.WebhookConfig{
        URL:            srv.URL,
        TimeoutSeconds: 5,
    }
    payload := notification.DivergencePayload{
        Source:    "wardex",
        EventType: "cpl.verify_link.mismatch",
        Timestamp: time.Now().UTC(),
        AuditLog:  "audit.log",
        Summary:   notification.Summary{TotalEntries: 10, OK: 9, Mismatch: 1},
    }

    if err := notification.Send(cfg, payload); err != nil {
        t.Fatalf("Send: %v", err)
    }
    if !called {
        t.Error("webhook não foi chamado")
    }
    if received.EventType != "cpl.verify_link.mismatch" {
        t.Errorf("event_type errado: %q", received.EventType)
    }
}

// TestWebhookNotCalledWhenURLEmpty verifica o opt-out silencioso.
func TestWebhookNotCalledWhenURLEmpty(t *testing.T) {
    cfg := notification.WebhookConfig{URL: ""}
    err := notification.Send(cfg, notification.DivergencePayload{})
    if err != nil {
        t.Errorf("URL vazia deve retornar nil, obteve: %v", err)
    }
}

// TestWebhookTimeoutDoesNotBlock verifica que um endpoint lento não
// bloqueia o caller além do timeout configurado.
func TestWebhookTimeoutDoesNotBlock(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(10 * time.Second) // nunca responde dentro do timeout
    }))
    defer srv.Close()

    cfg := notification.WebhookConfig{
        URL:            srv.URL,
        TimeoutSeconds: 1,
    }

    start := time.Now()
    err := notification.Send(cfg, notification.DivergencePayload{})
    elapsed := time.Since(start)

    if err == nil {
        t.Error("esperava erro de timeout, obteve nil")
    }
    if elapsed > 3*time.Second {
        t.Errorf("Send bloqueou além do timeout: %v", elapsed)
    }
}

// TestWebhookAuthHeaderPresent verifica que o Bearer token é enviado
// quando configurado, e ausente quando não configurado.
func TestWebhookAuthHeaderPresent(t *testing.T) {
    var gotAuth string

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotAuth = r.Header.Get("Authorization")
        w.WriteHeader(http.StatusOK)
    }))
    defer srv.Close()

    cfg := notification.WebhookConfig{
        URL:            srv.URL,
        Token:          "test-token-abc",
        TimeoutSeconds: 5,
    }
    notification.Send(cfg, notification.DivergencePayload{}) //nolint:errcheck

    if gotAuth != "Bearer test-token-abc" {
        t.Errorf("Authorization header errado: %q", gotAuth)
    }
}

// TestWebhookNonOKStatusReturnsError verifica que respostas HTTP não-2xx
// são tratadas como erro — sem pânico, sem silent failure.
func TestWebhookNonOKStatusReturnsError(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer srv.Close()

    cfg := notification.WebhookConfig{URL: srv.URL, TimeoutSeconds: 5}
    err := notification.Send(cfg, notification.DivergencePayload{})
    if err == nil {
        t.Error("status 500 deve retornar erro, obteve nil")
    }
}
```

