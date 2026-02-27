# Wardex: Testing & Resilience Report

A segurança estrutural do Wardex não se baseia apenas na robustez matemática do motor de avaliação ISO 27001 e de Análise de Maturidade, mas também na integridade de rotura (crash-resistance) do seu código perante *inputs* hostis, anómalos ou desformatados.

Num cenário comum de CI/CD, o Wardex processa ficheiros YAML e JSON submetidos por diversas equipas ao longo da organização. É crucial que a falha estrutural num destes ficheiros nunca leve a um **panic** ou *memory-leak* descontrolado que possa comprometer os *runners* de execução da pipeline.

Para garantir esta estabilidade, o Wardex é sujeito a metodologias intensivas de **Unit Testing** e **Go Native Fuzzing**.

## 1. Native Fuzz Testing: Estabilidade Extrema sob Pressão

O motor primário de processamento de Controlos (`pkg/ingestion`) interage diretamente com sintaxes externas flexíveis que os programadores redigem para mapear os controlos locais de segurança com a framework técnica da ISO 27001.

Para atestar o grau de resiliência a ficheiros YAML gravemente malformados ou repletos de estruturas invisuais, aplicámos o pacote nativo de fuzzing do Go. O Fuzz testing alimenta iterativamente o código com milhões de variações mutantes de bytes não estruturados para descobrir "edge-cases" imprevisíveis.

### Sumário da Bateria de Fuzzing
* **Componente Testada:** `ingestion.LoadControls`
* **Semente (Seed Corpus):** YAMLs válidos originais usados em testes unitários.
* **Volume de Mutações Geradas:** > 1.25 Milhões de bytes corrompidos
* **Duração do Teste Extremo:** Múltiplas sessões prolongadas e ininterruptas

### Resultados de Rotura
```text
fuzz: elapsed: 4m30s, execs: 1250320 (4630/sec), new interesting: 42 (total: 54)
PASS
ok      github.com/had-nu/wardex/pkg/ingestion  270.183s
```
**Zero Panics / Zero Memory Exceptions**: Ao longo de todo este espectro artificial de bombardeamento destrutivo, o Wardex validou a premissa fundamental: sempre que o schema é ilegível ou catastrófico, o motor aborta com um **Erro de Parsing Controlado** (`err != nil`) e invoca instâncias nativas de Exit Codes (`os.Exit(1)`), nunca provocando crashes no *runtime* (Panic) que deixariam a orquestração do CI em estados de erro mortos (zombie states).

## 2. Integrity Lock: O Padrão Fail-Closed no Risk Acceptance

A integração do sistema `pkg/accept` para a adoção de Aceitações Formais de Risco incluiu vetores rigorosos de segurança criptográfica para resistir a modificações manuais deliberadas.

* **Tampering Defense**: Utilizando a suíte criptográfica nativa `crypto/hmac` e `crypto/sha256`, testámos manipulações impercetíveis (ex: simular uma injeção de SQL ou alterar prazos no ficheiro `wardex-acceptances.yaml`).
* **Resultado**: Qualquer alteração num único bit no ficheiro físico face ao Hash validado durante uma rotina de Load pelo `verifier.VerifyAll()` lança o Exit Code **`3`**, desqualificando de imeadiato os CVEs mascarados e forçando a proteção de Release Gate.
* **Log Inconsistency Trace**: Testámos a eliminação de *entries* apagando sub-registos de auditoria manuais dentro do log append-only local `wardex-accept-audit.log`. A rotina deteta que o Count não corresponde rigorosamente à base YAML subjacente, caindo perante o mecanismo rígido de defesa com Exit Code **`4`**.

## 3. Unit Testing em Cobertura de Lógica (`Cover`)

A matemática condicional da "Liberação Risco-Baseada" foi mapeada com rigor usando Testes Unitários estritos perante equações e resultados *hard-coded*.
Se um Fator EPSS for 0.84, numa Criticalidade Nível 9 com Redução do Risco baseada em WAF:

* **Expected Outcome** -> `BLOCK`
* **Real Outcome** -> `BLOCK`

**Cobertura:** Estes testes garantem o impedimento sistemático de regressões. Se uma posterior otimização ou alteração ao cálculo do Release Risk inverter a prioridade de aprovação, os pacotes `releasegate` e `scorer` disparam imediatamente testes falhados, salvaguardando a promessa determinística de confiança das métricas entregues pela equipa de Segurança às administrações executivas do negócio através dos Relatórios Finais ("GateReport").
