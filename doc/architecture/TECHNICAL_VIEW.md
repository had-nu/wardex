# A Arquitectura e Engenharia do Wardex

O design do Wardex centra-se em portabilidade, desempenho e auditabilidade total, usando os módulos core (stdlib) primários do Ecossistema Go de forma a manter os fluxos de automação CI/CD isentos de complexidades redundantes impostas por dependências de pacotes opacos (*Bloat-free*). O projeto foi propositadamente concebido para funcionar unicamente no processamento de matrizes da avaliação de maturidade matemática.

## Componentes Chaves da Tomada de Decisão do Sistema

A complexidade interna subjacente não impacta a eficiência temporal nem logística; uma execução avalia e converte avaliações no decurso de pequenos milissegundos sem depender da criação dinâmica de contentores independentes nem requerer suporte primário de qualquer base de dados, utilizando puramente processos em estado estático (Stateless).

### 1. Sistema de "Ingestion" e Correlacionador (`pkg/ingestion`, `pkg/correlator`)
As rotinas foram concebidas adotando mapeamento de modelos padronizados, por forma a ser totalmente imune à semântica local das especificações particulares da organização:
* Os módulos aceitam `YAML`, `JSON` e exportações em `CSV`.
* O mecanismo implementa validações do schema obrigatório exigindo campos como `ID` e `Maturidade` desde logo, para impedir a geração de modelos imperfeitos para as componentes downstream que tomam a decisão avaliatória primária.
* A avaliação procede a uma análise dupla entre "Correlação Elevada (High)" e "Correlação de Nível Deduzido (Low)". Se uma organização usa "NIST", mas o Wardex utiliza a ISO 27001 como matriz de avaliação, o Correlacionador usa a interseção de domínios para alta confiança e o método `strings.Contains` em palavras-chave para as correlações de baixo nível. O resultado não bloqueia a compatibilidade internacional da infraestrutura GRC independente caso os domínios divirjam pontualmente, embora assinale explicitamente que a correlação exige curadoria extra para validação humana através das restrições de "Partial Coverages". 

### 2. Máquina Analítica e de Classificação (`pkg/scorer`, `pkg/analyzer`)
Na etapa avaliativa, o Scorer traduz instâncias isoladas em maturidade baseada em domínios ISO (A.5 à A.8). A pontuação de maturidade por domínio é calculada como a média da maturidade efectiva (`EffectiveMaturity`) dos controlos cobertos, permitindo uma visão realista da postura técnica.
* **Layer Delta (`ComputeLayerDelta`)**: Identifica o desvio entre o que o infosec declarou (Paper Security) e o que os scanners/ferramentas confirmaram (Shadow Security).
* **Asset Assessment (`AssessAssets`)**: Mapeia controlos a activos específicos, permitindo auditorias contextuais por unidade de negócio ou sistema crítico.

### 3. A Mecânica do Gate "Risk-Based" (`pkg/releasegate`)
A espinha dorsal operatória está na componente formal das Decisões de Avaliação Contínuas por Submissão (Gate Evaluations). Como discutido em relação ao Valor do Negócio (`BUSINESS_VIEW.md`), o Gate incorpora uma equação de matemática probabilística que processa em profundidade:

O Wardex utiliza um modelo de risco contextual purificado para a tomada de decisão:

$$R(v, \alpha) = (CVSS(v)/10) \times EPSS(v) \times C(\alpha) \times E(\alpha) \times (1 - \Phi(\alpha))$$

Onde:
*   **$CVSS(v)$**: Gravidade intrínseca da vulnerabilidade (NVD).
*   **$EPSS(v)$**: Probabilidade de exploração em 30 dias (FIRST.org).
*   **$C(\alpha)$**: Coeficiente de Criticidade do Negócio (ex: 1.5 para infraestrutura crítica/bancos).
*   **$E(\alpha)$**: Coeficiente de Exposição Efectiva (ajustado por acessibilidade de rede e autenticação).
*   **$(1 - \Phi(\alpha))$**: Factor de Eficácia de Controlos Compensatórios (WAF, IPS, Segmentação), limitado a uma redução máxima de 80% (clamped em 0.20).

O Wardex permite forçar a interrupção através de "Hard Gates", limitando explicitamente a probabilidade de aprovar Submissões sob modo **Aggregated** (se a soma de todos os pequenos scores for superior ao risco admissível geral) e/ou perante execuções isoladas via mecânica standard (O vetor base **ANY**). Existem três bandas possíveis: `ALLOW`, `WARN` (risco excede `warn_above` mas aceitável), e `BLOCK` (excede limite fatal `risk_appetite`). Isto proporciona flexibilidade operacional vital à gestão de tolerância progressiva das empresas.

A adoção progressiva deste módulo inferida de `InferMaturityLevel()` produz pontuação analítica do Gate num ranking em camadas baseadas em variáveis providenciadas (Level 1 a Level 5). Ao documentar mais características, a maturidade pontual tecnológica global do negócio acresce.

### 4. Gestão do Delta de Conformidade Incremental (`pkg/snapshot`)
Para gerir fluxos perfeitamente funcionais em metodologias ágeis de monitorização cíclica (CICD) - exigência suprema contemplada através da Regra do Aperfeiçoamento Incremental Contínuo prevista sob regulamentação da ISO Cláusula 10.2, - concebeu-se uma rotina nativa na exportação e compilação do rasto serializado em ficheiros `.wardex_snapshot.json`. Esta persistência elementar executa o diferencial delta, traduzindo no momento de elaboração dos relatórios subsequentes dados numéricos absolutos entre falhas novas, resolvidas à data, reduções de riscos e o respetivo acréscimo de avanço de percentil da Conformidade de Segurança da Rede sem interrupções nem interações das equipas envolvidas do Q.A (Qualidade / Assurance) do ambiente laboratorial da empresa para documentação exterior ou de entidades inspetórias de *Auditoria ISO Oficial*.

### 5. Estabilidade e Segurança do Código-Fonte (Unit & Fuzz Testing)
A arquitetura do **Wardex** não estaria completa sem uma fundação de testes robusta de modo a suportar os fluxos altamente sensíveis de Segurança e Integridade das pipelines (CI). O código fonte atende a dois espectros essenciais de garantia e qualidade:

1. **Unit Testing Exaustivo**: Todos os submódulos (`analyzer`, `correlator`, `ingestion`, `releasegate`, `report`, `scorer`, `snapshot`) possuem as respetivas suítes de teste (ex: `TestRiskBasedGateVsBinaryThreshold`, `TestGateMaturityInference`) para validar a exatidão das equações e saídas. As validações assentam primordialmente no cálculo comparativo das variáveis em *hard-coded* assegurando que desvios acidentais e de refatorações geram regressões iminentemente reportadas visíveis.
2. **Native Go Fuzzing**: Sendo que o Wardex processa invariavelmente controlos YAML, JSON e CSV como inputs primários, implementou-se em `pkg/ingestion/ingestion_fuzz_test.go` o motor Nativo de Fuzzing de Go (`go test -fuzz`). O motor valida campos obrigatórios e rejeita linhas malformadas, garantindo que o CLI encerra com erros controlados sem interromper bruscamente a rotina do pipeline ou expor falhas de memória (memory leaks) sob estresse massivo.

### 6. Sistema de Aceitação de Risco Assinado (`pkg/accept`)
Para suportar exceções justificadas ao *Release Gate*, o Wardex integra um sistema unificado em `pkg/accept` encarregue da *Aceitação Formal de Risco* com validação de adulteração state-of-the-art:

* **Integridade Criptográfica**: Recusa o uso de segredos na base de código, exigindo variáveis de ambiente restritas (`WARDEX_ACCEPT_SECRET`) para assinar payloads HMAC-SHA256.
* **Validação por Design**: Todas as exceções passam por rotinas de carga estritas. O sistema implementa o padrão "Fail-Closed" e aborta com Exit Codes rigorosos (`3` para adulterações/tampering ou configurações obsoletas pós-*drift*).
* **Auditoria Imutável**: Regista todos os passos ("created", "revoked", "expired") em matrizes `JSONL` locais (`wardex-accept-audit.log`) para integração com SIEM.

### 7. Testando o Módulo de Aceitação Localmente

Para validar em profundidade o comportamento criptográfico da aceitação de risco num laboratório local, a arquitetura permite-lhe injetar chaves e submeter a rotina end-to-end usando os dados de ambiente incluídos no repositório:

1. **Geração do *Dummy Report* Base**: O *Gate* avalia vulnerabilidades passadas como argumento (ex. via Grype) com a matriz de políticas YAML da sua empresa. Execute primeiro a validação primária:
   ```bash
    wardex evaluate --evidence test/testdata/vulnerabilities.yaml --config test/testdata/wardex-config.yaml -o json --out-file report.json
   ```

2. **Injetar Segredo de Assinatura via Config e EnvVars**: O mecanismo obriga à verificação do `hmac_secret_env` contido na policy original da organização para proibir *bypasses* estáticos:
   ```bash
   echo "accept:" >> test/testdata/wardex-config.yaml
   echo "  hmac_secret_env: WARDEX_ACCEPT_SECRET" >> test/testdata/wardex-config.yaml
   export WARDEX_ACCEPT_SECRET="wardex_local_test_key_123"
   ```

3. **Invocação de *Risk Acceptance* sobre um Bloqueio Explícito**:
   Solicitação manual de uma anulação temporária para um CVE em particular, submetido debaixo do nome e rasto verificável de um utilizador:
   ```bash
   wardex accept request --report report.json --cve CVE-2024-1234 --accepted-by tester@auth.com --justification "Local Testing Override" --yes
   ```
   *(Esta rotina cria o binário imutável em `wardex-acceptances.yaml` e adiciona as matrizes `JSONL` a `wardex-accept-audit.log`)*.

4. **Operações de Teste do Trimming de Validação Secundária**: Corrompa intencionalmente o payload das aceitações editando um byte ou re-arranjando IDs no `wardex-acceptances.yaml`. Valide o acionamento fulminante das flags anti-tampering (Exit Code **3**) recorrendo a:
   ```bash
   wardex accept list --active
   wardex accept verify
   ```
