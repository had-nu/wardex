# A Arquitectura e Engenharia do Wardex

O design do Wardex centra-se em portabilidade, desempenho e auditabilidade total, usando os módulos core (stdlib) primários do Ecossistema Go de forma a manter os fluxos de automação CI/CD isentos de complexidades redundantes impostas por dependências de pacotes opacos (*Bloat-free*). O projeto foi propositadamente concebido para funcionar unicamente no processamento de matrizes da avaliação de maturidade matemática.

## Componentes Chaves da Tomada de Decisão do Sistema

A complexidade interna subjacente não impacta a eficiência temporal nem logística; uma execução avalia e converte avaliações no decurso de pequenos milissegundos sem depender da criação dinâmica de contentores independentes nem requerer suporte primário de qualquer base de dados, utilizando puramente processos em estado estático (Stateless).

### 1. Sistema de "Ingestion" e Correlacionador (`pkg/ingestion`, `pkg/correlator`)
As rotinas foram concebidas adotando mapeamento de modelos padronizados, por forma a ser totalmente imune à semântica local das especificações particulares da organização:
* Os módulos aceitam `YAML`, `JSON` e exportações em `CSV`.
* O mecanismo implementa validações do schema obrigatório exigindo campos como `ID` e `Maturidade` desde logo, para impedir a geração de modelos imperfeitos para as componentes downstream que tomam a decisão avaliatória primária.
* A avaliação procede a uma análise dupla entre "Correlação Elevada (High)" e "Correlação de Nível Deduzido (Inferential/Low)". Se uma organização usa "NIST", mas o Wardex utiliza a ISO 27001 como matriz de avaliação, o Correlacionador usa mapeamento estrito por `Domains`, saltando para mapeamento via Regex simplificado nos elementos lexicais contidos em descrições de `Name` ou `Description` para as correlações Inferidas de Baixo Nível. O resultado não bloqueia a compatibilidade internacional da infraestrutura GRC independente caso os domínios divirjam pontualmente, embora assinale explicitamente que a correlação exige curadoria extra para validação humana através das restrições de "Partial Coverages". 

### 2. Máquina Analítica e de Classificação (`pkg/scorer`, `pkg/analyzer`)
Na etapa avaliativa, o Scorer traduz instâncias isoladas em maturidade baseada em domínios ISO (A.5 à A.8), permitindo que relatórios expressem, em vez de lacunas obscuras e técnicas singulares, défices amplos nas políticas formativas gerais de Gestão do Capital Humano, Organizacional, Tecnológico ou Físico (Facility Controls). Aqui insere-se a importância orgânica do Peso Contextual (`context_weight`). Base Scores puros, gerados arbitrariamente sobre controlos estáticos (Ex: Utilização Criptografia Têm Nível 10 - Elevado), não importam unicamente num modelo funcionalista, o que motivou a arquitetura do Scorer de prever multiplicadores explícitos geríveis centralmente do lado do cliente entre a gama conservadora standard de [0.5, 2.0] a fim de normalizar prioridades face à urgência autística dos outputs do *vendor* nativo.

### 3. A Mecânica do Gate "Risk-Based" (`pkg/releasegate`)
A espinha dorsal operatória está na componente formal das Decisões de Avaliação Contínuas por Submissão (Gate Evaluations). Como discutido em relação ao Valor do Negócio (`BUSINESS_VIEW.md`), o Gate incorpora uma equação de matemática probabilística que processa em profundidade:

```
Risco Ajustado = CVSS * Fator Previsto EPSS 
Limiar de Exposição = [ (Contexto Interno ou Contextual Externo) - Redução da Atividade de Autenticação ] * Avaliação da Exposição de Rota (Reachable Boolean Context)
Avaliação de Compensação = Total Aritmético de Eficiência por Componentes Adicionais (WAF/Segmentation), contido a um max de 0.8
Decisão Base = (Risco Ajustado * (1 - Avaliação de Compensação)) * Criticidade Económica Central * Limiar de Exposição
```

O Wardex permite forçar a interrupção através de "Hard Gates", limitando explicitamente a probabilidade de aprovar Submissões sob modo **Aggregated** (se a soma de todos os pequenos scores for superior ao risco admissível geral) e/ou perante execuções isoladas via mecânica standard (O vetor base **ANY**), proporcionando flexibilidade operacional vital à gestão de tolerância progressiva das empresas que utilizem as pipelines para efetivar os parâmetros limitativos. A análise de criticidade final inclui obrigatoriamente `Trace Trails` de Output para revisão direta, evidenciando as escolhas operacionais detalhadamente. Exemplo: `CVSS original: 9.1 | EPSS 0.83 -> Contexto Compensações do WAF. Fator de Block: ALLOW`.

A adoção progressiva deste módulo inferida de `InferMaturityLevel()` produz pontuação analítica do Gate num ranking em camadas baseadas em variáveis providenciadas (Level 1 a Level 5). Esse número alimenta organicamente os "Technological Control Scores", criando um ciclo reflexivo orgânico face aos progressos alcançados da ferramenta CI inserido integralmente num sistema ISO superior. Ao documentar mais características, a maturidade pontual tecnológica global do negócio acresce.

### 4. Gestão do Delta de Conformidade Incremental (`pkg/snapshot`)
Para gerir fluxos perfeitamente funcionais em metodologias ágeis de monitorização cíclica (CICD) - exigência suprema contemplada através da Regra do Aperfeiçoamento Incremental Contínuo prevista sob regulamentação da ISO Cláusula 10.2, - concebeu-se uma rotina nativa na exportação e compilação do rasto serializado em ficheiros `.wardex_snapshot.json`. Esta persistência elementar executa o diferencial delta, traduzindo no momento de elaboração dos relatórios subsequentes dados numéricos absolutos entre falhas novas, resolvidas à data, reduções de riscos e o respetivo acréscimo de avanço de percentil da Conformidade de Segurança da Rede sem interrupções nem interações das equipas envolvidas do Q.A (Qualidade / Assurance) do ambiente laboratorial da empresa para documentação exterior ou de entidades inspetórias de *Auditoria ISO Oficial*.

### 5. Estabilidade e Segurança do Código-Fonte (Unit & Fuzz Testing)
A arquitetura do **Wardex** não estaria completa sem uma fundação de testes robusta de modo a suportar os fluxos altamente sensíveis de Segurança e Integridade das pipelines (CI). O código fonte atende a dois espectros essenciais de garantia e qualidade:

1. **Unit Testing Exaustivo**: Todos os submódulos (`analyzer`, `correlator`, `ingestion`, `releasegate`, `report`, `scorer`, `snapshot`) possuem as respetivas suítes de teste (ex: `TestRiskBasedGateVsBinaryThreshold`, `TestGateMaturityInference`) para validar a exatidão das equações e saídas. As validações assentam primordialmente no cálculo comparativo das variáveis em *hard-coded* assegurando que desvios acidentais e de refatorações geram regressões iminentemente reportadas visíveis.
2. **Native Go Fuzzing**: Sendo que o Wardex processa invariavelmente controlos YAML, JSON e CSV como inputs primários (e frequentemente provindos de *data lakes* de terceiros corrompidos ou não estruturados), implementou-se em `pkg/ingestion/ingestion_fuzz_test.go` o motor Nativo de Fuzzing de Go (`go test -fuzz`). A bateria aplica estritamente mutações em centenas de milhares de sequências binárias randomizadas para avaliar ruturas catastróficas dos parsers ("*Panics*"). Com execuções que já ultrapassaram o crivo de milhões de execuções imperfeitas com *Zero Panics*, garante-se que o CLI encerra com erros controlados sem interromper bruscamente a rotina do pipeline ou expor falhas de memória (memory leaks) sob estresse massivo.
