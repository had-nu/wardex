# Security Posture Assessment — NovaBank SA
## Classificação: CONFIDENCIAL — Internal Use Only

**Data de Emissão:** 21 de Abril de 2026
**Período de Análise:** Q4 2025 – Q1 2026
**Avaliador:** Wardex Assurance Platform v1.7.1
**Frameworks Avaliados:** NIS2 (EU), DORA (EU)
**Classificação de Maturidade:** Gate Maturity Level 4/5

---

## 1. Executive Summary

| Indicador | Estado | Tendência |
|----------|--------|----------|
| **Postura de Segurança** | 🟡 EM MATURAÇÃO | → Estável |
| **Cobertura de Controlos NIS2** | 58% (8/11 covered, 2 partial, 1 gap) | ↑ +8% desde última avaliação |
| **Cobertura de Controlos DORA** | 80% (4/5 covered, 1 partial, 0 gap) | → Estável |
| **Release Gate Decision** | ✅ ALLOW | ↑ Melhorou |
| **Risco Residual** | MÉDIO | ↓ Reduzido |

### Key Findings (Inteligência)

1. **Risco Crítico Ativo:** 2 CVEs críticas (CVE-2024-3092, CVE-2024-21762) com aceitações de risco ativas até Q2 2025
2. **Gap Crítico:** DORA.Art5 (Governance Framework) sem controle mapeado — risco de compliance regulatório
3. **Fraqueza Sistémica:** Supply Chain Security (NIS2.21.2.d) com maturidade insuficiente
4. **Força:** Controles de criptografia (AES-256, TLS 1.3) com maturidade nível 4

---

## 2. Análise de Vulnerabilidades (Inteligência de Ameaças)

### Priorização por EPSS (Exploit Prediction Scoring System)

| CVE | Componente | CVSS | EPSS | Prob. Exploração | Risco | Status |
|-----|-----------|------|------|-----------------|------|--------|
| CVE-2024-3092 | liblzma | **10.0** | **0.998** | **CRÍTICA** | Aceito até 2025-06-01 |
| CVE-2024-21762 | libssl-dev | **9.8** | **0.972** | **CRÍTICA** | Aceito até 2025-02-01 |
| CVE-2023-4863 | libwebp | 8.8 | 0.015 | BAIXA | Mitigado |
| CVE-2024-24786 | grpc | 8.1 | 0.003 | BAIXA | Mitigado |
| CVE-2023-44487 | http2 | 7.5 | 0.045 | BAIXA | Mitigado |
| CVE-2024-10826 | kernel | 7.5 | <0.01 | MINIMA | Mitigado |

### Análise de Inteligência

**CVE-2024-3092 (xz/liblzma backdoor):**
- *Threat Actor:* APT sofisticados, possivelmente state-sponsored
- * vetor:* Supply chain compromise em ferramentas de compressão
- *EPSS:* 99.8% — exploração ativa confirmada em múltiplos tulisit
- *Postura:* Risco mitigado por aceitação formal até patch vendor (v5.4.1)
- *Inteligência adicional:* Vendor disclosure em 2024-03-29; nenhuma exploração in-the-wild detetada em ambiente NovaBank

**CVE-2024-21762 (OpenSSL):**
- *Threat Actor:* APT29, APT28 (Russia, China)
- *EPSS:* 97.2% — exploração massiva esperada
- *Postura:* Patch aplicado em produção desde 2024-12-18; risco residual em non-production

---

## 3. Cobertura de Controlos NIS2

| ID | Controlo | Cobertura | Score | Mapeamento | Gap Intelligence |
|----|---------|----------|-------|------------|-----------------|
| NIS2.21.2.a | Risk Analysis & Security Policy | ✅ Covered | 9.0 | CTRL-001 (Firewall), CTRL-003 (MFA), CTRL-020 (Access Reviews) | Maturidade OK |
| NIS2.21.2.b | Incident Handling | ⚠️ Partial | 9.5 | CTRL-002 (SIEM), CTRL-012 (IR Plan), CTRL-018 (Logs) | **IR Plan requer tabletop** |
| NIS2.21.2.c | Business Continuity | ✅ Covered | 8.5 | CTRL-005 (Backup) | Evidence atualizada Q4/25 |
| NIS2.21.2.d | Supply Chain Security | ⚠️ Partial | 10.0 | CTRL-007 (SBOM), CTRL-013 (Vendor Risk) | **CRÍTICO: Maturidade 2 < 3 mínimo** |
| NIS2.21.2.e | Network & System Security | ✅ Covered | 8.0 | CTRL-004 (Patch), CTRL-006 (WAF), CTRL-008 (API GW), CTRL-009 (Container), CTRL-015 (Vuln Scan) | Patch SLA compliance |
| NIS2.21.2.i | Security Training | ✅ Covered | 7.0 | CTRL-014 (Training) | Completude 98% |

### Riscos de Compliance NIS2

1. **NIS2.21.2.d — Supply Chain Security (GAP CRÍTICO):**
   - SBOM generation implementada mas maturidade nível 2 (mínimo 3 exigido)
   - Vendor risk assessment: 8/15 vendors respondidos (53%)
   - Risco: Sanção regulatória NIS2 Art.21

2. **NIS2.21.2.b — Incident Handling:**
   - IR Plan documentado mas último tabletop em Q1/2024
   - Risco: Incapacidade de demonstrar readiness

---

## 4. Cobertura de Controlos DORA

| ID | Controlo | Cobertura | Score | Mapeamento |
|----|---------|----------|-------|-----------|
| DORA.Art5 | Governance Framework | ❌ **GAP** | 10.0 | N/A |
| DORA.Art9 | Protection & Prevention | ✅ Covered | 9.5 | CTRL-001, 010, 011, 016, 017 |
| DORA.Art10 | Detection | ✅ Covered | 8.5 | CTRL-002 |
| DORA.Art11 | Response & Recovery | ✅ Covered | 9.0 | CTRL-005 |
| DORA.Art24 | Digital Resilience Testing | ⚠️ Partial | 7.5 | CTRL-015, 019 |

### Riscos de Compliance DORA

1. **DORA.Art5 — Governance (CRÍTICO):**
   - Nenhum controle mapeado para framework de governance ICT
   - Requer: Board-level ICT risk management policy formalizada
   - Impacto: Não conformidade Art.5 DORA

2. **DORA.Art24 — Resilience Testing:**
   - Vulnerability scanning OK
   - Pentest externo anual; próximo Q1/2025
   - Risco: DORA exige testing program mais frequente

---

## 5. Release Gate Analysis

| Métrica | Valor | Limiar | Status |
|--------|-------|--------|--------|
| Risk Appetite | 6.5 | 6.5 | ✅ PASS |
| Warn Above | 4.0 | Max allowed: 4.0 | ✅ PASS |
| Gate Maturity | 4/5 | Min required: 2/5 | ✅ PASS |
| Vulnerabilities Blocked | 0/10 | Expected: 0 | ✅ PASS |

### Fatores de Mitigação Ativos

1. **Network Segmentation:** 50% efetividade
2. **MFA Universal:** 60% efetividade
3. **Asset Criticality:** 0.9 (Restricted data class)
4. **Risk Acceptances:** 2 ativas (CVEs críticas)

---

## 6. Recomendações de Inteligência (Roadmap)

| Prioridade | Ação | Controlo Alvo | Prazo | Impacto |
|-----------|------|--------------|------|--------|
| 🔴 CRÍTICA | Formalizar ICT Governance Framework | DORA.Art5 | 2025-06-30 | Sanção regulatória |
| 🔴 CRÍTICA | Elevar SBOM maturity para nível 3 | NIS2.21.2.d | 2025-05-15 | NIS2 compliance |
| 🟡 ALTA | Completar vendor risk assessments (15→15) | NIS2.21.2.d | 2025-04-30 | Supply chain visibility |
| 🟡 ALTA | Executar IR tabletop exercise | NIS2.21.2.b | 2025-04-15 | IR readiness |
| 🟢 MÉDIA | Implementar TLAP (threat-led) | DORA.Art24 | 2025-Q3 | DORA testing |
| 🟢 MÉDIA | Access reviews trimestrais | NIS2.21.2.a | 2025-Q2 | IAM hygiene |

---

## 7. Anexos

### A. Inventário de Controlos Implementados

| ID | Nome | Maturidade | Status |
|----|------|------------|--------|
| CTRL-001 | Firewall Perimetral | 3 | Operational |
| CTRL-002 | SIEM Centralizado | 3 | Operational |
| CTRL-003 | MFA Azure AD | 4 | Operational |
| CTRL-004 | Patch Management | 2 | Partial |
| CTRL-005 | Backup & Recovery | 3 | Operational |
| CTRL-006 | WAF | 3 | Operational |
| CTRL-007 | SBOM Creation | 2 | Partial |
| CTRL-008 | API Gateway | 4 | Operational |
| CTRL-009 | Container Security | 3 | Operational |
| CTRL-010 | Encryption at Rest | 4 | Operational |
| CTRL-011 | DDoS Protection | 3 | Operational |
| CTRL-012 | Incident Response | 2 | Partial |
| CTRL-013 | Vendor Risk | 2 | Partial |
| CTRL-014 | Security Training | 3 | Operational |
| CTRL-015 | Vuln Scanner | 3 | Operational |
| CTRL-016 | Encryption in Transit | 4 | Operational |
| CTRL-017 | Network Segmentation | 2 | Partial |
| CTRL-018 | Log Retention | 3 | Operational |
| CTRL-019 | Pentesting | 2 | Partial |
| CTRL-020 | Access Reviews | 2 | Partial |

### B. Aceitações de Risco Ativas

| CVE | Expiração | Severidade | Aprovador |
|-----|----------|------------|-----------|
| CVE-2024-3092 | 2025-06-01 | CRITICAL | CISO |
| CVE-2024-21762 | 2025-02-01 | CRITICAL | CISO |

### C. Evidências de Avaliação

- Scan: Grype v0.80.0 (2026-04-20)
- EPSS Scores: FIRST.org API (2026-04-20)
- Catalogs: Wardex built-in NIS2, DORA (v1.7.1)
- Mapping: Manual, validado por AppSec Team

---

**Documento preparado por:** Wardex Assurance Platform
**Classificação:** CONFIDENCIAL — Internal Use Only
**Distribuição:** CISO, CIO, Head of AppSec, Legal & Compliance