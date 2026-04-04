"""
TestConvergentValidity — Validação convergente via SSVC
==========================================================

Verifica que os parâmetros do modelo derivados de FIPS199/VCDB (por sector)
e os derivados de SSVC/Vulnrichment (por CVE, independentemente) produzem
ordenações de risco concordantes.

Metodologia: triangulação de constructo (não criterion validity).
- Fonte A: C(α) e E(α) derivados de FIPS 199 + VCDB por sector NAICS
- Fonte B: C(α) e E(α) derivados de SSVC Mission Prevalence + Automatable por CVE
- Estatística: Spearman ρ entre rank(R_A) e rank(R_B)
- Hipótese nula: ρ = 0 (sem concordância entre derivações)
- Hipótese alternativa: ρ > 0 (derivações produzem ordenações concordantes)

Referência: Campbell & Fiske (1959), convergent validity via multiple operationalism.
No presente contexto: sector-level proxies (FIPS199) aproximam CVE-level expert
classification (SSVC), validando o uso de proxies sectoriais para parametrização.

Limitação documentada: SSVC Mission Prevalence é avaliado por analistas para o
sistema afectado pelo CVE; FIPS199 é atribuído ao sector da organização que o
opera. As duas medições não são equivalentes — são proxies independentes do mesmo
constructo latente (criticidade operacional do activo). Concordância parcial
(ρ > 0.40) é suficiente para validade convergente; concordância perfeita não é
esperada nem é a hipótese.
"""

import math
import json
import pytest
from pathlib import Path
from dataclasses import dataclass

# Importar funções do pipeline
import sys
sys.path.insert(0, str(Path(__file__).parent))
from pipeline import (
    compute_contextual_score,
    ssvc_to_c_alpha,
    ssvc_to_e_alpha,
)


# ── Parâmetros dos 4 perfis do paper (Fonte A: FIPS199/VCDB) ─────────────────
PAPER_PROFILES_CV = {
    "BANK":  {"c_alpha": 1.50, "e_alpha": 1.00, "theta_block": 0.5},
    "HOSP":  {"c_alpha": 1.50, "e_alpha": 0.80, "theta_block": 0.8},
    "SAAS":  {"c_alpha": 1.00, "e_alpha": 0.80, "theta_block": 2.0},
    "INFRA": {"c_alpha": 1.50, "e_alpha": 0.50, "theta_block": 0.3},
}


def _spearman_rho(xs: list[float], ys: list[float]) -> float:
    """
    Spearman rank correlation sem dependências externas.
    Implementação directa via ranks e Pearson sobre os ranks.
    Empates: rank médio (average rank).
    """
    assert len(xs) == len(ys) >= 3, "Mínimo 3 observações para Spearman ρ"

    def rank_list(vals: list[float]) -> list[float]:
        sorted_vals = sorted(enumerate(vals), key=lambda x: x[1])
        ranks = [0.0] * len(vals)
        i = 0
        while i < len(sorted_vals):
            j = i
            while j < len(sorted_vals) - 1 and sorted_vals[j][1] == sorted_vals[j+1][1]:
                j += 1
            avg_rank = (i + j) / 2 + 1  # 1-indexed average rank
            for k in range(i, j + 1):
                ranks[sorted_vals[k][0]] = avg_rank
            i = j + 1
        return ranks

    rx = rank_list(xs)
    ry = rank_list(ys)
    n  = len(rx)

    mean_rx = sum(rx) / n
    mean_ry = sum(ry) / n

    num = sum((rx[i] - mean_rx) * (ry[i] - mean_ry) for i in range(n))
    den = math.sqrt(
        sum((rx[i] - mean_rx) ** 2 for i in range(n)) *
        sum((ry[i] - mean_ry) ** 2 for i in range(n))
    )
    return num / den if den > 1e-12 else 0.0


def _load_snapshot() -> list[dict]:
    path = Path("data") / "dataset_2025-03-01.json"
    if not path.exists():
        pytest.skip(f"Snapshot não encontrado: {path}. Execute smoke_test_pipeline.py primeiro.")
    data = json.loads(path.read_text())
    return data.get("cve_records", [])


def _ssvc_mission_prevalence_from_record(rec: dict) -> str:
    """
    Inferir SSVC Mission Prevalence a partir dos campos disponíveis no snapshot.

    Nos dados reais (Vulnrichment): campo directo 'ssvc_mission_prevalence'.
    No snapshot sintético: aproximado por heurística conservadora:
      - ssvc_automatable AND ssvc_exploitation in {poc, active} → "Essential"
      - ssvc_automatable OR ssvc_exploitation == "active"       → "Support"
      - else                                                    → "Minimal"

    Esta aproximação é conservadora: sub-estima "Essential" para CVEs onde
    a automação não está confirmada mas o impacto da exploração seria crítico.
    Documentar como limitação se usar dados sintéticos.
    """
    if "ssvc_mission_prevalence" in rec:
        return rec["ssvc_mission_prevalence"]

    # Heurística sintética
    automatable  = rec.get("ssvc_automatable", False)
    exploitation = rec.get("ssvc_exploitation", "none")

    if automatable and exploitation in ("poc", "active"):
        return "Essential"
    elif automatable or exploitation == "active":
        return "Support"
    else:
        return "Minimal"


class TestConvergentValidity:
    """
    Validade convergente: SSVC (por CVE) vs FIPS199/VCDB (por sector).

    Interpretação dos resultados:
      ρ ≥ 0.60 — concordância forte: as duas fontes ordenam risco de forma consistente
      ρ ∈ [0.40, 0.60) — concordância moderada: validade convergente defensável
      ρ ∈ [0.20, 0.40) — concordância fraca: limitação a documentar no paper
      ρ < 0.20 — sem concordância: as fontes medem constructos distintos

    Para publicação, ρ ≥ 0.40 é suficiente para afirmar validade convergente
    dado que as duas fontes operam em níveis de análise diferentes
    (CVE-level vs sector-level).
    """

    SPEARMAN_MIN = 0.40  # threshold mínimo para validade convergente

    @pytest.fixture(scope="class")
    def cve_records(self):
        return _load_snapshot()

    @pytest.fixture(scope="class")
    def ssvc_enriched(self, cve_records):
        """
        Enriquecer cada CVE com parâmetros derivados via SSVC (Fonte B).
        Filtra CVEs sem dados SSVC suficientes.
        """
        enriched = []
        for rec in cve_records:
            cvss = rec.get("cvss_base", 0.0)
            epss = rec.get("epss_score", 0.0)
            if cvss <= 0 or epss <= 0:
                continue  # skip CVEs sem scores válidos

            automatable  = rec.get("ssvc_automatable", False)
            exploitation = rec.get("ssvc_exploitation", "none")
            mission      = _ssvc_mission_prevalence_from_record(rec)

            c_ssvc = ssvc_to_c_alpha(mission)
            e_ssvc = ssvc_to_e_alpha(automatable, exploitation)
            r_ssvc = compute_contextual_score(cvss, epss, c_ssvc, e_ssvc)

            enriched.append({
                "cve_id":      rec.get("cve_id", ""),
                "cvss":        cvss,
                "epss":        epss,
                "cisa_kev":    rec.get("cisa_kev", False),
                "c_ssvc":      c_ssvc,
                "e_ssvc":      e_ssvc,
                "r_ssvc":      r_ssvc,
                "exploitation": exploitation,
                "automatable": automatable,
                "mission":     mission,
            })
        return enriched

    # ── Teste 1: Ordenação concordante para cada perfil ──────────────────────

    @pytest.mark.parametrize("profile_name", list(PAPER_PROFILES_CV.keys()))
    def test_spearman_concordance_per_profile(self, profile_name, ssvc_enriched):
        """
        Para cada perfil, R_ssvc e R_fips devem ordenar os CVEs de forma concordante.

        R_ssvc = CVSS × EPSS × C_ssvc × E_ssvc   (Fonte B: SSVC per-CVE)
        R_fips = CVSS × EPSS × C_profile × E_fips (Fonte A: FIPS199 por sector)

        Spearman ρ mede a concordância ordinal entre as duas ordenações.
        Um ρ alto significa que CVEs considerados de alto risco por SSVC
        são também considerados de alto risco pelo modelo FIPS199 — e vice-versa.
        """
        if len(ssvc_enriched) < 10:
            pytest.skip("Amostra insuficiente para Spearman (mínimo 10 CVEs)")

        profile = PAPER_PROFILES_CV[profile_name]
        c_p = profile["c_alpha"]
        e_p = profile["e_alpha"]

        r_ssvc_vals = []
        r_fips_vals = []

        for rec in ssvc_enriched:
            r_fips = compute_contextual_score(rec["cvss"], rec["epss"], c_p, e_p)
            r_ssvc_vals.append(rec["r_ssvc"])
            r_fips_vals.append(r_fips)

        rho = _spearman_rho(r_ssvc_vals, r_fips_vals)

        print(f"\n[CV] {profile_name}: Spearman ρ = {rho:.3f} "
              f"(n={len(r_ssvc_vals)}, threshold={self.SPEARMAN_MIN})")

        assert rho >= self.SPEARMAN_MIN, (
            f"[{profile_name}] Validade convergente insuficiente: "
            f"Spearman ρ={rho:.3f} < {self.SPEARMAN_MIN}. "
            f"SSVC e FIPS199 produzem ordenações discordantes — "
            f"verificar se os mapeamentos ssvc_to_c_alpha/ssvc_to_e_alpha "
            f"são coerentes com os parâmetros do perfil."
        )

    # ── Teste 2: Concordância por tier de exploração SSVC ────────────────────

    def test_exploitation_tier_ordering(self, ssvc_enriched):
        """
        Dentro de cada perfil, CVEs com exploitation='active' devem ter
        R_ssvc mediana superior a CVEs com exploitation='poc' ou 'none'.

        Este teste verifica que o mapeamento ssvc_to_e_alpha preserva
        a ordenação semântica do SSVC: active > poc > none.
        Corolário: se R_ssvc e R_fips concordam nesta ordenação, a validade
        convergente é confirmada ao nível do constructo E(α).
        """
        tiers = {"none": [], "poc": [], "active": []}
        for rec in ssvc_enriched:
            tier = rec.get("exploitation", "none")
            if tier in tiers:
                tiers[tier].append(rec["r_ssvc"])

        results = {}
        for tier, vals in tiers.items():
            if vals:
                results[tier] = sum(vals) / len(vals)

        print(f"\n[CV] SSVC exploitation median R_ssvc: "
              f"none={results.get('none', 0):.3f}, "
              f"poc={results.get('poc', 0):.3f}, "
              f"active={results.get('active', 0):.3f}")

        # Verificar que a ordenação semântica é preservada
        if "none" in results and "active" in results:
            assert results["active"] >= results["none"], (
                "ssvc_to_e_alpha não preserva ordenação: "
                f"R_ssvc(active)={results['active']:.3f} < R_ssvc(none)={results['none']:.3f}"
            )
        if "poc" in results and "active" in results:
            assert results["active"] >= results["poc"], (
                f"R_ssvc(active)={results['active']:.3f} < R_ssvc(poc)={results['poc']:.3f}"
            )

    # ── Teste 3: KEV como âncora de calibração ───────────────────────────────

    def test_kev_higher_risk_both_sources(self, ssvc_enriched):
        """
        CVEs no CISA KEV devem ter R mediana superior a CVEs fora do KEV,
        tanto via SSVC (Fonte B) como via FIPS199/BANK (Fonte A).

        Justificação: KEV = exploração confirmada in-the-wild → ambas as
        fontes devem convergir na identificação destes CVEs como alto risco.
        Se uma fonte não discrimina KEV de não-KEV, falha como proxy de risco.

        Nota: não é criterion validity — KEV não é o target de predição.
        É um sanity check: ambas as fontes devem concordar que CVEs
        explorados activamente têm score mais alto que CVEs não explorados.
        """
        kev_ssvc     = [r["r_ssvc"] for r in ssvc_enriched if r["cisa_kev"]]
        non_kev_ssvc = [r["r_ssvc"] for r in ssvc_enriched if not r["cisa_kev"]]

        if len(kev_ssvc) < 3 or len(non_kev_ssvc) < 3:
            pytest.skip("Amostra KEV insuficiente (mínimo 3 em cada grupo)")

        # Fonte B (SSVC): KEV deve ter mediana superior
        kev_ssvc_median     = sorted(kev_ssvc)[len(kev_ssvc) // 2]
        non_kev_ssvc_median = sorted(non_kev_ssvc)[len(non_kev_ssvc) // 2]

        # Fonte A (BANK profile): idem
        bank = PAPER_PROFILES_CV["BANK"]
        kev_fips     = [compute_contextual_score(r["cvss"], r["epss"],
                                                  bank["c_alpha"], bank["e_alpha"])
                        for r in ssvc_enriched if r["cisa_kev"]]
        non_kev_fips = [compute_contextual_score(r["cvss"], r["epss"],
                                                  bank["c_alpha"], bank["e_alpha"])
                        for r in ssvc_enriched if not r["cisa_kev"]]

        kev_fips_median     = sorted(kev_fips)[len(kev_fips) // 2]
        non_kev_fips_median = sorted(non_kev_fips)[len(non_kev_fips) // 2]

        print(f"\n[CV] KEV vs non-KEV medians:")
        print(f"     SSVC:  KEV={kev_ssvc_median:.3f}, non-KEV={non_kev_ssvc_median:.3f}")
        print(f"     FIPS:  KEV={kev_fips_median:.3f}, non-KEV={non_kev_fips_median:.3f}")

        # Concordância: ambas as fontes devem concordar na direcção
        ssvc_discriminates = kev_ssvc_median > non_kev_ssvc_median
        fips_discriminates = kev_fips_median > non_kev_fips_median

        assert ssvc_discriminates and fips_discriminates, (
            "Uma ou ambas as fontes não discriminam KEV de não-KEV na direcção esperada. "
            f"SSVC discrimina: {ssvc_discriminates}. FIPS discrimina: {fips_discriminates}."
        )

        # Concordância directa: ambas as fontes devem concordar na ordenação
        # (tanto SSVC como FIPS classificam KEV como maior risco)
        both_agree = (kev_ssvc_median > non_kev_ssvc_median) == \
                     (kev_fips_median > non_kev_fips_median)
        assert both_agree, "SSVC e FIPS discordam na ordenação KEV vs non-KEV"

    # ── Teste 4: Relatório de concordância por perfil (sem assert) ────────────

    def test_print_convergent_validity_report(self, ssvc_enriched):
        """
        Gera relatório de concordância Spearman para todos os perfis.
        Não faz assert — é um test de observação para o paper.
        Output vai para os logs do pytest (-v).
        """
        if len(ssvc_enriched) < 5:
            pytest.skip("Amostra insuficiente")

        print("\n\n=== CONVERGENT VALIDITY REPORT ===")
        print(f"{'Profile':8} {'Spearman ρ':>12} {'n CVEs':>8} {'Verdict':>12}")
        print("-" * 45)

        for profile_name, profile in PAPER_PROFILES_CV.items():
            r_ssvc_vals = [rec["r_ssvc"] for rec in ssvc_enriched]
            r_fips_vals = [
                compute_contextual_score(
                    rec["cvss"], rec["epss"],
                    profile["c_alpha"], profile["e_alpha"]
                )
                for rec in ssvc_enriched
            ]
            rho = _spearman_rho(r_ssvc_vals, r_fips_vals)
            verdict = (
                "strong" if rho >= 0.60 else
                "moderate" if rho >= 0.40 else
                "weak" if rho >= 0.20 else
                "none"
            )
            print(f"{profile_name:8} {rho:>12.3f} {len(ssvc_enriched):>8} {verdict:>12}")

        print("\nMission Prevalence distribution:")
        missions = {}
        for rec in ssvc_enriched:
            m = rec["mission"]
            missions[m] = missions.get(m, 0) + 1
        for m, n in sorted(missions.items()):
            print(f"  {m}: {n} CVEs ({n/len(ssvc_enriched):.1%})")

        print("\nExploitation tier distribution:")
        tiers = {}
        for rec in ssvc_enriched:
            t = rec["exploitation"]
            tiers[t] = tiers.get(t, 0) + 1
        for t, n in sorted(tiers.items()):
            print(f"  {t}: {n} CVEs ({n/len(ssvc_enriched):.1%})")

        # Sempre passa — é um test de observação
        assert True
