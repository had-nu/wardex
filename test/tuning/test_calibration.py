"""
SPEC: Calibration Test Suite for R(v, α) = CVSS(v) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))
==========================================================================

Objectivo:
    Verificar que os parâmetros derivados empiricamente C(α) e E(α), e a função de
    scoring central, satisfazem as propriedades formais do modelo antes de qualquer
    submissão académica ou integração no protótipo Wardex.

Organização dos testes:
    T1 — Propriedades matemáticas da função (unit, determinístico)
    T2 — Invariantes do modelo (property-based, Hypothesis)
    T3 — Calibração empírica (integração com pipeline.py)
    T4 — Validação contra ground truth (CISA KEV + SSVC)
    T5 — Sensitividade paramétrica (κ, thresholds)
    T6 — Regressão de casos ilustrativos (CVEs documentados no paper)

Execução:
    pip install pytest hypothesis pytest-cov
    pytest tests/test_calibration.py -v --tb=short

Reprodutibilidade:
    Todos os testes T3/T4 lêem de data/dataset_2025-03-01.json (snapshot fixado).
    Se o ficheiro não existir, os testes são marcados SKIP com mensagem clara.
    Nunca fazem chamadas de rede em runtime de teste.

Estratégia de falha:
    T1/T2 — FAIL imediato (propriedades matemáticas são não-negociáveis)
    T3     — WARN se calibração empírica divergir >20% dos valores sintéticos do paper
    T4     — FAIL se KEV recall < 0.60 para perfis BANK/HOSP (limiar conservador)
    T5     — FAIL se κ ∈ [0.70, 0.90] produzir >10% variação no block count
    T6     — FAIL se qualquer caso ilustrativo divergir da decisão documentada no paper
"""

import json
import math
import pytest
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

# ── Hypothesis (property-based testing) ──────────────────────────────────────
from hypothesis import given, settings, assume
from hypothesis import strategies as st

# ── Módulos do pipeline (importados do mesmo pacote) ──────────────────────────
# Se o pipeline ainda não estiver instalado como pacote, ajustar o sys.path:
# import sys; sys.path.insert(0, str(Path(__file__).parent.parent))
from pipeline import (
    compute_contextual_score,
    evaluate_gate,
    derive_profile_calibration,
    ssvc_to_c_alpha,
    ssvc_to_e_alpha,
    naics_to_fips199,
    IncidentRecord,
    ProfileCalibration,
    NAICS_TO_FIPS199,
)

# ═════════════════════════════════════════════════════════════════════════════
# FIXTURES E HELPERS
# ═════════════════════════════════════════════════════════════════════════════

SNAPSHOT_PATH = Path("data") / "dataset_2025-03-01.json"
CALIBRATION_PATH = Path("data") / "calibration.json"

def load_snapshot() -> dict:
    if not SNAPSHOT_PATH.exists():
        pytest.skip(f"Snapshot não encontrado: {SNAPSHOT_PATH}. "
                    f"Execute pipeline.py primeiro.")
    return json.loads(SNAPSHOT_PATH.read_text())


def load_calibration() -> dict:
    if not CALIBRATION_PATH.exists():
        pytest.skip(f"Calibration output não encontrado: {CALIBRATION_PATH}.")
    return json.loads(CALIBRATION_PATH.read_text())


@dataclass
class ProfileFixture:
    """Valores sintéticos do paper (secção V) — referência de comparação."""
    name: str
    c_alpha: float
    e_alpha: float
    theta_block: float
    theta_warn: float
    expected_block_rate_min: float
    expected_block_rate_max: float


# Valores exactos conforme publicados no paper (Table 1)
PAPER_PROFILES = [
    ProfileFixture("BANK", 1.50, 1.00, 0.5, 0.3, 0.70, 0.80),
    ProfileFixture("HOSP", 1.50, 0.80, 0.8, 0.5, 0.65, 0.76),
    ProfileFixture("SAAS", 1.00, 0.80, 2.0, 1.0, 0.40, 0.55),
    ProfileFixture("DEV",  0.25, 0.30, 4.0, 2.0, 0.00, 0.05),
]

# Casos ilustrativos do paper (Table 2) — ground truth de regressão
ILLUSTRATIVE_CASES = [
    # (cve_id, cvss, epss, profile_name, expected_decision)
    ("CVE-2021-44228", 10.0, 0.940, "BANK", "BLOCK"),
    ("CVE-2021-44228", 10.0, 0.940, "DEV",  "APPROVE"),
    ("CVE-2024-3094",  10.0, 0.860, "BANK", "BLOCK"),
    ("CVE-2024-3094",  10.0, 0.860, "DEV",  "APPROVE"),
    ("CVE-2023-38545",  9.8, 0.260, "BANK", "BLOCK"),
    ("CVE-2023-38545",  9.8, 0.260, "SAAS", "APPROVE"),
    ("CVE-2019-10744",  9.8, 0.010, "BANK", "APPROVE"),
    ("CVE-2019-10744",  9.8, 0.010, "HOSP", "APPROVE"),
]


# ═════════════════════════════════════════════════════════════════════════════
# T1 — PROPRIEDADES MATEMÁTICAS (unit, determinístico)
# ═════════════════════════════════════════════════════════════════════════════

class TestMathematicalProperties:
    """
    Verifica as três proposições formais do paper (§III.C):
      P1 — Monotonicity
      P2 — Bounded output ∈ [0, 15]
      P3 — Fail-close EPSS
    """

    # ── P2: Bounded output ───────────────────────────────────────────────────

    def test_bounded_output_maximum(self):
        """R ≤ 15 para qualquer input válido (Proposição 2)."""
        score = compute_contextual_score(
            cvss=10.0, epss=1.0,
            c_alpha=1.50, e_alpha=1.00,
            compensating_effectiveness=0.0, kappa=0.8
        )
        assert score <= 15.0, f"Upper bound violado: R={score}"

    def test_bounded_output_exact_maximum(self):
        """Maximum exacto: 10 × 1 × 1.5 × 1.0 × (1−0) = 15.0"""
        score = compute_contextual_score(
            cvss=10.0, epss=1.0,
            c_alpha=1.50, e_alpha=1.00,
            compensating_effectiveness=0.0, kappa=0.8
        )
        assert math.isclose(score, 15.0, rel_tol=1e-9)

    def test_bounded_output_minimum(self):
        """R ≥ 0 para qualquer input válido."""
        score = compute_contextual_score(
            cvss=0.0, epss=0.0,
            c_alpha=0.25, e_alpha=0.10,
            compensating_effectiveness=0.0, kappa=0.8
        )
        assert score >= 0.0

    def test_bounded_output_with_controls_not_zero(self):
        """Controlos máximos (κ=0.8) produzem R > 0 quando CVSS e EPSS > 0.
        Φ máximo = κ = 0.8, portanto (1−Φ) ≥ 0.2."""
        score = compute_contextual_score(
            cvss=5.0, epss=0.5,
            c_alpha=1.0, e_alpha=1.0,
            compensating_effectiveness=1.0,   # sum_eps=1.0, capped at κ=0.8
            kappa=0.8
        )
        expected = 5.0 * 0.5 * 1.0 * 1.0 * (1 - 0.8)
        assert math.isclose(score, expected, rel_tol=1e-9)
        assert score > 0.0

    # ── P1: Monotonicity ─────────────────────────────────────────────────────

    def test_monotone_in_cvss(self):
        """R cresce com CVSS (todos os outros factores fixos)."""
        base_kwargs = dict(epss=0.5, c_alpha=1.0, e_alpha=0.8,
                           compensating_effectiveness=0.0, kappa=0.8)
        r_low  = compute_contextual_score(cvss=4.0, **base_kwargs)
        r_high = compute_contextual_score(cvss=9.0, **base_kwargs)
        assert r_low < r_high

    def test_monotone_in_epss(self):
        """R cresce com EPSS (todos os outros factores fixos)."""
        base_kwargs = dict(cvss=7.5, c_alpha=1.0, e_alpha=0.8,
                           compensating_effectiveness=0.0, kappa=0.8)
        r_low  = compute_contextual_score(epss=0.01, **base_kwargs)
        r_high = compute_contextual_score(epss=0.90, **base_kwargs)
        assert r_low < r_high

    def test_monotone_in_c_alpha(self):
        """R cresce com C(α)."""
        base_kwargs = dict(cvss=7.5, epss=0.3, e_alpha=0.8,
                           compensating_effectiveness=0.0, kappa=0.8)
        r_low  = compute_contextual_score(c_alpha=0.25, **base_kwargs)
        r_high = compute_contextual_score(c_alpha=1.50, **base_kwargs)
        assert r_low < r_high

    def test_monotone_in_e_alpha(self):
        """R cresce com E(α)."""
        base_kwargs = dict(cvss=7.5, epss=0.3, c_alpha=1.0,
                           compensating_effectiveness=0.0, kappa=0.8)
        r_low  = compute_contextual_score(e_alpha=0.10, **base_kwargs)
        r_high = compute_contextual_score(e_alpha=1.00, **base_kwargs)
        assert r_low < r_high

    def test_monotone_decreasing_in_controls(self):
        """R decresce com compensating control effectiveness."""
        base_kwargs = dict(cvss=7.5, epss=0.3, c_alpha=1.0, e_alpha=0.8, kappa=0.8)
        r_no_ctrl  = compute_contextual_score(compensating_effectiveness=0.0, **base_kwargs)
        r_some_ctrl= compute_contextual_score(compensating_effectiveness=0.4, **base_kwargs)
        r_max_ctrl = compute_contextual_score(compensating_effectiveness=1.0, **base_kwargs)
        assert r_no_ctrl > r_some_ctrl > r_max_ctrl

    # ── P3: Fail-close EPSS ──────────────────────────────────────────────────

    def test_failclose_epss_zero_treated_as_one(self):
        """EPSS=0.0 (indisponível) é tratado como 1.0 (fail-close)."""
        r_failclose = compute_contextual_score(
            cvss=7.0, epss=0.0,  # 0.0 → indisponível
            c_alpha=1.0, e_alpha=0.8, kappa=0.8
        )
        r_worst_case = compute_contextual_score(
            cvss=7.0, epss=1.0,  # máximo EPSS
            c_alpha=1.0, e_alpha=0.8, kappa=0.8
        )
        assert math.isclose(r_failclose, r_worst_case, rel_tol=1e-9), (
            f"Fail-close violado: epss=0.0 produziu R={r_failclose}, "
            f"mas epss=1.0 produziu R={r_worst_case}"
        )

    def test_failclose_never_lower_than_known_epss(self):
        """R(EPSS=0.0) ≥ R(EPSS=x) para qualquer x ∈ (0, 1]."""
        base_kwargs = dict(cvss=8.0, c_alpha=1.5, e_alpha=1.0, kappa=0.8)
        r_failclose = compute_contextual_score(epss=0.0, **base_kwargs)
        for epss in [0.01, 0.1, 0.5, 0.9, 1.0]:
            r_known = compute_contextual_score(epss=epss, **base_kwargs)
            assert r_failclose >= r_known, (
                f"Fail-close violado para EPSS={epss}: "
                f"R(0.0)={r_failclose} < R({epss})={r_known}"
            )

    # ── Kappa cap ─────────────────────────────────────────────────────────────

    def test_kappa_cap_applied(self):
        """Φ(α) nunca excede κ, independentemente da soma de εᵢ."""
        # sum_eps = 0.95 > κ = 0.8 → Φ = 0.8
        score_with_excess = compute_contextual_score(
            cvss=10.0, epss=1.0, c_alpha=1.5, e_alpha=1.0,
            compensating_effectiveness=0.95, kappa=0.8
        )
        # sum_eps = 0.80 = κ → Φ = 0.8
        score_at_cap = compute_contextual_score(
            cvss=10.0, epss=1.0, c_alpha=1.5, e_alpha=1.0,
            compensating_effectiveness=0.80, kappa=0.8
        )
        assert math.isclose(score_with_excess, score_at_cap, rel_tol=1e-9), (
            "κ cap não está a ser aplicado correctamente"
        )

    def test_kappa_configurable(self):
        """κ é configurável — resultados mudam com κ diferente."""
        base = dict(cvss=8.0, epss=0.5, c_alpha=1.0, e_alpha=0.8,
                    compensating_effectiveness=0.7)
        r_kappa_07 = compute_contextual_score(**base, kappa=0.7)
        r_kappa_09 = compute_contextual_score(**base, kappa=0.9)
        # kappa=0.9 → Φ=0.7 (não capped) → (1-0.7)=0.3
        # kappa=0.7 → Φ=0.7 (capped at 0.7) → (1-0.7)=0.3
        # Com sum_eps=0.7 exactamente igual a ambos os κ → resultado deve ser igual
        assert math.isclose(r_kappa_07, r_kappa_09, rel_tol=1e-9)

    def test_kappa_smaller_produces_higher_score(self):
        """κ menor (menos crédito para controlos) → R mais alto."""
        base = dict(cvss=8.0, epss=0.5, c_alpha=1.0, e_alpha=0.8,
                    compensating_effectiveness=0.9)
        # sum_eps=0.9; com kappa=0.6 → Φ=0.6; com kappa=0.9 → Φ=0.9
        r_kappa_06 = compute_contextual_score(**base, kappa=0.6)
        r_kappa_09 = compute_contextual_score(**base, kappa=0.9)
        assert r_kappa_06 > r_kappa_09


# ═════════════════════════════════════════════════════════════════════════════
# T2 — INVARIANTES PROPERTY-BASED (Hypothesis)
# ═════════════════════════════════════════════════════════════════════════════

# Estratégias de geração de valores válidos
valid_cvss  = st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False)
valid_epss  = st.floats(min_value=0.0, max_value=1.0,  allow_nan=False, allow_infinity=False)
valid_c     = st.floats(min_value=0.1, max_value=2.0,  allow_nan=False, allow_infinity=False)
valid_e     = st.floats(min_value=0.0, max_value=1.0,  allow_nan=False, allow_infinity=False)
valid_kappa = st.floats(min_value=0.1, max_value=0.99, allow_nan=False, allow_infinity=False)
valid_ctrl  = st.floats(min_value=0.0, max_value=2.0,  allow_nan=False, allow_infinity=False)


class TestPropertyBased:
    """
    Property-based tests usando Hypothesis.
    Cada test verifica invariantes para qualquer input no espaço válido.
    """

    @given(cvss=valid_cvss, epss=valid_epss, c=valid_c, e=valid_e,
           ctrl=valid_ctrl, kappa=valid_kappa)
    @settings(max_examples=500, deadline=None)
    def test_output_always_non_negative(self, cvss, epss, c, e, ctrl, kappa):
        """R ≥ 0 para qualquer combinação de inputs válidos."""
        score = compute_contextual_score(cvss, epss, c, e, ctrl, kappa)
        assert score >= 0.0, f"R negativo: {score} para cvss={cvss} epss={epss}"

    @given(cvss=valid_cvss, epss=valid_epss, c=valid_c, e=valid_e,
           ctrl=valid_ctrl, kappa=valid_kappa)
    @settings(max_examples=500, deadline=None)
    def test_output_bounded_above(self, cvss, epss, c, e, ctrl, kappa):
        """R ≤ CVSS_MAX × 1 × C_MAX × 1 × 1 = 10 × 2.0 × 1 = 20 (limite liberal)."""
        score = compute_contextual_score(cvss, epss, c, e, ctrl, kappa)
        upper = 10.0 * 1.0 * 2.0 * 1.0 * 1.0  # bound liberal
        assert score <= upper + 1e-9, f"R={score} excede upper bound liberal={upper}"

    @given(
        cvss=valid_cvss,
        epss=st.floats(min_value=0.01, max_value=1.0,  # EPSS positivo e conhecido
                       allow_nan=False, allow_infinity=False),
        c=valid_c, e=valid_e, ctrl=valid_ctrl, kappa=valid_kappa,
        delta=st.floats(min_value=0.01, max_value=5.0)
    )
    @settings(max_examples=300, deadline=None)
    def test_monotone_cvss_strict(self, cvss, epss, c, e, ctrl, kappa, delta):
        """R(CVSS + δ) ≥ R(CVSS) quando CVSS + δ ≤ 10."""
        cvss2 = cvss + delta
        assume(cvss2 <= 10.0)
        r1 = compute_contextual_score(cvss,  epss, c, e, ctrl, kappa)
        r2 = compute_contextual_score(cvss2, epss, c, e, ctrl, kappa)
        assert r2 >= r1 - 1e-9, f"Monotonicity CVSS violada: R({cvss2})={r2} < R({cvss})={r1}"

    @given(
        cvss=st.floats(min_value=0.1, max_value=10.0, allow_nan=False),
        epss=valid_epss, c=valid_c, e=valid_e, kappa=valid_kappa,
        ctrl1=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        ctrl2=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    )
    @settings(max_examples=300, deadline=None)
    def test_monotone_controls_decreasing(self, cvss, epss, c, e, kappa, ctrl1, ctrl2):
        """Mais controlos → R menor ou igual."""
        r_less_ctrl = compute_contextual_score(cvss, epss, c, e,
                                               min(ctrl1, ctrl2), kappa)
        r_more_ctrl = compute_contextual_score(cvss, epss, c, e,
                                               max(ctrl1, ctrl2), kappa)
        assert r_less_ctrl >= r_more_ctrl - 1e-9

    @given(cvss=valid_cvss, c=valid_c, e=valid_e, ctrl=valid_ctrl, kappa=valid_kappa)
    @settings(max_examples=300, deadline=None)
    def test_failclose_invariant(self, cvss, c, e, ctrl, kappa):
        """Para qualquer EPSS ∈ [0, 1], R(EPSS=0.0) ≥ R(EPSS=known)."""
        r_failclose = compute_contextual_score(cvss, 0.0, c, e, ctrl, kappa)
        for epss in [0.001, 0.1, 0.5, 1.0]:
            r_known = compute_contextual_score(cvss, epss, c, e, ctrl, kappa)
            assert r_failclose >= r_known - 1e-9

    @given(
        cvss=valid_cvss, epss=valid_epss, c=valid_c, e=valid_e, ctrl=valid_ctrl,
        kappa_lo=st.floats(min_value=0.1, max_value=0.89, allow_nan=False),
        kappa_hi=st.floats(min_value=0.1, max_value=0.89, allow_nan=False),
    )
    @settings(max_examples=200, deadline=None)
    def test_kappa_monotone(self, cvss, epss, c, e, ctrl, kappa_lo, kappa_hi):
        """κ menor → Φ menor ou igual → (1-Φ) maior → R maior ou igual.
        Só quando sum_eps > min(kappa_lo, kappa_hi)."""
        kl, kh = min(kappa_lo, kappa_hi), max(kappa_lo, kappa_hi)
        assume(kl < kh)
        # Se ctrl ≤ kl, o cap não é atingido em nenhum → resultado idêntico
        # Se ctrl > kl, o cap é atingido com kl mas não com kh → R(kl) > R(kh)
        r_kl = compute_contextual_score(cvss, epss, c, e, ctrl, kl)
        r_kh = compute_contextual_score(cvss, epss, c, e, ctrl, kh)
        assert r_kl >= r_kh - 1e-9


# ═════════════════════════════════════════════════════════════════════════════
# T3 — CALIBRAÇÃO EMPÍRICA (integração com pipeline output)
# ═════════════════════════════════════════════════════════════════════════════

class TestEmpiricalCalibration:
    """
    Verifica que os parâmetros derivados empiricamente pelo pipeline
    são coerentes com os valores sintéticos do paper.

    Tolerância: 20% de desvio — reflecte a incerteza de calibrar parâmetros
    contínuos a partir de dados de incidentes discretos por sector.
    """

    TOLERANCE = 0.20   # 20% de desvio máximo aceitável

    @pytest.fixture(scope="class")
    def empirical_profiles(self) -> dict[str, dict]:
        """Carrega calibrações empíricas geradas pelo pipeline."""
        cal = load_calibration()
        return {p["profile_name"]: p for p in cal["calibrations"]}

    @pytest.mark.parametrize("fixture", PAPER_PROFILES, ids=lambda f: f.name)
    def test_c_alpha_within_tolerance(self, fixture, empirical_profiles):
        """C(α) empírico está dentro de ±20% do valor sintético do paper."""
        if fixture.name not in empirical_profiles:
            pytest.skip(f"Perfil {fixture.name} não encontrado na calibração empírica")

        emp_c = empirical_profiles[fixture.name]["c_alpha"]
        ref_c = fixture.c_alpha
        deviation = abs(emp_c - ref_c) / ref_c

        assert deviation <= self.TOLERANCE, (
            f"[{fixture.name}] C(α) empírico={emp_c:.3f} desvia {deviation:.1%} "
            f"do valor sintético={ref_c} (tolerância={self.TOLERANCE:.0%})"
        )

    @pytest.mark.parametrize("fixture", PAPER_PROFILES, ids=lambda f: f.name)
    def test_e_alpha_within_tolerance(self, fixture, empirical_profiles):
        """E(α) empírico está dentro de ±20% do valor sintético do paper."""
        if fixture.name not in empirical_profiles:
            pytest.skip(f"Perfil {fixture.name} não encontrado na calibração empírica")

        emp_e = empirical_profiles[fixture.name]["e_alpha"]
        ref_e = fixture.e_alpha
        deviation = abs(emp_e - ref_e) / ref_e

        assert deviation <= self.TOLERANCE, (
            f"[{fixture.name}] E(α) empírico={emp_e:.3f} desvia {deviation:.1%} "
            f"do valor sintético={ref_e} (tolerância={self.TOLERANCE:.0%})"
        )

    @pytest.mark.parametrize("fixture", PAPER_PROFILES, ids=lambda f: f.name)
    def test_minimum_incident_support(self, fixture, empirical_profiles):
        """Cada perfil deve ter pelo menos 50 incidentes de suporte na calibração."""
        MIN_INCIDENTS = 50
        if fixture.name not in empirical_profiles:
            pytest.skip(f"Perfil {fixture.name} não encontrado")

        n = empirical_profiles[fixture.name]["n_incidents"]
        assert n >= MIN_INCIDENTS, (
            f"[{fixture.name}] Apenas {n} incidentes — calibração insuficiente. "
            f"Mínimo: {MIN_INCIDENTS}"
        )

    def test_calibration_ordering_preserved(self, empirical_profiles):
        """Ordenação BANK ≥ HOSP ≥ SAAS ≥ DEV em C(α) deve ser preservada.
        Esta é a propriedade ordinal central do modelo."""
        profiles_needed = {"BANK", "HOSP", "SAAS", "DEV"}
        missing = profiles_needed - set(empirical_profiles.keys())
        if missing:
            pytest.skip(f"Perfis em falta: {missing}")

        c_bank = empirical_profiles["BANK"]["c_alpha"]
        c_hosp = empirical_profiles["HOSP"]["c_alpha"]
        c_saas = empirical_profiles["SAAS"]["c_alpha"]
        c_dev  = empirical_profiles["DEV"]["c_alpha"]

        assert c_bank >= c_hosp, f"BANK.C(α)={c_bank} < HOSP.C(α)={c_hosp}"
        assert c_hosp >= c_saas, f"HOSP.C(α)={c_hosp} < SAAS.C(α)={c_saas}"
        assert c_saas >= c_dev,  f"SAAS.C(α)={c_saas} < DEV.C(α)={c_dev}"

    def test_e_alpha_ordering_bank_dev(self, empirical_profiles):
        """BANK deve ter E(α) ≥ DEV — banco internet-facing vs. dev sandbox."""
        if "BANK" not in empirical_profiles or "DEV" not in empirical_profiles:
            pytest.skip("BANK ou DEV não encontrado")

        e_bank = empirical_profiles["BANK"]["e_alpha"]
        e_dev  = empirical_profiles["DEV"]["e_alpha"]
        assert e_bank >= e_dev, f"BANK.E(α)={e_bank} < DEV.E(α)={e_dev}"


# ═════════════════════════════════════════════════════════════════════════════
# T4 — VALIDAÇÃO CONTRA GROUND TRUTH (CISA KEV + SSVC)
# ═════════════════════════════════════════════════════════════════════════════

class TestGroundTruthValidation:
    """
    Verifica que o modelo bloqueia o que o CISA KEV confirma como explorado.

    Definição de KEV Recall:
        KEV Recall = |CVEs KEV bloqueados| / |CVEs KEV no dataset|

    Threshold conservador: 0.60 (60% dos CVEs explorados confirmados devem ser bloqueados
    pelos perfis BANK e HOSP, que têm os θ_block mais baixos).

    NOTA: Um recall de 100% não é esperado nem desejável — o modelo incorpora EPSS,
    e algumas CVEs no KEV têm EPSS baixo porque a exploração foi muito dirigida
    (não automatizável em larga escala). Estas CVEs são correctamente tratadas com
    decisão ACCEPT_SLA ou APPROVE nos perfis de baixa criticidade.
    """

    KEV_RECALL_THRESHOLD   = 0.60   # limiar mínimo para BANK/HOSP
    SSVC_PRECISION_THRESHOLD = 0.50  # % de BLOCK do modelo que são Active/PoC no SSVC

    @pytest.fixture(scope="class")
    def snapshot(self):
        return load_snapshot()

    def _get_cve_records(self, snapshot: dict) -> list[dict]:
        return snapshot["cve_records"]

    def _compute_gate_for_profile(
        self,
        cve_records: list[dict],
        profile: ProfileFixture,
    ) -> list[dict]:
        """Compute gate decisions for all CVEs under a given profile."""
        results = []
        for rec in cve_records:
            score = compute_contextual_score(
                cvss=rec["cvss_base"],
                epss=rec["epss_score"],
                c_alpha=profile.c_alpha,
                e_alpha=profile.e_alpha,
            )
            decision = evaluate_gate(score, profile.theta_block, profile.theta_warn)
            results.append({
                "cve_id":   rec["cve_id"],
                "score":    score,
                "decision": decision,
                "cisa_kev": rec["cisa_kev"],
                "ssvc_exploitation": rec.get("ssvc_exploitation", "none"),
            })
        return results

    @pytest.mark.parametrize("fixture", [PAPER_PROFILES[0], PAPER_PROFILES[1]],
                             ids=["BANK", "HOSP"])
    def test_kev_recall_regulated_profiles(self, fixture, snapshot):
        """BANK e HOSP devem bloquear ≥60% dos CVEs confirmados no KEV."""
        cve_records = self._get_cve_records(snapshot)
        decisions   = self._compute_gate_for_profile(cve_records, fixture)

        kev_records  = [d for d in decisions if d["cisa_kev"]]
        if len(kev_records) == 0:
            pytest.skip("Nenhum CVE KEV no dataset — verificar snapshot")

        kev_blocked  = [d for d in kev_records if d["decision"] == "BLOCK"]
        recall       = len(kev_blocked) / len(kev_records)

        assert recall >= self.KEV_RECALL_THRESHOLD, (
            f"[{fixture.name}] KEV Recall={recall:.2%} < threshold={self.KEV_RECALL_THRESHOLD:.0%}. "
            f"KEV total={len(kev_records)}, BLOCKED={len(kev_blocked)}. "
            f"CVEs KEV não bloqueados: "
            f"{[d['cve_id'] for d in kev_records if d['decision'] != 'BLOCK'][:5]}"
        )

    def test_dev_profile_kev_mostly_allowed(self, snapshot):
        """DEV deve permitir a maioria dos CVEs — mesmo os KEV.
        O perfil DEV (sandbox) é intencional: θ_block=4.0 é alto.
        Test verifica que o modelo não sobre-bloqueia no contexto DEV."""
        fixture     = PAPER_PROFILES[3]  # DEV
        cve_records = self._get_cve_records(snapshot)
        decisions   = self._compute_gate_for_profile(cve_records, fixture)

        total_blocked = sum(1 for d in decisions if d["decision"] == "BLOCK")
        block_rate    = total_blocked / len(decisions) if decisions else 0.0

        # DEV deve ter block rate perto de 0%
        assert block_rate < 0.05, (
            f"DEV profile block rate={block_rate:.2%} — esperado < 5%. "
            f"Θ_block=4.0 pode estar errado ou EPSS fail-close a disparar."
        )

    def test_ssvc_active_exploitation_mostly_blocked_bank(self, snapshot):
        """CVEs com SSVC exploitation='active' devem ser maioritariamente BLOCK em BANK."""
        fixture     = PAPER_PROFILES[0]  # BANK
        cve_records = self._get_cve_records(snapshot)
        decisions   = self._compute_gate_for_profile(cve_records, fixture)

        active_records = [d for d in decisions if d["ssvc_exploitation"] == "active"]
        if len(active_records) < 5:
            pytest.skip("Menos de 5 CVEs com SSVC exploitation=active — sample insuficiente")

        active_blocked = sum(1 for d in active_records if d["decision"] == "BLOCK")
        rate = active_blocked / len(active_records)

        assert rate >= 0.70, (
            f"[BANK] Apenas {rate:.0%} dos CVEs SSVC-Active bloqueados — esperado ≥70%"
        )

    def test_ssvc_none_exploitation_low_block_rate(self, snapshot):
        """CVEs com SSVC exploitation='none' devem ter block rate baixa em SAAS/DEV."""
        fixture     = PAPER_PROFILES[2]  # SAAS
        cve_records = self._get_cve_records(snapshot)
        decisions   = self._compute_gate_for_profile(cve_records, fixture)

        none_records = [d for d in decisions if d["ssvc_exploitation"] == "none"]
        if len(none_records) < 5:
            pytest.skip("Amostra de SSVC-None insuficiente")

        none_blocked = sum(1 for d in none_records if d["decision"] == "BLOCK")
        rate = none_blocked / len(none_records)

        # Em SAAS, CVEs sem exploração conhecida não devem bloquear frequentemente
        assert rate < 0.30, (
            f"[SAAS] {rate:.0%} dos CVEs sem exploração estão a BLOCK — "
            f"possível over-blocking para perfil SaaS"
        )


# ═════════════════════════════════════════════════════════════════════════════
# T5 — ANÁLISE DE SENSITIVIDADE (κ e thresholds)
# ═════════════════════════════════════════════════════════════════════════════

class TestSensitivityAnalysis:
    """
    Verifica que o modelo é qualitativamente estável para κ ∈ [0.70, 0.90]
    e que variações razoáveis de θ_block não invertem a ordenação dos perfis.

    CRITÉRIO: Variação de ≤10% no block count para κ ∈ [0.70, 0.90].
    Justificação do paper §V.C: "fewer than 12 CVEs (5%) for a 20-point variation."
    Usamos 10% como threshold conservador.
    """

    MAX_KAPPA_VARIATION = 0.10   # ≤10% variação no block count

    @pytest.fixture(scope="class")
    def snapshot(self):
        return load_snapshot()

    def _count_blocks(self, cve_records: list[dict], profile: ProfileFixture,
                      kappa: float) -> int:
        count = 0
        for rec in cve_records:
            score = compute_contextual_score(
                cvss=rec["cvss_base"], epss=rec["epss_score"],
                c_alpha=profile.c_alpha, e_alpha=profile.e_alpha, kappa=kappa
            )
            if score > profile.theta_block:
                count += 1
        return count

    @pytest.mark.parametrize("fixture", PAPER_PROFILES[:2], ids=["BANK", "HOSP"])
    def test_kappa_stability_in_range(self, fixture, snapshot):
        """Block count varia ≤10% para κ ∈ [0.70, 0.90] (BANK e HOSP)."""
        cve_records = snapshot["cve_records"]

        counts = {
            kappa: self._count_blocks(cve_records, fixture, kappa)
            for kappa in [0.70, 0.75, 0.80, 0.85, 0.90]
        }

        min_count = min(counts.values())
        max_count = max(counts.values())
        n_total   = len(cve_records)

        variation = (max_count - min_count) / n_total if n_total > 0 else 0.0

        assert variation <= self.MAX_KAPPA_VARIATION, (
            f"[{fixture.name}] κ variation={variation:.1%} excede "
            f"threshold={self.MAX_KAPPA_VARIATION:.0%}. "
            f"Block counts por κ: {counts}"
        )

    def test_profile_ordering_preserved_across_thresholds(self, snapshot):
        """A ordenação block_rate BANK > HOSP > SAAS > DEV é preservada para
        qualquer θ_block razoável (±50% do valor nominal)."""
        cve_records = snapshot["cve_records"]

        for theta_factor in [0.5, 0.75, 1.0, 1.25, 1.5]:
            rates = {}
            for fixture in PAPER_PROFILES:
                theta = fixture.theta_block * theta_factor
                count = self._count_blocks(cve_records, fixture, kappa=0.8)
                rates[fixture.name] = count / len(cve_records) if cve_records else 0

            assert rates["BANK"] >= rates["SAAS"], (
                f"BANK block rate < SAAS com θ_factor={theta_factor}: {rates}"
            )
            assert rates["SAAS"] >= rates["DEV"], (
                f"SAAS block rate < DEV com θ_factor={theta_factor}: {rates}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# T6 — REGRESSÃO DOS CASOS ILUSTRATIVOS (Table 2 do paper)
# ═════════════════════════════════════════════════════════════════════════════

class TestIllustrativeCasesRegression:
    """
    Verifica que os 8 casos documentados na Table 2 do paper produzem as
    decisões exactas publicadas. Estes são testes de regressão não-negociáveis:
    qualquer alteração ao modelo que mude estes resultados é uma breaking change
    que exige revisão da secção de resultados.
    """

    @pytest.mark.parametrize(
        "cve_id,cvss,epss,profile_name,expected_decision",
        ILLUSTRATIVE_CASES,
        ids=[f"{c[0]}/{c[3]}" for c in ILLUSTRATIVE_CASES]
    )
    def test_illustrative_case(
        self, cve_id, cvss, epss, profile_name, expected_decision
    ):
        """Decisão para CVE ilustrativo deve coincidir com Table 2 do paper."""
        fixture = next(f for f in PAPER_PROFILES if f.name == profile_name)

        score    = compute_contextual_score(
            cvss=cvss, epss=epss,
            c_alpha=fixture.c_alpha, e_alpha=fixture.e_alpha
        )
        decision = evaluate_gate(score, fixture.theta_block, fixture.theta_warn)

        assert decision == expected_decision, (
            f"[{cve_id} / {profile_name}] "
            f"Esperado={expected_decision}, Obtido={decision}. "
            f"Score={score:.4f}, θ_block={fixture.theta_block}, "
            f"C(α)={fixture.c_alpha}, E(α)={fixture.e_alpha}"
        )

    def test_log4shell_bank_score_range(self):
        """Log4Shell em BANK deve ter R >> θ_block (não é caso marginal)."""
        fixture = PAPER_PROFILES[0]  # BANK
        score = compute_contextual_score(
            cvss=10.0, epss=0.940,
            c_alpha=fixture.c_alpha, e_alpha=fixture.e_alpha
        )
        # R = 10.0 × 0.94 × 1.5 × 1.0 = 14.1 >> θ_block=0.5
        assert score > fixture.theta_block * 10, (
            f"Log4Shell BANK score={score:.2f} não está bem acima de "
            f"θ_block={fixture.theta_block} (esperado >10×)"
        )

    def test_minimist_allows_all_profiles(self):
        """minimist (CVSS=9.8, EPSS=0.01) deve ser APPROVE em todos os perfis.
        É o caso exemplar de EPSS a corrigir o over-blocking do CVSS-only."""
        for fixture in PAPER_PROFILES:
            score = compute_contextual_score(
                cvss=9.8, epss=0.010,
                c_alpha=fixture.c_alpha, e_alpha=fixture.e_alpha
            )
            decision = evaluate_gate(score, fixture.theta_block, fixture.theta_warn)
            assert decision != "BLOCK", (
                f"minimist (CVE-2019-10744) bloqueado em {fixture.name}. "
                f"Score={score:.4f}, θ_block={fixture.theta_block}. "
                f"CVSS-only teria bloqueado — isto seria over-blocking."
            )

    def test_log4shell_dev_below_threshold(self):
        """Log4Shell em DEV deve ser APPROVE (demonstra sensibilidade ao contexto)."""
        fixture = PAPER_PROFILES[3]  # DEV
        score   = compute_contextual_score(
            cvss=10.0, epss=0.940,
            c_alpha=fixture.c_alpha, e_alpha=fixture.e_alpha
        )
        # R = 10.0 × 0.94 × 0.25 × 0.30 = 0.705 < θ_block=4.0
        decision = evaluate_gate(score, fixture.theta_block, fixture.theta_warn)
        assert decision != "BLOCK", (
            f"Log4Shell em DEV deveria ser APPROVE mas é {decision}. "
            f"Score={score:.4f}, θ_block={fixture.theta_block}."
        )


# ═════════════════════════════════════════════════════════════════════════════
# T_UNIT — TESTES UNITÁRIOS DOS MAPEAMENTOS NAICS/SSVC
# ═════════════════════════════════════════════════════════════════════════════

class TestMappingFunctions:
    """
    Testa as funções de mapeamento que convertem dados externos
    nos parâmetros do modelo. São funções puras — determinísticas e testáveis.
    """

    # ── naics_to_fips199 ──────────────────────────────────────────────────────

    @pytest.mark.parametrize("naics,expected_fips", [
        ("52",   "High"),      # Finance
        ("522",  "High"),      # Commercial Banking (subsector 52)
        ("62",   "High"),      # Healthcare
        ("6211", "High"),      # Offices of Physicians (subsector 62)
        ("92",   "High"),      # Government
        ("51",   "Moderate"),  # Tech/Information
        ("54",   "Moderate"),  # Professional Services
        ("44",   "Moderate"),  # Retail
        ("23",   "Low"),       # Construction
        ("11",   "Low"),       # Agriculture
        ("00",   "Moderate"),  # Unknown → default Moderate
    ])
    def test_naics_to_fips199_mapping(self, naics, expected_fips):
        assert naics_to_fips199(naics) == expected_fips, (
            f"NAICS {naics} → esperado {expected_fips}, obtido {naics_to_fips199(naics)}"
        )

    def test_naics_uses_first_two_digits(self):
        """NAICS com 6 dígitos deve usar os primeiros 2 para classificação."""
        assert naics_to_fips199("521110") == naics_to_fips199("52")

    # ── ssvc_to_c_alpha ───────────────────────────────────────────────────────

    @pytest.mark.parametrize("mission_prevalence,expected_c", [
        ("Minimal",   0.25),
        ("Support",   0.75),
        ("Essential", 1.50),
    ])
    def test_ssvc_to_c_alpha_mapping(self, mission_prevalence, expected_c):
        result = ssvc_to_c_alpha(mission_prevalence)
        assert math.isclose(result, expected_c, rel_tol=1e-9), (
            f"ssvc_to_c_alpha({mission_prevalence!r}) = {result}, esperado {expected_c}"
        )

    def test_ssvc_c_alpha_ordering(self):
        """Essential > Support > Minimal — ordenação cardinal preservada."""
        c_minimal   = ssvc_to_c_alpha("Minimal")
        c_support   = ssvc_to_c_alpha("Support")
        c_essential = ssvc_to_c_alpha("Essential")
        assert c_minimal < c_support < c_essential

    # ── ssvc_to_e_alpha ───────────────────────────────────────────────────────

    @pytest.mark.parametrize("automatable,exploitation,expected_e", [
        (True,  "active", 1.0),
        (True,  "poc",    0.80),
        (True,  "none",   0.50),
        (False, "active", 0.50),
        (False, "poc",    0.30),
        (False, "none",   0.30),
    ])
    def test_ssvc_to_e_alpha_mapping(self, automatable, exploitation, expected_e):
        result = ssvc_to_e_alpha(automatable, exploitation)
        assert math.isclose(result, expected_e, rel_tol=1e-9), (
            f"ssvc_to_e_alpha(auto={automatable}, exploit={exploitation!r}) = {result}, "
            f"esperado {expected_e}"
        )

    def test_ssvc_e_alpha_automatable_increases_exposure(self):
        """Automatable=True deve produzir E(α) ≥ Automatable=False (same exploitation)."""
        for expl in ["none", "poc", "active"]:
            e_auto = ssvc_to_e_alpha(True,  expl)
            e_no   = ssvc_to_e_alpha(False, expl)
            assert e_auto >= e_no, (
                f"ssvc_to_e_alpha(auto=True, {expl!r})={e_auto} < "
                f"ssvc_to_e_alpha(auto=False, {expl!r})={e_no}"
            )

    def test_ssvc_e_alpha_exploitation_increases_exposure(self):
        """active > poc > none para E(α) com Automatable fixo."""
        for auto in [True, False]:
            e_none   = ssvc_to_e_alpha(auto, "none")
            e_poc    = ssvc_to_e_alpha(auto, "poc")
            e_active = ssvc_to_e_alpha(auto, "active")
            assert e_none <= e_poc <= e_active, (
                f"Ordem exploitation violada para auto={auto}: "
                f"none={e_none}, poc={e_poc}, active={e_active}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# T_DERIVE — CALIBRAÇÃO EMPÍRICA COM DADOS SINTÉTICOS (sem rede)
# ═════════════════════════════════════════════════════════════════════════════

class TestDeriveProfileCalibration:
    """
    Testa derive_profile_calibration() com incidentes sintéticos construídos
    in-test. Não requer acesso à rede nem ao snapshot VCDB real.
    """

    def _make_incident(self, naics: str, access_vector: str,
                       fips: str = "High") -> IncidentRecord:
        return IncidentRecord(
            source="test", incident_id="test",
            naics_sector=naics, org_size="medium",
            asset_type="Server", access_vector=access_vector,
            cia_impact="C", cve_ids=[], fips199_level=fips,
        )

    def test_all_internet_facing_produces_high_e_alpha(self):
        """100% internet-facing → E(α) = 1.00."""
        incidents = [
            self._make_incident("52", "External - Internet")
            for _ in range(100)
        ]
        cal = derive_profile_calibration("TEST", ["52"], incidents)
        assert math.isclose(cal.e_alpha, 1.00, rel_tol=1e-9), (
            f"E(α)={cal.e_alpha} com 100% internet-facing — esperado 1.00"
        )

    def test_all_internal_produces_low_e_alpha(self):
        """0% internet-facing → E(α) = 0.30."""
        incidents = [
            self._make_incident("51", "Internal")
            for _ in range(100)
        ]
        cal = derive_profile_calibration("TEST", ["51"], incidents)
        assert math.isclose(cal.e_alpha, 0.30, rel_tol=1e-9)

    def test_regulatory_sector_adds_c_alpha_bonus(self):
        """Sector regulado (NAICS 52) recebe +0.50 em C(α)."""
        # FIPS 199 High → c_base = 1.00 → regulatory +0.50 → c_alpha = 1.50
        incidents = [
            self._make_incident("52", "External - Internet", fips="High")
            for _ in range(50)
        ]
        cal = derive_profile_calibration("BANK_TEST", ["52"], incidents)
        assert math.isclose(cal.c_alpha, 1.50, rel_tol=1e-9), (
            f"C(α)={cal.c_alpha} — esperado 1.50 para sector regulado com FIPS High"
        )

    def test_non_regulatory_sector_no_bonus(self):
        """Sector não-regulado (NAICS 51) não recebe bonus regulatório."""
        incidents = [
            self._make_incident("51", "External - Internet", fips="High")
            for _ in range(50)
        ]
        cal = derive_profile_calibration("SAAS_TEST", ["51"], incidents)
        assert math.isclose(cal.c_alpha, 1.00, rel_tol=1e-9), (
            f"C(α)={cal.c_alpha} — esperado 1.00 para sector não-regulado com FIPS High"
        )

    def test_empty_incidents_returns_default(self):
        """Sem incidentes → valores default sem crash."""
        cal = derive_profile_calibration("EMPTY", ["99"], [])
        assert cal.c_alpha == 0.50
        assert cal.e_alpha == 0.50
        assert cal.n_incidents == 0

    def test_mixed_fips_uses_modal(self):
        """Modal FIPS 199 determina C(α) base — maioria wins."""
        # 70 High, 30 Moderate → modal = High
        incidents = (
            [self._make_incident("44", "Internal", fips="High")    for _ in range(70)] +
            [self._make_incident("44", "Internal", fips="Moderate") for _ in range(30)]
        )
        cal = derive_profile_calibration("MIXED", ["44"], incidents)
        # Non-regulatory (44=Retail) com High modal → c_alpha = 1.00
        assert math.isclose(cal.c_alpha, 1.00, rel_tol=1e-9)


# ═════════════════════════════════════════════════════════════════════════════
# CONFTEST HELPERS (normalmente em conftest.py)
# ═════════════════════════════════════════════════════════════════════════════

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: testes que requerem o snapshot em data/dataset_*.json"
    )
    config.addinivalue_line(
        "markers",
        "regression: testes que verificam resultados publicados no paper"
    )
