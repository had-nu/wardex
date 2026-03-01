#!/usr/bin/env bash
# run-all-scenarios.sh
#
# Run the full Wardex PoC locally without GitHub Actions.
# Requires: Go >= 1.22
#
# Usage:
#   export WARDEX_HMAC_SECRET="your-secret-here"
#   chmod +x run-all-scenarios.sh
#   ./run-all-scenarios.sh

set -euo pipefail

export WARDEX_ACCEPT_SECRET="wardex-poc-secret-key-256-bits!!"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# ── Helpers ──────────────────────────────────────────────────────────────────
header()  { echo -e "\n${BLUE}══════════════════════════════════════════${NC}"; \
            echo -e "${BLUE}  $1${NC}"; \
            echo -e "${BLUE}══════════════════════════════════════════${NC}"; }
ok()      { echo -e "${GREEN}[PASS] $1${NC}"; }
fail()    { echo -e "${RED}[FAIL] $1${NC}"; }
info()    { echo -e "${YELLOW}[INFO] $1${NC}"; }

# ── Resolve paths relative to this script ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
POC_DIR="${SCRIPT_DIR}"

WARDEX_CONFIG="${POC_DIR}/wardex-config.yaml"
CONTROLS="${POC_DIR}/controls.yaml"

PASS=0
FAIL=0

# ── Build wardex from source ─────────────────────────────────────────────────
header "Building wardex from source"
cd "${REPO_ROOT}"
go build -o bin/wardex .
WARDEX="${REPO_ROOT}/bin/wardex"
ok "wardex built successfully"

# ── Scenario 01: Happy Path ──────────────────────────────────────────────────
header "Scenario 01 · Happy Path → ALLOW"
if ${WARDEX} \
    --config="${POC_DIR}/config-s01.yaml" \
    --gate="${POC_DIR}/scenario-01-happy-path.yaml" \
    "${CONTROLS}"; then
  ok "Gate returned ALLOW as expected"
  cp report.json "${POC_DIR}/report-s01.json" 2>/dev/null || true
  PASS=$((PASS + 1))
else
  fail "Gate returned BLOCK — unexpected for this scenario"
  FAIL=$((FAIL + 1))
fi

# ── Scenario 02: Block Path ─────────────────────────────────────────────────
header "Scenario 02 · Critical CVE → BLOCK"
if ${WARDEX} \
    --config="${POC_DIR}/config-s02.yaml" \
    --gate="${POC_DIR}/scenario-02-block-critical.yaml" \
    "${CONTROLS}"; then
  fail "Gate returned ALLOW — should have been BLOCK"
  FAIL=$((FAIL + 1))
else
  ok "Gate correctly returned BLOCK (exit code $?)"
  cp report.json "${POC_DIR}/report-s02.json" 2>/dev/null || true
  PASS=$((PASS + 1))
fi

# ── Scenario 03: Compensating Controls ──────────────────────────────────────
header "Scenario 03 · Compensating Controls → ALLOW"
if ${WARDEX} \
    --config="${POC_DIR}/config-s03.yaml" \
    --gate="${POC_DIR}/scenario-03-compensating-controls.yaml" \
    "${CONTROLS}"; then
  ok "Gate returned ALLOW — controls successfully dampened the risk score"
  cp report.json "${POC_DIR}/report-s03.json" 2>/dev/null || true
  PASS=$((PASS + 1))
else
  fail "Gate returned BLOCK — compensating controls did not reduce risk as expected"
  FAIL=$((FAIL + 1))
fi

# ── Scenario 04: Risk Acceptance Flow ────────────────────────────────────────
header "Scenario 04 · Risk Acceptance Exception Flow"

# Step 1: Initial gate — must BLOCK
info "Step 1: Running initial gate (expect BLOCK)"
rm -f wardex-acceptances.yaml wardex-accept-audit.log
if ${WARDEX} \
    --config="${POC_DIR}/config-s04.yaml" \
    --gate="${POC_DIR}/scenario-04-risk-acceptance.yaml" \
    "${CONTROLS}"; then
  fail "Initial gate returned ALLOW — expected BLOCK as baseline"
  FAIL=$((FAIL + 1))
else
  ok "Initial gate correctly returned BLOCK"
  cp report.json "${POC_DIR}/report-s04-initial.json" 2>/dev/null || true

  # Step 2: Register exception
  info "Step 2: Registering risk-acceptance exception"
  ${WARDEX} --config="${POC_DIR}/config-s04.yaml" accept request \
    --report "${POC_DIR}/report-s04-initial.json" \
    --cve CVE-2025-0042 \
    --accepted-by sec-lead@company.com \
    --justification "No upstream patch available at this time. WAF virtual patch rules were deployed 2025-02-28. Accepted for 14 days pending vendor update." \
    --expires 14d
  ok "Exception registered and signed with HMAC-SHA256"

  # Step 3: Re-run gate — must now ALLOW
  info "Step 3: Re-running gate with active exception (expect ALLOW)"
  if ${WARDEX} \
      --config="${POC_DIR}/config-s04.yaml" \
      --gate="${POC_DIR}/scenario-04-risk-acceptance.yaml" \
      "${CONTROLS}"; then
    ok "Gate returned ALLOW — exception correctly honoured"
    cp report.json "${POC_DIR}/report-s04-accepted.json" 2>/dev/null || true

    # Step 4: Verify integrity
    info "Step 4: Verifying HMAC integrity of all acceptance records"
    if ${WARDEX} --config="${POC_DIR}/config-s04.yaml" accept verify; then
      ok "All acceptance records passed integrity check"
      PASS=$((PASS + 1))
    else
      fail "Integrity check failed — acceptance records may have been tampered with"
      FAIL=$((FAIL + 1))
    fi
  else
    fail "Gate still returned BLOCK after exception registration"
    FAIL=$((FAIL + 1))
  fi
fi

# ── Scenario 05: Warn Risk Band ──────────────────────────────────────────────
header "Scenario 05 · Warn Risk Band → ALLOW (with Warnings)"
if ${WARDEX} \
    --config="${POC_DIR}/config-s05.yaml" \
    --gate="${POC_DIR}/scenario-05-warn-band.yaml" \
    "${CONTROLS}"; then
  ok "Gate returned ALLOW (Warn) — risk exceeded warn_above but not risk_appetite"
  cp report.json "${POC_DIR}/report-s05.json" 2>/dev/null || true
  PASS=$((PASS + 1))
else
  fail "Gate returned BLOCK — warn risk band failed"
  FAIL=$((FAIL + 1))
fi

# ── Scenario 06: Grype Adapter & Risk Simulator ──────────────────────────────
header "Scenario 06 · Grype Adapter & Risk Simulator (DX Sprint)"
info "Step 1: Converting Grype JSON to Wardex YAML"
if ${WARDEX} convert grype "${POC_DIR}/scenario-06-mock-grype.json" \
    --default-epss 1.0 \
    --output "${POC_DIR}/scenario-06-converted.yaml"; then
  ok "Grype JSON successfully converted to Wardex Native YAML"
  
  info "Step 2: Dry-run converted Grype output against the gate"
  # This block will fail the gate because it's a 9.8 Critical vuln without compensations, testing the integration
  if ${WARDEX} \
      --config="${POC_DIR}/config-s06.yaml" \
      --gate="${POC_DIR}/scenario-06-converted.yaml" \
      "${CONTROLS}" > /dev/null 2>&1; then
    fail "Gate returned ALLOW for 9.8 Critical Grype vuln — unexpected"
    FAIL=$((FAIL + 1))
  else
    ok "Gate returned BLOCK for converted Critical Grype vuln"
    PASS=$((PASS + 1))
  fi
else
  fail "Failed to convert Grype JSON"
  FAIL=$((FAIL + 1))
fi

info "Step 3: Generating offline Risk Simulator"
if ${WARDEX} simulate > /dev/null; then
  ok "Wardex Risk Simulator generated successfully"
  PASS=$((PASS + 1))
else
  fail "Failed to generate Risk Simulator"
  FAIL=$((FAIL + 1))
fi


# ── SDK PoC ──────────────────────────────────────────────────────────────────
header "Go SDK Integration Test"
info "Running sdk-poc/main.go directly via Go"
cd "${POC_DIR}"
if go run main.go; then
  ok "SDK PoC passed all 4 scenarios"
  PASS=$((PASS + 1))
else
  fail "SDK PoC failed — check output above"
  FAIL=$((FAIL + 1))
fi
cd "${REPO_ROOT}"

cat << 'EOF' > "${POC_DIR}/config-s07.yaml"
release_gate:
  enabled: true
  risk_appetite: 0.1
  warn_above: 0.05
  asset_context:
    criticality: 1.0
    internet_facing: true
    requires_auth: false
EOF

header "Scenario 07 · SBOM Ingestion (CycloneDX) → BLOCK"
info "Converting mock-sbom.json to Wardex native YAML..."
${WARDEX} convert sbom "${POC_DIR}/scenario-07-mock-sbom.json" -o "${POC_DIR}/scenario-07-converted.yaml"

if ${WARDEX} \
    --config="${POC_DIR}/config-s07.yaml" \
    --gate="${POC_DIR}/scenario-07-converted.yaml" \
    "${POC_DIR}/scenario-07-nocontrols.yaml"; then
  fail "Gate returned ALLOW for SBOM — expected BLOCK due to tight config"
  FAIL=$((FAIL + 1))
else
  ok "Gate correctly blocked the vulnerabilities imported from the SBOM"
  PASS=$((PASS + 1))
fi

# ── Scenario 08: RBAC Profile Overrides ──────────────────────────────────────
header "Scenario 08 · RBAC Profile Overrides (Strict vs Lenient)"

# Baseline run (strict config) -> Expect BLOCK
if ${WARDEX} \
    --config="${POC_DIR}/config-s08.yaml" \
    --gate="${POC_DIR}/scenario-07-converted.yaml" \
    "${POC_DIR}/scenario-07-nocontrols.yaml"; then
  fail "Gate returned ALLOW on baseline — expected BLOCK"
  FAIL=$((FAIL + 1))
else
  ok "Gate correctly returned BLOCK on strict baseline"
  PASS=$((PASS + 1))
fi

# Override run (lenient profile) -> Expect ALLOW
if ${WARDEX} \
    --config="${POC_DIR}/config-s08.yaml" \
    --profile="lenient-team" \
    --gate="${POC_DIR}/scenario-07-converted.yaml" \
    "${POC_DIR}/scenario-07-nocontrols.yaml"; then
  ok "Gate correctly returned ALLOW when using --profile lenient-team"
  PASS=$((PASS + 1))
else
  fail "Gate returned BLOCK even with lenient profile — override failed"
  FAIL=$((FAIL + 1))
fi

# ── Summary ──────────────────────────────────────────────────────────────────
header "Summary"
echo -e "Tests Passed: ${GREEN}${PASS}${NC}"
echo -e "Tests Failed: ${RED}${FAIL}${NC}"
echo -e "${BLUE}══════════════════════════════════════════${NC}"

if [[ ${FAIL} -gt 0 ]]; then
  exit 1
fi
