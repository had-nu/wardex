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
ok()      { echo -e "${GREEN}✅ $1${NC}"; }
fail()    { echo -e "${RED}❌ $1${NC}"; }
info()    { echo -e "${YELLOW}ℹ  $1${NC}"; }

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
    --config="${WARDEX_CONFIG}" \
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
    --config="${WARDEX_CONFIG}" \
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
    --config="${WARDEX_CONFIG}" \
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
if ${WARDEX} \
    --config="${WARDEX_CONFIG}" \
    --gate="${POC_DIR}/scenario-04-risk-acceptance.yaml" \
    "${CONTROLS}"; then
  fail "Initial gate returned ALLOW — expected BLOCK as baseline"
  FAIL=$((FAIL + 1))
else
  ok "Initial gate correctly returned BLOCK"
  cp report.json "${POC_DIR}/report-s04-initial.json" 2>/dev/null || true

  # Step 2: Register exception
  info "Step 2: Registering risk-acceptance exception"
  ${WARDEX} accept request \
    --report "${POC_DIR}/report-s04-initial.json" \
    --cve CVE-2025-0042 \
    --accepted-by sec-lead@company.com \
    --justification "No upstream patch. WAF virtual patch deployed 2025-02-28. Accepted for 14 days." \
    --expires 14d
  ok "Exception registered and signed with HMAC-SHA256"

  # Step 3: Re-run gate — must now ALLOW
  info "Step 3: Re-running gate with active exception (expect ALLOW)"
  if ${WARDEX} \
      --config="${WARDEX_CONFIG}" \
      --gate="${POC_DIR}/scenario-04-risk-acceptance.yaml" \
      "${CONTROLS}"; then
    ok "Gate returned ALLOW — exception correctly honoured"
    cp report.json "${POC_DIR}/report-s04-accepted.json" 2>/dev/null || true

    # Step 4: Verify integrity
    info "Step 4: Verifying HMAC integrity of all acceptance records"
    if ${WARDEX} accept verify; then
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

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}══════════════════════════════════════════${NC}"
echo -e "  PoC Summary: ${GREEN}${PASS} passed${NC} / ${RED}${FAIL} failed${NC}"
echo -e "${BLUE}══════════════════════════════════════════${NC}"

if [[ ${FAIL} -gt 0 ]]; then
  exit 1
fi
