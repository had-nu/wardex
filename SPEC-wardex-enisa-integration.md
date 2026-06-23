# Wardex + ENISA Integration Specification
## Positioning Wardex as the Reference Implementation for CRA Article 14 Compliance Automation

**Version:** 1.0  
**Date:** June 20, 2026  
**Status:** Design Specification  
**Audience:** ENISA Standards Team, Regulatory Authorities, Organizations Implementing CRA  

---

## Executive Summary

This specification defines how Wardex integrates with ENISA's official vulnerability data sources and notification infrastructure to become the de facto reference implementation for CRA Article 14 compliance automation.

**Key Positioning:**
- Not "Wardex is a tool to buy"
- But "This is how CRA Article 14 compliance automation should be architected"

**Current State (v2.1.1):**
- ✅ Risk-based release gate (exit codes 0, 10, 11, 12)
- ✅ CRA Article 14 notification artefacts (HMAC-signed, timestamped)
- ✅ Art14 lifecycle (mark-dispatched, finalize, verify)
- ✅ Framework catalogs (ISO 27001, NIS2, DORA, NIST CSF, SOC 2)
- ✅ Supply chain validation (Cosign, SBOM)
- ⚠️ ENISA backend (stub, no network calls by design)

**Proposed State (v2.2+):**
- ✅ Live ENISA EUVD API integration
- ✅ Scheduled polling for active exploits (GitHub Actions cron)
- ✅ Regulatory-grade audit trail with ENISA timestamps
- ✅ Automatic CRA Article 14 artefact generation on new ENISA events
- ✅ Reference implementation for CRA Article 14 automation

---

## Part 1: Architecture Overview

### 1.1 Current Architecture (Wardex v2.1.1)

```
┌─────────────────────────────────────────────────┐
│            CLI / Interface Layer                 │
│  evaluate | assess | art14 | accept | convert   │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│          Analysis Engine                         │
│  ingestion → catalog → correlator → analyzer    │
│     → scorer → gate.Evaluate() → art14           │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│      Persistence & Reporting Layer               │
│  reports | snapshot | accept | trust | config   │
│  Backends: SyslogBackend | ENISABackend (stub)  │
└─────────────────────────────────────────────────┘
```

**Current Data Flow:**

```
Evidence (Grype, Trivy, etc.)
    ↓
wardex convert → VulnerabilityEnvelope
    ↓
wardex evaluate:
  - Load controls YAML
  - Correlate against catalogs
  - Compute LayerDelta (Policy vs Practice)
  - Calculate risk: R(α) = (CVSS/10 × EPSS) × (1 − Σ(Φ)) × C(α) × E(α)
  - Decision: ALLOW (0) | WARN (10) | BLOCK (10) | ACTIVE_EXPLOIT (12)
    ↓
  - If exit code 12: Generate Art14NotificationArtefact
  - HMAC-SHA256 sign with WARDEX_ACCEPT_SECRET
  - Append to audit log (chained)
    ↓
Output: GapReport (JSON/HTML/Markdown/CSV)
        Art14 metadata
        Exit code
```

**Current EPSS Enrichment:**

```
wardex enrich:
  - Fetch EPSS scores from FIRST.org API
  - Verify with TLS cert pinning
  - Return normalized [0,1] score
  - Cache locally to avoid repeated calls
```

**Current ENISABackend (Stub):**

```go
type ENISABackend struct {
    // no network calls
}

func (e *ENISABackend) Submit(art *Art14NotificationArtefact) error {
    // stub: returns nil
}

func (e *ENISABackend) Forward(log *AuditLog) error {
    // stub: returns nil
}
```

### 1.2 Proposed Integration: Three Layers

#### **Layer 1: Data Source Integration (ENISA EUVD API)**

```
Wardex         ENISA EUVD
  │              API
  ├─────────────→│ (live)
  │              │
  │  EPSS        │ Vulnerabilities
  │  KEV Status  │ Advisories
  │  Publish Date│ CVSS
  │              │ Exploitability
  ├──────────────│ (cached)
  │              │
  └─ Local Cache │
     (1h TTL)    └─
```

**Responsibilities:**
- Wardex pulls live ENISA EUVD data (not just static KEV)
- Caches to avoid API hammering
- Offline fallback to cached data

#### **Layer 2: Scheduled Polling (GitHub Actions)**

```
GitHub Actions       Wardex CLI            ENISA EUVD
  │                   │                      API
  │ (cron: */30)      │                      │
  │──wardex enisa poll─→│                     │
  │                   │──GET /vulnerabilities─→│
  │                   │  /active?since=30m    │
  │                   │←──── JSON ────────────┤
  │                   │                       │
  │                   │ Check cache first     │
  │                   │ └─ hit → skip         │
  │                   │ └─ miss → store +     │
  │                   │    create art14       │
  │                   │                       │
  │                   │ Art14 artefact:       │
  │                   │ ├─ CVE ID             │
  │                   │ ├─ EPSS score         │
  │                   │ ├─ timestamp          │
  │                   │ ├─ HMAC sign          │
  │                   │ └─ audit log          │
```

**Responsibilities:**
- GitHub Actions cron triggers `wardex enisa poll` every 30 minutes
- Polls ENISA EUVD API for newly active exploits
- Compares against file-based cache to avoid duplicates
- Generates Art14NotificationArtefact for new events only
- Compliance clock starts from ENISA publication timestamp

#### **Layer 3: Regulatory Reporting**

```
Wardex                ENISA / Regulators
  │                        │
  │ Art14Artefact         │
  │ (HMAC-signed)         │
  │ timestamp             │
  │ CVE                   │
  │ early-warning         │
  │ decision              │
  │ patch status          │
  │                       │
  ├────report via────→   │
  │ SFTP / REST / Email   │
  │                       │
  │ ← receipt signature ─ ┤
  │ (proves receipt)      │
```

**Responsibilities:**
- Wardex maintains Art14 artefact lifecycle
- Automatic submission of reports to ENISA/authorities
- Prove delivery (signed receipts)

---

## Part 2: Detailed Integration Specification

### 2.1 ENISABackendLive Implementation

**Location:** `internal/backends/enisa.go`

#### **2.1.1 Client Initialization**

```go
package backends

import (
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "path/filepath"
    "time"
)

const (
    enisaBaseURL    = "https://euvdservices.enisa.europa.eu/api"
    enisaCacheDir   = "enisa_cache"
    defaultCacheTTL = 1 * time.Hour
)

type ENISABackendLive struct {
    client    *http.Client
    logger    *slog.Logger
    cacheDir  string          // ~/.wardex/enisa_cache/
    cacheTTL  time.Duration
    apiKey    string
    offline   bool
}

type cachedVulnerability struct {
    CVEID     string    `json:"cve_id"`
    EPSS      float64   `json:"epss"`
    CVSS      float64   `json:"cvss"`
    Exploited bool      `json:"is_actively_exploited"`
    Timestamp time.Time `json:"timestamp"`
    Expires   time.Time `json:"expires"`
}

// NewENISABackendLive initializes live backend with ENISA credentials
func NewENISABackendLive(ctx context.Context, opts ...ENISAOption) (*ENISABackendLive, error) {
    cfg := &enisaConfig{
        BaseURL:  enisaBaseURL,
        Timeout:  30 * time.Second,
        CacheTTL: defaultCacheTTL,
    }

    for _, opt := range opts {
        opt(cfg)
    }

    cacheDir := filepath.Join(os.Getenv("HOME"), ".wardex", enisaCacheDir)
    if cfg.CacheDir != "" {
        cacheDir = cfg.CacheDir
    }

    client := &http.Client{Timeout: cfg.Timeout}

    // Test connectivity
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BaseURL+"/health", nil)
    if _, err := client.Do(req); err != nil {
        if cfg.Offline {
            return &ENISABackendLive{offline: true}, nil
        }
        return nil, fmt.Errorf("ENISA API unavailable: %w", err)
    }

    return &ENISABackendLive{
        client:   client,
        logger:   slog.Default(),
        cacheDir: cacheDir,
        cacheTTL: cfg.CacheTTL,
        apiKey:   os.Getenv("ENISA_API_KEY"),
        offline:  false,
    }, nil
}
```

#### **2.1.2 Vulnerability Enrichment**

```go
// QueryVulnerability retrieves live ENISA data for a CVE
func (e *ENISABackendLive) QueryVulnerability(ctx context.Context, cveID string) (*EnrichedVulnerability, error) {
    if e.offline {
        return e.queryOffline(cveID)
    }

    // Check file-based cache first
    if cv := e.cacheGet(cveID); cv != nil {
        if time.Now().Before(cv.Expires) {
            e.logger.DebugContext(ctx, "cache hit", "cve", cveID)
            return e.enrichVulnerability(cv), nil
        }
        os.Remove(e.cachePath(cveID))
    }

    // Query ENISA EUVD API via HTTP
    vuln, err := e.fetchVulnerability(ctx, cveID)
    if err != nil {
        if fallback := e.cacheGet(cveID); fallback != nil {
            e.logger.WarnContext(ctx, "ENISA query failed, using cached data", "cve", cveID, "err", err)
            return e.enrichVulnerability(fallback), nil
        }
        return nil, fmt.Errorf("ENISA query failed: %w", err)
    }

    // Write to file-based cache
    e.cacheSet(cveID, vuln)

    return e.enrichVulnerability(vuln), nil
}

func (e *ENISABackendLive) cachePath(cveID string) string {
    return filepath.Join(e.cacheDir, cveID+".json")
}

func (e *ENISABackendLive) cacheGet(cveID string) *cachedVulnerability {
    data, err := os.ReadFile(e.cachePath(cveID))
    if err != nil {
        return nil
    }
    var cv cachedVulnerability
    if err := json.Unmarshal(data, &cv); err != nil {
        return nil
    }
    return &cv
}

func (e *ENISABackendLive) cacheSet(cveID string, vuln *cachedVulnerability) {
    os.MkdirAll(e.cacheDir, 0700)
    data, _ := json.Marshal(vuln)
    os.WriteFile(e.cachePath(cveID), data, 0600)
}

// enrichVulnerability converts ENISA response to Wardex model
func (e *ENISABackendLive) enrichVulnerability(vuln *cachedVulnerability) *EnrichedVulnerability {
    return &EnrichedVulnerability{
        CVEID:         vuln.CVEID,
        CVSS:          vuln.CVSS,
        EPSS:          vuln.EPSS,
        ActiveExploit: vuln.Exploited,
        EnisaSource:   "EUVD",
    }
}
```

#### **2.1.3 Active Exploitation Detection**

```go
// QueryActiveExploits retrieves CVEs with active wild exploitation
func (e *ENISABackendLive) QueryActiveExploits(ctx context.Context, since time.Time) ([]*ActiveExploit, error) {
    if e.offline {
        return e.queryActiveExploitsOffline(since)
    }

    // Query ENISA EUVD for active exploits filter
    //   GET /api/vulnerabilities?activelyExploited=true&since=2026-06-20
    url := fmt.Sprintf("%s/vulnerabilities?activelyExploited=true&since=%s",
        enisaBaseURL, since.Format(time.RFC3339))

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, fmt.Errorf("creating request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+e.apiKey)

    resp, err := e.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("ENISA query failed: %w", err)
    }
    defer resp.Body.Close()

    var result struct {
        Vulnerabilities []struct {
            CVE          string    `json:"cve"`
            EPSS         float64   `json:"epss"`
            CVSS         float64   `json:"cvss"`
            Published    time.Time `json:"published_date"`
            LastUpdated  time.Time `json:"last_updated"`
            EnisaID      string    `json:"enisa_id"`
            Exploited    bool      `json:"is_actively_exploited"`
        } `json:"vulnerabilities"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("decoding response: %w", err)
    }

    exploits := make([]*ActiveExploit, 0, len(result.Vulnerabilities))
    for _, v := range result.Vulnerabilities {
        exploits = append(exploits, &ActiveExploit{
            CVEID:          v.CVE,
            EPSS:           v.EPSS,
            DetectedDate:   v.Published,
            LastConfirmed:  v.LastUpdated,
            EnisaReference: v.EnisaID,
            CISAKEVMatch:   isCISAKEV(v.CVE),
        })
    }

    return exploits, nil
}

// isCISAKEV checks if vulnerability is in CISA KEV catalogue
func isCISAKEV(cveID string) bool {
    // Cross-reference with local CISA KEV list
    // Simplified: could query a local dataset
    return false
}
```

#### **2.1.4 Audit Trail Forwarding**

```go
// SubmitArt14Notification submits a CRA Article 14 artefact to ENISA
func (e *ENISABackendLive) SubmitArt14Notification(ctx context.Context, art *Art14NotificationArtefact) (*SubmissionReceipt, error) {
    if e.offline {
        e.logger.WarnContext(ctx, "offline mode: storing art14 for later", "id", art.ID)
        return &SubmissionReceipt{StoredForLater: true}, nil
    }

    // Submit to ENISA endpoint via HTTP
    // POST /api/compliance/cra/notifications
    payload, _ := json.Marshal(art)
    url := enisaBaseURL + "/compliance/cra/notifications"

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
    if err != nil {
        return nil, fmt.Errorf("creating request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+e.apiKey)
    req.Header.Set("Content-Type", "application/json")

    resp, err := e.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("ENISA submission failed: %w", err)
    }
    defer resp.Body.Close()

    var receipt struct {
        ID        string    `json:"id"`
        Timestamp time.Time `json:"timestamp"`
        StatusURL string    `json:"status_url"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
        return nil, fmt.Errorf("decoding receipt: %w", err)
    }

    e.logger.InfoContext(ctx, "art14 submitted to ENISA",
        "id", art.ID, "receipt", receipt.ID)

    return &SubmissionReceipt{
        ID:        receipt.ID,
        Timestamp: receipt.Timestamp,
        StatusURL: receipt.StatusURL,
    }, nil
}

// ForwardAuditLog sends audit entries to ENISA
func (e *ENISABackendLive) ForwardAuditLog(ctx context.Context, entries []*AuditLogEntry) error {
    if e.offline {
        return nil
    }

    // Use existing Forwarder interface — ENISABackendLive implements it
    // Forwarding is delegated to the ForwardMultiplexer
    return nil
}
```
---

### 2.3 Configuration & Deployment

#### **2.3.1 wardex.yaml**

```yaml
# Enable live ENISA integration
compliance:
  enisa:
    enabled: true                          # false = use stub backend
    
    # ENISA EUVD API settings
    api:
      base_url: https://euvdservices.enisa.europa.eu/api
      timeout_seconds: 30
      
    # File-based cache (~/.wardex/enisa_cache/)
    cache:
      enabled: true
      ttl_seconds: 3600                    # 1 hour cache TTL per CVE
      
    # Offline fallback
    offline_mode: true                     # continue if ENISA down
    offline_cache_dir: ~/.wardex/enisa_cache
    
    # Poll interval (GitHub Actions schedules the run)
    poll_interval_minutes: 30
    
    # Forwarding to authorities (uses existing Forwarder interface)
    forwarding:
      enabled: true
      method: https
      endpoint: https://authority.example.eu/cra/submit
      certificate_pin: sha256/ABC123...    # HPKP pinning
      
  cra:
    article14:
      enabled: true
      auto_submit: true                    # automatically submit via ENISA backend
      deadlines_enabled: true              # track 24h/72h/14d
```

#### **2.3.2 Environment Variables**

```bash
# ENISA EUVD API key (required for live backend)
export ENISA_API_KEY=sk_live_...

# Organization context (for tracking submissions)
export WARDEX_ORG_ID=org_...
export WARDEX_AUTHORITY_ID=auth_... # which authority to report to
```

---

## Part 3: Regulatory Alignment

### 3.1 CRA Article 14 Compliance

**Article 14 Requirements:**
1. Detect actively exploited vulnerabilities
2. Notify competent authority within 72 hours
3. Submit detailed report within 14 days
4. Prove remediation

**Wardex Implementation:**

```
ENISA Notification
    ↓ (ENISA poll, timestamp T)
    ├─ Early Warning (T + 24h deadline)
    │  └─ wardex art14 mark-dispatched <id>
    ├─ Detailed Report (T + 72h deadline)
    │  └─ wardex art14 show <id> → generate report
    └─ Patch Confirmation (T + 14 days)
       └─ wardex art14 finalize <id> --patch-date ...
```

**Timestamp Chain:**
```
ENISA poll returns: {"timestamp": "2026-06-20T14:32:00Z", "cve": "CVE-2024-3094"}
                ↓
Wardex creates Art14 (cache miss → new exploit):
{
  "id": "wardex-art14-CVE-2024-3094-1718882320",
  "cra_status": {
    "awareness_timestamp": "2026-06-20T14:32:00Z",
    "early_warning_deadline": "2026-06-21T14:32:00Z",
    "report_deadline": "2026-06-23T14:32:00Z",
    "correction_deadline": "2026-07-04T14:32:00Z"
  },
  "hmac_sha256": "8c4f..."
}
                ↓
Regulators verify: ENISA timestamp ← Wardex Art14 ← Organization action
```

### 3.2 NIS2 Article 21 (Management Responsibility)

**Article 21 Requirement:**
> "The management of undertakings shall be responsible for oversight and monitoring of implementation."

**Wardex Evidence:**

```
wardex config seal
    └─ Ed25519 signed config → .wexstate
    └─ Proof that management reviewed and approved

wardex evaluate --strict
    └─ Requires sealed config
    └─ Exit code 3 if config tampered
    └─ Non-repudiation: CIO approved this policy

wardex art14 verify <id>
    └─ HMAC validation
    └─ Timestamp chain
    └─ Proof of decision
```

### 3.3 DORA Article 15 (Incident Reporting)

**DORA Requirement:**
> "Critical incidents shall be reported to competent authority within 72 hours."

**Wardex Role:**

```
ransomware via CVE
    ↓
wardex evaluate (incident triggers exit code 12)
    ↓
Art14NotificationArtefact created automatically
    ├─ 24h early warning
    ├─ 72h detailed report
    └─ Organization + Wardex timeline is synchronized
    
Regulatory proof: Art14 artefact shows exactly when Wardex detected
                 and what actions were triggered
```

------

## Part 5: Implementation Roadmap

### Milestone 1: ENISABackendLive (Weeks 1-3)

**Deliverables:**
- [ ] ENISABackendLive struct + EUVD API client integration
- [ ] QueryVulnerability() with EPSS enrichment
- [ ] QueryActiveExploits() with CISA KEV correlation
- [ ] Local caching (1h TTL)
- [ ] Offline fallback mode
- [ ] Tests against EUVD sandbox API

**Code:**
```
internal/backends/enisa.go (new)
internal/backends/enisa_test.go
internal/backends/cache.go (file-based cache)
test/integration/enisa_backend_test.go
```

**Config Changes:**
```
wardex.yaml: add compliance.enisa section
environment: ENISA_API_KEY
```

---

### Milestone 2: Scheduled Polling (Weeks 2-4)

**Deliverables:**
- [ ] `wardex enisa poll` subcommand for on-demand ENISA check
- [ ] `wardex enisa poll --daemon` for continuous polling loop
- [ ] File-based cache (`~/.wardex/enisa_cache/*.json` with TTL)
- [ ] Automatic Art14NotificationArtefact generation on new active exploits
- [ ] Audit trail logging to `wardex enisa audit`

**Code:**
```
internal/backends/enisa.go: PollActiveExploits()
internal/backends/cache.go (file-based TTL cache)
test/integration/enisa_poll_test.go
```

**GitHub Actions:**
```yaml
# .github/workflows/enisa-poll.yml
name: ENISA EUVD Poll
on:
  schedule:
    - cron: '*/30 * * * *'   # every 30 minutes
  workflow_dispatch:          # manual trigger

jobs:
  poll:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: wardex enisa poll
        env:
          ENISA_API_KEY: ${{ secrets.ENISA_API_KEY }}
      - run: wardex art14 list --since 30m
```

---

### Milestone 3: Regulatory Reporting (Weeks 4-6)

**Deliverables:**
- [ ] Art14NotificationArtefact submission to ENISA
- [ ] HTTPS + certificate pinning
- [ ] Signed receipts from authorities
- [ ] SLA tracking (24h, 72h, 14d)
- [ ] Automatic reminders

**Code:**
```
internal/backends/enisa.go: SubmitArt14Notification()
pkg/report/cra_formatter.go (regulatory format)
pkg/notify/deadline_tracker.go (SLA alerts)
test/integration/enisa_submission_test.go
```

**Configuration:**
```
wardex.yaml: add compliance.cra.forwarding section
```

---

### Milestone 4: Documentation (Weeks 6-8)

**Deliverables:**
- [ ] Technical spec for ENISA (this document)
- [ ] CRA Article 14 Implementation Guide
- [ ] NIS2 Article 21 Governance Pattern
- [ ] DORA integration example

**Documentation:**
```
docs/ENISA_INTEGRATION.md
docs/CRA_ARTICLE_14.md
docs/NIS2_ARTICLE_21.md
docs/DORA_COMPLIANCE.md
```

---

## Appendix: Signature Schemes

**Art14 Artefact Signature (Wardex → Authority):**
```
Payload: Art14NotificationArtefact (JSON)
Signature: HMAC-SHA256(payload, WARDEX_ACCEPT_SECRET)
Format: artefact.hmac_sha256 = "<hex>"
Verification: wardex art14 verify <id>
```

---

## Conclusion

This specification positions Wardex as the open-source reference implementation for CRA Article 14 compliance automation through:

1. **Live integration** with official ENISA vulnerability data
2. **Scheduled polling** of ENISA EUVD active exploits (via GitHub Actions cron)
3. **Regulatory-grade** audit trails and artefact signing
4. **Framework-agnostic** governance (ISO 27001, NIS2, DORA, NIST CSF)
5. **Documented patterns** that enable reproducible CRA compliance workflows

**The Goal:** By September 2026 (CRA enforcement), Wardex is the implicit standard for CRA Article 14 automation — not because it was sold, but because it's how compliance actually works.

---

**Document Status:** Ready for Technical Review  
**Next Step:** Publish as RFC in Wardex GitHub  
**Timeline:** Implementation starts Week 1 of July 2026

