# Garuda EASM — Watchdog Universal Ingestion Engine
## Design Specification & Implementation Plan

**Version:** 2.0  
**Status:** Design Phase  
**Scope:** `worker/` folder — complete refactor

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Universal Data Model (UDM)](#2-universal-data-model-udm)
   - 2.1 Sub-models
   - 2.2 UniversalFinding (root document)
   - 2.3 Asset Document
3. [Fingerprint Strategy](#3-fingerprint-strategy)
4. [Severity Normalization](#4-severity-normalization)
5. [Finding Type Taxonomy](#5-finding-type-taxonomy)
6. [MongoDB Upsert Patterns](#6-mongodb-upsert-patterns)
7. [Adapter YAML Specification](#7-adapter-yaml-specification)
   - 7.1 Extraction Modes
   - 7.2 Field Mapping Rules
   - 7.3 Transform Pipeline
   - 7.4 Full Examples (Nuclei, Nmap, Invicti, TruffleHog, Burp)
8. [New Worker Architecture](#8-new-worker-architecture)
   - 8.1 Directory Structure
   - 8.2 Data Flow
   - 8.3 File Lifecycle Management (incoming → archive / quarantine)
9. [Implementation Plan (Step-by-Step)](#9-implementation-plan-step-by-step)
10. [Migration Strategy](#10-migration-strategy)
11. [Testing Checklist](#11-testing-checklist)

---

## 1. Problem Statement

### Current State Bottlenecks

| Issue | File | Impact |
|---|---|---|
| Models hard-wired to Nuclei fields | `scanners/nuclei/models.py` | Cannot ingest Invicti, Burp, TruffleHog without Python code changes |
| MD5 fingerprint (`template_id + matched_at` only) | `fingerprint.py` | No Web vs Network distinction; collisions possible |
| Per-finding `find_one` + `insert/update` | `scanners/nuclei/processor.py` | N findings = N DB round-trips; no `bulk_write` |
| `_upsert_asset()` is read-then-write | `scanners/nuclei/processor.py` | Race condition under concurrent ingestion; not atomic |
| No YAML/JSONPath config for adapters | `scanners/` (pure Python) | Every new scanner = new Python module |
| `host_classification` duplicated | `worker/app/core/` AND `backend/app/utils/` | Maintenance drift |
| No `$addToSet` for cross-tool dedup | `processor.py` | Multiple tools finding same vuln → duplicates |

### Target State

```
Drop a JSON file from ANY scanner
   into incoming/<scanner>/
          ↓
YAML config loaded for that scanner
          ↓
Extraction Strategy runs (flat / nested_join / context_inject)
          ↓
JSONPath mapping → UniversalFinding (Pydantic v2)
          ↓
SHA-256 fingerprint computed (formula by finding_type)
          ↓
Severity: take MAX across tools
          ↓
MongoDB bulk_write with $setOnInsert + $set + $addToSet
          ↓
Asset upsert: atomic $addToSet (non-destructive)
          ↓
Snapshot dirty flag set
```

Adding a new scanner in the future = **write one YAML file, zero Python**.

---

## 2. Universal Data Model (UDM)

### 2.1 Sub-models

#### `UDMTarget` — The affected asset
```python
class UDMTarget(BaseModel):
    ip:              str | None = None   # "1.2.3.4"
    hostname:        str | None = None   # "api.example.com"
    url:             str | None = None   # "https://api.example.com/v1/users?id=1"
    port:            int | None = None   # 443
    protocol:        str | None = None   # "tcp" | "https" | "udp"
    path:            str | None = None   # "/v1/users"
    host_normalized: str                 # COMPUTED: apex domain or raw IP
```
**Computation rule for `host_normalized`:**
- If `hostname` present → extract apex domain (e.g., `api.example.com` → `example.com`)
- Else if `url` present → parse hostname from URL, then extract apex
- Else if `ip` present → use `ip` as-is
- Fallback → `"unknown"`

#### `UDMIdentity` — What was found
```python
class UDMIdentity(BaseModel):
    standardized_rule_id: str              # Canonical cross-tool ID (see §3)
    raw_rule_id:          str              # As-is from tool output
    name:                 str              # Human-readable name
    category:             str              # "xss" | "rce" | "port_open" | ...
    cve:                  list[str] = []   # ["CVE-2021-44228"]
    cwe:                  list[str] = []   # ["CWE-79"]
    cvss_score:           float | None = None
    cvss_vector:          str   | None = None  # "CVSS:3.1/AV:N/..."
```

**`standardized_rule_id` normalization rules:**
| Tool | Raw ID | Standardized |
|---|---|---|
| Nuclei | `cves/2021/CVE-2021-44228.yaml` | `CVE-2021-44228` (extract CVE if present) |
| Nuclei | `http/exposures/configs/nginx-config.yaml` | `nuclei:http/exposures/configs/nginx-config` |
| Nmap | service name `openssh` | `nmap:openssh` |
| Invicti | `db/vulnerabilities/acx/2004/XSS.yaml` | `invicti:acx/2004/XSS` |
| TruffleHog | `AWS` (detector name) | `trufflehog:AWS` |
| Burp | `Cross-site scripting (reflected)` | `burp:xss-reflected` (slugified) |
| Shodan | CVE from vulns module | `CVE-XXXX-XXXXX` |

#### `UDMEvidence` — Proof
```python
class UDMEvidence(BaseModel):
    request:          str | None = None   # Raw HTTP request
    response:         str | None = None   # Raw HTTP response (may be truncated)
    matched_at:       str | None = None   # URL/string where match occurred
    extracted:        list[str] = []      # Regex captures / extracted values
    curl_command:     str | None = None   # Reproducible PoC

    # Web scanner specific (Invicti, Burp, Acunetix)
    http_method:      str | None = None   # "POST", "GET"
    input_type:       str | None = None   # "json", "query", "header", "cookie"
    input_name:       str | None = None   # Parameter name (e.g., "messages.1.content")
    test_value:       str | None = None   # Payload used

    # Template/details rendering (Invicti details_template)
    details_template: str | None = None   # Mustache template string
    details_data:     dict     = {}       # Data to render into template

    # Secret scanner specific (TruffleHog, Gitleaks)
    secret_type:      str | None = None   # "AWS_ACCESS_KEY", "JWT", "SSH_KEY"
    secret_raw:       str | None = None   # Redacted partial value (never full secret)
    repo_url:         str | None = None
    commit_hash:      str | None = None
    file_path:        str | None = None
    line_number:      int | None = None

    # Evidence history: Option C — accumulate over time
    # Each re-scan of same fingerprint appends here
    history:          list[EvidenceSnapshot] = []

    # Full raw scanner output (passthrough)
    # Truncation is handled BEFORE storage based on adapter evidence_limits config.
    # This avoids MongoDB 16MB document limit crashes.
    raw:                  dict = {}       # truncated if response_body exceeds max_response_size_kb
    raw_truncated:        bool = False    # True if raw was truncated before storage
    raw_original_size_kb: int  | None = None  # original size before truncation (for audit)
```

```python
class EvidenceSnapshot(BaseModel):
    timestamp:   datetime
    source_tool: str
    raw:         dict    # raw finding at that point in time
```

#### `UDMSeverityLevel` — Enum
```python
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    UNKNOWN  = "unknown"

SEVERITY_RANK: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH:     4,
    SeverityLevel.MEDIUM:   3,
    SeverityLevel.LOW:      2,
    SeverityLevel.INFO:     1,
    SeverityLevel.UNKNOWN:  0,
}
```

---

### 2.2 `UniversalFinding` — Root MongoDB Document

```python
class UniversalFinding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # ── COMPUTED (set by ingestion engine, never from adapter) ──────────────
    fingerprint:       str          # SHA-256 hex, formula by finding_type (§3)
    schema_version:    int = 2

    # ── CLASSIFICATION ───────────────────────────────────────────────────────
    finding_type: Literal[
        "vulnerability",    # Confirmed or possible security flaw (Nuclei CVE, DAST)
        "exposure",         # Exposed panel/file (risky but not confirmed exploitable)
        "port_service",     # Open port + service info (Nmap, Masscan, Shodan)
        "dns_finding",      # Subdomain takeover, dangling CNAME (dnsx, Amass)
        "ssl_finding",      # Cert expiry, weak cipher (SSLyze, testssl, Invicti TLS)
        "secret",           # Leaked key/token/cred (TruffleHog, Gitleaks)
        "misconfiguration", # Missing header, CORS open (Nuclei misconfig, Invicti config)
        "asset_discovery",  # New host/IP found (Subfinder, httpx)
    ]

    # ── MODELS ───────────────────────────────────────────────────────────────
    target:   UDMTarget
    identity: UDMIdentity
    evidence: UDMEvidence | None = None

    # ── SEVERITY ─────────────────────────────────────────────────────────────
    severity:          SeverityLevel           # Current effective severity
    severity_source:   str = "scanner"         # "scanner" | "cvss" | "override"
    override_severity: SeverityLevel | None = None

    # ── TIMESTAMPS (immutable: $setOnInsert) ─────────────────────────────────
    first_seen:        datetime
    source_tool_first: str                     # Tool that first discovered this

    # ── TIMESTAMPS (mutable: $set) ───────────────────────────────────────────
    last_seen: datetime

    # ── CROSS-TOOL ACCUMULATION ($addToSet) ──────────────────────────────────
    discovery_tools: list[str] = []            # ["nuclei", "shodan"] — audit trail
    tags:            list[str] = []
    references:      list[str] = []

    # ── WORKFLOW STATE ($set, user-managed) ──────────────────────────────────
    status:    Literal["Open", "Investigating", "Accepted Risk", "Resolved"] = "Open"
    asset_id:  Any | None = None               # ObjectId → assets collection

    # ── SOURCE METADATA ($set) ───────────────────────────────────────────────
    source_file: str
```

**MongoDB field-level operation mapping:**

| Field | Operation | Rationale |
|---|---|---|
| `fingerprint`, `finding_type`, `target`, `identity`, `first_seen`, `source_tool_first` | `$setOnInsert` | Immutable — set only on creation |
| `last_seen`, `evidence`, `severity`, `source_file` | `$set` | Updated on every re-scan |
| `severity` | `$set` with MAX logic (in app layer) | Always keep highest severity seen |
| `discovery_tools` | `$addToSet` | Accumulate tool names, never overwrite |
| `tags`, `references` | `$addToSet { $each: [...] }` | Accumulate, never overwrite |
| `status`, `override_severity`, `asset_id` | `$set` only if not null (user-managed) | Preserve triage state |

---

### 2.3 Asset Document

```python
# MongoDB collection: assets
{
    # ── KEY (immutable: $setOnInsert) ──────────────────────────────────────
    "host_normalized": "example.com",   # UNIQUE INDEX
    "type":            "domain",        # "ip" | "domain" | "subdomain" | "unknown"
    "first_seen":      ISODate,

    # ── MUTABLE ($set) ──────────────────────────────────────────────────────
    "last_seen": ISODate,

    # ── COMPUTED (recalculation job, $set after bulk ingest) ────────────────
    # Never set directly during ingestion; set only by recalc job
    "highest_severity":    "critical",
    "vulnerability_count": 12,
    "open_finding_types":  ["vulnerability", "misconfiguration"],

    # ── ACCUMULATIVE — IPs and technologies (NEVER overwrite, always $addToSet) ──
    "ip_addresses":    ["1.2.3.4", "1.2.3.5"],
    "technologies":    ["nginx/1.21", "php/8.1"],
    "discovery_tools": ["nmap", "nuclei", "httpx"],

    # ── PORT METADATA (replaces flat open_ports array) ───────────────────────
    # Keyed by "<port>/<protocol>" string. Updated via $set dot-notation.
    # Ports are NEVER deleted from this dict.
    # Status transitions:  (none) → open  →  stale
    #   "open"  = detected in a recent scan
    #   "stale" = last_seen older than staleness_threshold (default 7 days)
    #             set by recalculator.py, NOT during ingestion
    #
    # first_seen is preserved using $min operator:
    #   - new port entry:      $min sets first_seen = now  (field did not exist)
    #   - existing port entry: $min keeps original first_seen (now > first_seen)
    "port_metadata": {
        "443/tcp": {"first_seen": "ISODate", "last_seen": "ISODate", "status": "open",  "service": "https"},
        "80/tcp":  {"first_seen": "ISODate", "last_seen": "ISODate", "status": "open",  "service": "http"},
        "22/tcp":  {"first_seen": "ISODate", "last_seen": "ISODate", "status": "stale", "service": "ssh"}
    },

    # ── COMPUTED ($set after recalc) ────────────────────────────────────────
    "services": ["https", "http", "ssh"]
}
```

---

### 2.4 Workflow State Rules — Status Immutability & Scan Isolation

This is a **hard architectural constraint** of the ingestion engine. Violations will corrupt triage workflows.

#### Rule 1: `status` is USER-OWNED, never engine-owned

```
                 ┌─────────────────────────┐
  Ingestion      │  $setOnInsert only       │  Engine sets "Open" ONCE on first insert
  Engine         │  status = "Open"         │  and NEVER touches it again
                 └─────────────────────────┘

                 ┌─────────────────────────┐
  User via API   │  PATCH /vulns/{id}       │  Only path that can change status to:
                 │  status = "Investigating" │  Investigating / Accepted Risk / Resolved
                 └─────────────────────────┘
```

**Fields the ingestion engine must NEVER put in `$set`:**
- `status`
- `override_severity`
- `asset_id` (set by backend asset linking job, not ingestion)

#### Rule 2: Scan Isolation — a scan only touches its own fingerprints

```
Scan batch received:  [finding_C from asset_D, finding_E from asset_D]

Engine behavior:
  ✅  finding_C fingerprint → upsert (update last_seen if exists)
  ✅  finding_E fingerprint → upsert (update last_seen if exists)
  ✅  finding_A (from a previous scan, not in this batch) → UNTOUCHED
  ✅  finding_A.status remains whatever the user set it to
  ✅  finding_A.last_seen is NOT updated (it was not re-detected)
```

**Consequence for vulnerability lifecycle:**

| Event | Effect on finding |
|---|---|
| Finding first detected | Inserted with `status=Open`, `first_seen=now`, `last_seen=now` |
| Same finding re-detected in later scan | `last_seen` updated, `discovery_tools` $addToSet, `evidence` overwritten |
| Same finding NOT detected in later scan | **Nothing changes** — last_seen drifts older |
| User triages: sets `status=Resolved` | status=Resolved, preserved across all future scans |
| Resolved finding re-detected | `last_seen` updated, `discovery_tools` $addToSet — status stays `Resolved` |

**Note on re-opened findings:** The decision to re-open a `Resolved` finding when it is re-detected is a **business logic decision**, not an ingestion decision. If needed, implement it as a separate `AlertingJob` that queries for `{status: "Resolved", last_seen: {$gte: recent_scan_start}}` and notifies the user — but never auto-change status in the ingestion path.

```python
# WRONG — never do this:
"$set": {
    "status": "Open",   # ← violates scan isolation, destroys triage state
    "last_seen": now,
}

# CORRECT:
"$set": {
    "last_seen": now,   # ← only update temporal fields
    "evidence":  ...,
    "source_file": ...,
}
```
```

---

## 3. Fingerprint Strategy

**Algorithm:** SHA-256 (hex digest)  
**Purpose:** Deterministic deduplication across re-runs of same tool on same target.  
Cross-tool deduplication handled via `$addToSet` on `discovery_tools` (Hybrid approach).

### Formula Matrix

| finding_type | Is Web? | Formula |
|---|---|---|
| `vulnerability` | Yes (`target.url` not None) | `SHA256(standardized_rule_id \| hostname \| url_path)` |
| `vulnerability` | No | `SHA256(standardized_rule_id \| ip \| port \| protocol)` |
| `exposure` | Yes | `SHA256("exposure" \| standardized_rule_id \| hostname \| url_path)` |
| `exposure` | No | `SHA256("exposure" \| standardized_rule_id \| hostname)` |
| `misconfiguration` | Yes | `SHA256("misconfig" \| standardized_rule_id \| hostname \| url_path)` |
| `misconfiguration` | No | `SHA256("misconfig" \| standardized_rule_id \| hostname)` |
| `port_service` | N/A | `SHA256("port" \| ip \| port \| protocol)` |
| `ssl_finding` | N/A | `SHA256("ssl" \| standardized_rule_id \| hostname \| port)` |
| `dns_finding` | N/A | `SHA256("dns" \| category \| hostname)` |
| `secret` | N/A | `SHA256("secret" \| standardized_rule_id \| repo_url_or_url \| file_path \| line_number)` |
| `asset_discovery` | N/A | `SHA256("asset" \| host_normalized)` |

### Canonicalization Rules (before hashing)
- All strings: `.lower().strip()`
- URL path: strip query string and fragment before hashing (path only)
- Port: always `str(int(port))` to normalize "0443" → "443"
- Protocol: always lowercase
- `None` fields: replace with empty string `""`
- Separator: `"|"` (pipe character)

### Python Implementation Sketch
```python
import hashlib

def build_fingerprint(finding_type: str, target: UDMTarget, identity: UDMIdentity) -> str:
    is_web = target.url is not None

    if finding_type == "vulnerability":
        parts = [identity.standardized_rule_id]
        if is_web:
            from urllib.parse import urlparse
            parsed = urlparse(target.url)
            parts += [target.hostname or "", parsed.path]
        else:
            parts += [target.ip or "", str(target.port or ""), target.protocol or ""]

    elif finding_type == "port_service":
        parts = ["port", target.ip or "", str(target.port or ""), target.protocol or ""]

    elif finding_type == "ssl_finding":
        parts = ["ssl", identity.standardized_rule_id, target.hostname or "", str(target.port or "")]

    elif finding_type == "dns_finding":
        parts = ["dns", identity.category, target.hostname or ""]

    elif finding_type == "secret":
        ev = ...  # evidence
        parts = ["secret", identity.standardized_rule_id,
                 ev.repo_url or target.url or "", ev.file_path or "", str(ev.line_number or "")]

    elif finding_type in ("exposure", "misconfiguration"):
        prefix = "exposure" if finding_type == "exposure" else "misconfig"
        if is_web:
            from urllib.parse import urlparse
            parts = [prefix, identity.standardized_rule_id, target.hostname or "", urlparse(target.url).path]
        else:
            parts = [prefix, identity.standardized_rule_id, target.hostname or ""]

    elif finding_type == "asset_discovery":
        parts = ["asset", target.host_normalized]

    else:
        raise ValueError(f"Unknown finding_type: {finding_type}")

    raw = "|".join(p.lower().strip() for p in parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()
```

---

## 4. Severity Normalization

### Integer → String Mapping (for Invicti/Acunetix)
```python
INVICTI_SEVERITY_MAP = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}
```

### String Aliases (for Nuclei, Nmap)
```python
SEVERITY_ALIASES = {
    "informational": "info",
    "information":   "info",
    "note":          "info",
    "warn":          "low",
    "warning":       "low",
    "moderate":      "medium",
    "important":     "high",
    "urgent":        "critical",
    "crit":          "critical",
}
```

### Conflict Resolution (Q5 answer: MAX wins)
```python
def resolve_severity(existing: SeverityLevel, incoming: SeverityLevel) -> SeverityLevel:
    return existing if SEVERITY_RANK[existing] >= SEVERITY_RANK[incoming] else incoming
```

When upserting:
1. Fetch current `severity` from existing document (or None if new)
2. Compare with incoming severity
3. `$set severity` only if incoming rank > existing rank

---

## 5. Finding Type Taxonomy

### Auto-detection from adapter config
Each adapter YAML declares `finding_type_default`. For scanners that produce mixed types (Nuclei), a `finding_type_rules` section overrides per finding:

```yaml
finding_type_rules:
  # Evaluated in order; first match wins
  - if_tag_contains: ["cve"]
    set_type: vulnerability
  - if_category_equals: ["ssl_weak_ciphers", "hsts_missing"]
    set_type: ssl_finding
  - if_category_equals: ["configuration", "misconfig"]
    set_type: misconfiguration
  - if_tag_contains: ["exposure", "exposed"]
    set_type: exposure
  - if_tag_contains: ["info", "tech"]
    set_type: exposure
  # fallback
  - default: vulnerability
```

### `category` field canonical values
These are free-form strings but the following are standard:
```
rce, sqli, xss, xxe, ssrf, ssti, lfi, rfi,
idor, auth_bypass, open_redirect, csrf,
path_traversal, command_injection,
exposure, information_disclosure,
ssl_weak_cipher, ssl_expired, ssl_selfsigned, hsts_missing,
port_open, service_detected,
secret_aws, secret_github_token, secret_jwt, secret_ssh_key,
misconfiguration, cors_open, csp_missing, header_missing,
dns_takeover, dangling_cname,
```

---

## 6. MongoDB Upsert Patterns

### Vulnerability Upsert (bulk_write compatible)
```python
from pymongo import UpdateOne

def build_vuln_upsert(finding: UniversalFinding, now: datetime) -> UpdateOne:
    fp = finding.fingerprint
    incoming_sev = finding.severity

    return UpdateOne(
        filter={"fingerprint": fp},
        update={
            "$setOnInsert": {
                "fingerprint":        fp,
                "finding_type":       finding.finding_type,
                "target":             finding.target.model_dump(),
                "identity":           finding.identity.model_dump(),
                "first_seen":         now,
                "source_tool_first":  finding.discovery_tools[0] if finding.discovery_tools else "unknown",
                "schema_version":     2,
                "status":             "Open",
            },
            "$set": {
                "last_seen":    now,
                "evidence":     finding.evidence.model_dump() if finding.evidence else {},
                "source_file":  finding.source_file,
                # severity: handled separately via conditional $set (see below)
            },
            "$addToSet": {
                "discovery_tools": {"$each": finding.discovery_tools},
                "tags":            {"$each": finding.tags},
                "references":      {"$each": finding.references},
            },
        },
        upsert=True,
    )

# Severity MAX: requires a separate conditional update
# After bulk_write, for newly inserted docs severity is already correct.
# For existing docs: use aggregation pipeline update to take max
def build_severity_max_update(fingerprint: str, incoming_sev: str) -> UpdateOne:
    incoming_rank = SEVERITY_RANK[SeverityLevel(incoming_sev)]
    return UpdateOne(
        filter={
            "fingerprint": fingerprint,
            f"_severity_rank": {"$lt": incoming_rank},   # only update if current is lower
        },
        update={"$set": {"severity": incoming_sev, "_severity_rank": incoming_rank}},
    )
```

**Note:** `_severity_rank` is an internal integer field stored alongside `severity` to enable efficient MAX comparison without client-side reads.

### Asset Upsert (non-destructive)
```python
def build_asset_upsert(
    host_normalized: str,
    host_type: str,
    ip: str | None,
    port_str: str | None,    # "443/tcp"  e.g. "443/tcp", "22/tcp"
    port_service: str | None,  # service name e.g. "https", "ssh"
    technology: str | None,
    tool_name: str,
    now: datetime,
) -> UpdateOne:
    # IPs and technologies: pure $addToSet — never overwrite
    add_to_set: dict = {"discovery_tools": tool_name}
    if ip:
        add_to_set["ip_addresses"] = ip
    if technology:
        add_to_set["technologies"] = technology

    # Ports: $set dot-notation per port key + $min for first_seen preservation
    # $min on first_seen:
    #   - new port: field doesn't exist → $min creates it with value=now
    #   - existing port: field exists with earlier date → $min keeps earlier date (now > first_seen)
    set_fields: dict = {"last_seen": now}
    min_fields: dict = {}

    if port_str:
        set_fields[f"port_metadata.{port_str}.last_seen"] = now
        set_fields[f"port_metadata.{port_str}.status"]    = "open"
        set_fields[f"port_metadata.{port_str}.service"]   = port_service or ""
        min_fields[f"port_metadata.{port_str}.first_seen"] = now

    update: dict = {
        "$setOnInsert": {
            "host_normalized": host_normalized,
            "type":            host_type,
            "first_seen":      now,
        },
        "$set":      set_fields,
        "$addToSet": add_to_set,
    }
    if min_fields:
        update["$min"] = min_fields

    return UpdateOne(
        filter={"host_normalized": host_normalized},
        update=update,
        upsert=True,
    )
```

### Bulk Execution
```python
async def execute_bulk(
    db,
    vuln_ops: list[UpdateOne],
    asset_ops: list[UpdateOne],
) -> BulkWriteResult:
    results = {}
    if vuln_ops:
        results["vulns"] = await db.vulnerabilities.bulk_write(
            vuln_ops, ordered=False
        )
    if asset_ops:
        results["assets"] = await db.assets.bulk_write(
            asset_ops, ordered=False
        )
    return results
```

---

## 7. Adapter YAML Specification

### 7.1 Extraction Modes

#### Mode 1: `flat`
One JSON object = one finding. Used by Nuclei, Nmap, TruffleHog, Shodan.
```yaml
extraction:
  mode: flat
  findings_path: "$"          # root is already the finding (JSONL)
  # OR
  findings_path: "$[*]"       # root is array of findings (JSON Array)
```

#### Mode 2: `nested_join`
Findings live in one array; metadata lives in another. A JOIN key connects them.
Used by Invicti, Acunetix, Burp Suite (JSON export).
```yaml
extraction:
  mode: nested_join
  findings_path: "$.scans[*].vulnerability_types[*]"   # iterate this
  lookups:
    location:
      source_path: "$.scans[*].locations[*]"    # the "right table"
      key_field:   "loc_id"                     # key in right table
      join_on:     "$.loc_id"                   # field in finding (left table)
  context_inject:
    # Fields from parent scope injected into every finding
    scan_host:      "$.scans[?(@.vulnerability_types)].info.host"
    scan_start:     "$.scans[?(@.vulnerability_types)].info.start_date"
```

Resolved finding object looks like:
```python
{
  # original vulnerability_type fields
  "vt_id": "...",
  "name":  "...",
  "loc_id": 2,

  # injected context (prefixed with "ctx_")
  "ctx_scan_host":  "https://example.com",
  "ctx_scan_start": "2026-03-31T04:20:45Z",

  # resolved lookup (prefixed with "lkp_<name>_")
  "lkp_location_url":        "https://example.com/api/chat",
  "lkp_location_path":       "/api/chat",
  "lkp_location_input_data": [...],
}
```

#### Mode 3: `envelope`
Report wraps all findings in a top-level envelope with scan metadata.
Used by Burp Suite JSON, Semgrep, OWASP ZAP.
```yaml
extraction:
  mode: envelope
  findings_path: "$.issue_events[*].issue"   # Burp: issue_events array
  # No JOIN needed; metadata available in parent scope
  context_inject:
    scan_host: "$.target[0].host"
```

### 7.2 Field Mapping Rules

Mapping values can be:

| Type | Syntax | Example |
|---|---|---|
| JSONPath from finding | `"$.field.nested"` | `"$.info.name"` |
| JSONPath from lookup | `"$.lkp_location.url"` | for nested_join results |
| JSONPath from context | `"$.ctx_scan_host"` | for injected context |
| Static string | `"'static_value'"` (quoted) | `"'info'"` |
| Static list | `["val1", "val2"]` | `["port_open"]` |
| Null / skip | `null` | field will be None |

#### `sources` — Field Aliases (scanner format resilience)

When a scanner changes a field name across versions, `sources` lets you list multiple JSONPath candidates.
The mapper evaluates them **in order** and uses the **first non-null result**. Zero Python code changes needed.

```yaml
mappings:
  target.url:
    sources:
      - "$.matched-at"       # Nuclei v2/v3 (current)
      - "$.matched_at"       # hypothetical v4 rename
      - "$.url"              # ultimate fallback
    # shorthand (single source, no aliases needed):
    # target.url: "$.matched-at"

  evidence.request:
    sources:
      - "$.request"          # Nuclei standard
      - "$.http.request"     # alternate structure
      - "$.raw_request"      # another variant
```

**When to add an alias:** When a scanner release changes a field name, open the YAML, prepend the old path as the first `sources` entry. The test suite (`adapters/nuclei.sample.jsonl` + `adapters/nuclei.expected.json`) will fail CI if the format breaks — that's the signal to update.

#### `required_fields` — Validation Gate

Fields listed here must be non-None after mapping. If any are missing, the finding is **quarantined** (moved to `quarantine/<scanner>/`) with a reason log, instead of being silently inserted with nulls or silently dropped.

```yaml
# Every adapter should declare these at minimum:
required_fields:
  - target.hostname          # need at least a target
  - identity.standardized_rule_id   # need to know what was found
  - severity                 # need to know how bad
```

Quarantine record written alongside the file:
```json
{
  "file": "nuclei_scan_2026-04-19.jsonl",
  "line": 42,
  "reason": "required_field_missing",
  "missing_fields": ["identity.standardized_rule_id"],
  "raw_finding": { ... }
}
```

**Why this matters:** Without `required_fields`, a scanner format change silently inserts thousands of documents with `null` fingerprints, corrupting the DB. Quarantine gives you a recoverable failure — fix the YAML, re-drop the quarantined file.

#### `evidence_limits` — Truncation Config (per adapter)

Controls what gets stored in `evidence.raw` and `evidence.response`. Prevents document-size crashes.

```yaml
evidence_limits:
  max_response_size_kb: 512      # truncate response body if larger; default 512
  skip_binary_content: true      # do NOT store body if Content-Type is binary
                                 # (application/zip, application/octet-stream, etc.)
  binary_types:                  # MIME types considered binary (override default list)
    - "application/zip"
    - "application/octet-stream"
    - "application/pdf"
    - "application/x-executable"
  max_raw_size_kb: 1024          # truncate evidence.raw dict if serialized size exceeds this
```

Truncation behavior:
```python
# If response > max_response_size_kb:
evidence.response = response[:max_bytes]
evidence.raw["_response_truncated"] = True
evidence.raw_truncated = True
evidence.raw_original_size_kb = original_kb

# If Content-Type is binary:
evidence.response = f"[BINARY SKIPPED: content-type={ct}, size={size_kb}KB]"
evidence.raw_truncated = True
```

### 7.3 Transform Pipeline

Each mapping can optionally pipe through transforms:
```yaml
mappings:
  severity:
    source: "$.severity"
    transform:
      - type: integer_map        # int → string via map table
        map: {0: info, 1: low, 2: medium, 3: high, 4: critical}

  identity.standardized_rule_id:
    source: "$.app_id"
    transform:
      - type: regex_extract      # extract substring
        pattern: 'acx/\d+/(.+)\.yaml$'
        group: 1
        prefix: "invicti:"       # prepend prefix to result

  identity.cve:
    source: "$.tags"
    transform:
      - type: filter_by_prefix   # keep only tags starting with "CVE-"
        prefix: "CVE-"

  target.port:
    source: "$.port"
    transform:
      - type: cast_int

  evidence.raw:
    source: "$"                  # entire finding object
    transform:
      - type: passthrough        # no-op, just store as dict
```

Available transforms:
```
passthrough         - identity (store as-is)
integer_map         - int → string via explicit map
string_map          - string → string via explicit map  
regex_extract       - extract capture group from string
regex_replace       - replace pattern in string
filter_by_prefix    - filter list to items with prefix
cast_int            - cast to integer
cast_str            - cast to string
split               - split string by delimiter into list
join                - join list into string by delimiter
slugify             - "Some Text" → "some-text"
strip_scheme        - "https://host" → "host"
url_path_only       - "https://host/path?q=1" → "/path"
url_hostname_only   - "https://host/path" → "host"
```

### 7.4 Full Adapter Examples

---

#### `adapters/nuclei.yaml`
```yaml
scanner: nuclei
finding_type_default: vulnerability
input:
  format: auto          # auto-detect: json-array or jsonl

extraction:
  mode: flat
  findings_path: "$[*]"  # json-array; for jsonl use "$"

finding_type_rules:
  - if_tag_contains: ["cve"]
    set_type: vulnerability
  - if_tag_contains: ["ssl", "tls"]
    set_type: ssl_finding
  - if_category_equals: ["exposure"]
    set_type: exposure
  - if_tag_contains: ["misconfig"]
    set_type: misconfiguration
  - if_tag_contains: ["tech", "detect"]
    set_type: exposure
  - default: vulnerability

mappings:
  target.ip:                     "$.ip"
  target.hostname:               "$.host"
  target.url:                    "$.matched-at"
  target.port:
    source: "$.port"
    transform: [{type: cast_int}]
  target.protocol:               "$.scheme"

  identity.raw_rule_id:          "$.template-id"
  identity.standardized_rule_id:
    source: "$.template-id"
    transform:
      - type: regex_extract
        pattern: '(CVE-\d{4}-\d+)'
        group: 1
        fallback_source: "$.template-id"   # if no CVE match, prefix with "nuclei:"
        fallback_prefix: "nuclei:"
  identity.name:                 "$.info.name"
  identity.category:             "$.info.tags[0]"
  identity.cve:
    source: "$.info.classification.cve-id"
    transform: [{type: passthrough}]
  identity.cwe:                  "$.info.classification.cwe-id"
  identity.cvss_score:           "$.info.classification.cvss-metrics[0].score"
  identity.cvss_vector:          "$.info.classification.cvss-metrics[0].vector"

  severity:                      "$.info.severity"

  evidence.request:              "$.request"
  evidence.response:             "$.response"
  evidence.matched_at:           "$.matched-at"
  evidence.extracted:            "$.extracted-results"
  evidence.curl_command:         "$.curl-command"
  evidence.raw:                  "$"

  tags:                          "$.info.tags"
  references:                    "$.info.reference"
```

---

#### `adapters/nmap.yaml`
```yaml
scanner: nmap
finding_type_default: port_service
input:
  format: json_array

extraction:
  mode: flat
  findings_path: "$[*]"

finding_type_rules:
  - default: port_service

mappings:
  target.ip:                     "$.address"
  target.port:
    source: "$.port"
    transform: [{type: cast_int}]
  target.protocol:               "$.protocol"
  target.hostname:               "$.hostname"

  identity.raw_rule_id:          "$.service.name"
  identity.standardized_rule_id:
    source: "$.service.name"
    transform: [{type: slugify, prefix: "nmap:"}]
  identity.name:                 "$.service.name"
  identity.category:             "'port_open'"

  severity:                      "'info'"

  evidence.matched_at:
    source: "$.service.version"
  evidence.raw:                  "$"

  tags:
    source: ["$.service.product", "$.service.extrainfo"]
    transform: [{type: filter_empty}]
```

---

#### `adapters/invicti.yaml`
```yaml
scanner: invicti
finding_type_default: vulnerability
input:
  format: json_object   # root is an object, not array

extraction:
  mode: nested_join
  findings_path: "$.scans[*].vulnerability_types[*]"
  lookups:
    location:
      source_path: "$.scans[*].locations[*]"
      key_field:   "loc_id"
      join_on:     "$.loc_id"
  context_inject:
    scan_host:  "$.scans[0].info.host"
    scan_start: "$.scans[0].info.start_date"

finding_type_rules:
  - if_category_equals: ["configuration"]
    set_type: misconfiguration
  - if_tag_contains: ["ssl", "tls", "weak_crypto"]
    set_type: ssl_finding
  - if_tag_contains: ["information_disclosure"]
    set_type: exposure
  - if_tag_contains: ["llm"]
    set_type: vulnerability
  - default: vulnerability

severity_mapping:
  type: integer_map
  source: "$.severity"
  map: {0: info, 1: low, 2: medium, 3: high, 4: critical}

mappings:
  target.url:                    "$.lkp_location_url"
  target.path:                   "$.lkp_location_path"
  target.hostname:
    source: "$.ctx_scan_host"
    transform: [{type: url_hostname_only}]

  identity.raw_rule_id:          "$.app_id"
  identity.standardized_rule_id:
    source: "$.app_id"
    transform:
      - type: regex_extract
        pattern: 'acx/\d+/(.+)\.yaml$'
        group: 1
        prefix: "invicti:"
  identity.name:                 "$.name"
  identity.category:             "$.type"
  identity.cve:
    source: "$.tags"
    transform: [{type: filter_by_prefix, prefix: "CVE-"}]
  identity.cwe:
    source: "$.tags"
    transform: [{type: filter_by_prefix, prefix: "CWE-"}]
  identity.cvss_score:           "$.cvss4_score"
  identity.cvss_vector:          "$.cvss4"

  severity:                      "$.severity"   # handled by severity_mapping

  evidence.matched_at:           "$.lkp_location_url"
  evidence.details_template:     "$.details_template"
  evidence.raw:                  "$"

  tags:                          "$.tags"
  references:                    "$.refs[*].url"
```

---

#### `adapters/trufflehog.yaml`
```yaml
# TruffleHog v3 JSON output (--json flag)
# Each line: {"SourceMetadata": {...}, "SourceName": "...", "DetectorName": "AWS", "Raw": "...", "Verified": true}
scanner: trufflehog
finding_type_default: secret
input:
  format: jsonl

extraction:
  mode: flat
  findings_path: "$"

finding_type_rules:
  - default: secret

mappings:
  target.url:                    "$.SourceMetadata.Data.Git.link"
  target.hostname:
    source: "$.SourceMetadata.Data.Git.link"
    transform: [{type: url_hostname_only}]

  identity.raw_rule_id:          "$.DetectorName"
  identity.standardized_rule_id:
    source: "$.DetectorName"
    transform: [{type: slugify, prefix: "trufflehog:"}]
  identity.name:
    source: "$.DetectorName"
    transform: [{type: passthrough, prefix: "Exposed Secret: "}]
  identity.category:
    source: "$.DetectorName"
    transform: [{type: slugify, prefix: "secret_"}]

  severity:                      "'high'"   # secrets default to high

  evidence.secret_type:          "$.DetectorName"
  evidence.repo_url:             "$.SourceMetadata.Data.Git.repository"
  evidence.commit_hash:          "$.SourceMetadata.Data.Git.commit"
  evidence.file_path:            "$.SourceMetadata.Data.Git.file"
  evidence.line_number:
    source: "$.SourceMetadata.Data.Git.line"
    transform: [{type: cast_int}]
  # NOTE: "$.Raw" intentionally NOT mapped to avoid storing actual secret value
  # Store only the detector name and verified status
  evidence.raw:
    source: "$"
    transform:
      - type: omit_keys
        keys: ["Raw", "RawV2"]   # Redact secret values before storage

  tags:
    source: ["$.DetectorType", "$.DetectorName"]
    static: ["secret", "credential"]
```

---

#### `adapters/burp.yaml`
```yaml
# Burp Suite Professional — "Save items" as JSON
# Structure: {"issue_events": [{"issue": {...}, "type": "issue_found"}]}
scanner: burp
finding_type_default: vulnerability
input:
  format: json_object

extraction:
  mode: envelope
  findings_path: "$.issue_events[?(@.type == 'issue_found')].issue"
  context_inject:
    scan_host: "$.target[0].host"

finding_type_rules:
  - if_name_contains: ["Cross-site scripting", "SQL injection", "Command injection"]
    set_type: vulnerability
  - if_name_contains: ["SSL", "TLS", "certificate"]
    set_type: ssl_finding
  - if_name_contains: ["Information disclosure", "path disclosure"]
    set_type: exposure
  - default: vulnerability

mappings:
  target.url:                    "$.path"
  target.hostname:               "$.ctx_scan_host"
  target.port:
    source: "$.origin"
    transform: [{type: url_port_only}]
  target.protocol:
    source: "$.origin"
    transform: [{type: url_scheme_only}]

  identity.raw_rule_id:          "$.type"
  identity.standardized_rule_id:
    source: "$.type"
    transform: [{type: slugify, prefix: "burp:"}]
  identity.name:                 "$.name"
  identity.category:
    source: "$.issueType"
    transform: [{type: slugify}]

  severity:
    source: "$.severity"
    transform:
      - type: string_map
        map:
          high:           high
          medium:         medium
          low:            low
          information:    info
          false_positive: info

  evidence.request:              "$.requestResponse[0].request"
  evidence.response:             "$.requestResponse[0].response"
  evidence.matched_at:           "$.path"
  evidence.raw:                  "$"

  tags:
    static: ["burp", "dast"]
```

---

## 8. New Worker Architecture

### 8.1 Directory Structure (post-refactor)
```
worker/
├── Dockerfile
├── Dockerfile.dev
├── requirements.txt
├── ingestion_worker.py          # Main event loop (mostly unchanged)
├── data/                        # Runtime data (Docker volume mount)
│   ├── incoming/                # ← Scanners DROP files here
│   │   ├── nuclei/              #   folder name = scanner name = adapter key
│   │   ├── nmap/
│   │   ├── invicti/
│   │   ├── trufflehog/
│   │   └── burp/
│   ├── archive/                 # ← Processed files moved here (timestamped)
│   │   └── nuclei/
│   └── quarantine/              # ← Failed files + .error.json sidecar
│       └── nuclei/
└── app/
    ├── config.py                # Settings (unchanged)
    ├── db.py                    # Motor client + index creation
    │
    ├── udm/                     # NEW: Universal Data Model
    │   ├── __init__.py
    │   ├── models.py            # UniversalFinding, UDMTarget, UDMIdentity, UDMEvidence
    │   ├── enums.py             # SeverityLevel, FindingType literals
    │   └── fingerprint.py      # build_fingerprint() with formula matrix
    │
    ├── core/                    # Shared utilities
    │   ├── __init__.py
    │   ├── canonical.py         # Severity normalization
    │   ├── host_classification.py
    │   └── jsonpath_utils.py    # NEW: JSONPath evaluation helpers
    │
    ├── adapters/                # NEW: Config-driven adapter system
    │   ├── __init__.py
    │   ├── base.py              # AdapterConfig Pydantic model (YAML schema)
    │   ├── loader.py            # Load + validate YAML configs from adapters/ dir
    │   ├── extractor.py         # Extraction strategies (flat, nested_join, envelope)
    │   ├── mapper.py            # JSONPath mapping + transform pipeline
    │   ├── registry.py          # Map scanner name → YAML config
    │   └── configs/             # YAML adapter definitions
    │       ├── nuclei.yaml
    │       ├── nmap.yaml
    │       ├── invicti.yaml
    │       ├── trufflehog.yaml
    │       └── burp.yaml
    │
    ├── engine/                  # NEW: Universal ingestion engine
    │   ├── __init__.py
    │   ├── processor.py         # Main process_file() entry point
    │   ├── upsert.py            # build_vuln_upsert(), build_asset_upsert()
    │   ├── recalculator.py      # Asset stats recalculation (post-bulk)
    │   └── file_lifecycle.py    # move_to_archive(), move_to_quarantine()
    │
    ├── archive.py               # Unchanged
    └── snapshots.py             # Unchanged
```

### 8.2 Data Flow (New)
```
ingestion_worker.py
  └── queue_consumer()
        └── get_adapter_config(scanner_name)    ← registry.py: name → YAML
              └── AdapterConfig.load("nuclei.yaml")
                    └── extract_findings(file_path, config)   ← extractor.py
                          # yields raw dict per finding (post-JOIN if nested_join)
                          └── map_finding(raw_dict, config)   ← mapper.py
                                # returns UniversalFinding (Pydantic validated)
                                └── build_fingerprint(finding)  ← fingerprint.py
                                      └── collect → List[UniversalFinding]

        └── build_bulk_ops(findings)             ← upsert.py
              # returns (vuln_ops, asset_ops) lists

        └── db.vulnerabilities.bulk_write(vuln_ops)
        └── db.assets.bulk_write(asset_ops)
        └── recalculate_assets(touched_hosts)    ← recalculator.py
        └── mark_snapshot_dirty()
        └── move_file_to_archive_or_quarantine() ← file_lifecycle.py
```

---

### 8.3 File Lifecycle Management

#### Folder Convention

```
worker/data/
├── incoming/          ← Scanners DROP report files here
│   ├── nuclei/        ← folder name = scanner name = adapter config key
│   ├── nmap/
│   ├── invicti/
│   ├── trufflehog/
│   └── burp/
│
├── archive/           ← Successfully processed files moved here
│   ├── nuclei/
│   ├── nmap/
│   └── ...
│
└── quarantine/        ← Failed files moved here, with sidecar error report
    ├── nuclei/
    ├── nmap/
    └── ...
```

**Folder name → adapter lookup rule:**  
The subfolder name under `incoming/` is the `scanner_name`. The registry looks up `adapters/configs/<scanner_name>.yaml`. Dropping a file into `incoming/invicti/` automatically uses the Invicti adapter — no config needed.

To add a new scanner: create the YAML adapter + `mkdir data/incoming/<scanner_name>/`. Done.

---

#### File Naming Convention

Files are renamed on move to prevent collisions across multiple scan runs:

```
Original:  nuclei_scan.json
Archive:   nuclei_scan-20260419T143022Z.json         # ISO 8601 UTC timestamp
Quarantine: nuclei_scan-20260419T143022Z.json        # same format
Sidecar:   nuclei_scan-20260419T143022Z.error.json   # written alongside quarantined file
```

Timestamp format: `%Y%m%dT%H%M%SZ` (UTC, no separators for filesystem safety).

---

#### Complete File Lifecycle State Machine

```
                    ┌─────────────────────────┐
                    │  incoming/<scanner>/     │
                    │  report.json             │
                    └────────────┬────────────┘
                                 │
                    PollingObserver detects file
                                 │
                    Wait until file is stable
                    (size unchanged for 5 seconds)
                                 │
                    ┌────────────▼────────────┐
                    │  Load adapter config     │
                    │  (registry lookup)       │
                    └────────────┬────────────┘
                                 │
                         ┌───────┴────────┐
                         │ Config found?  │
                    No ◄──┘                └──► Yes
                    │                           │
          ┌─────────▼──────────┐    ┌───────────▼──────────┐
          │ QUARANTINE          │    │ extract_findings()   │
          │ reason: no_adapter  │    │ map_finding() × N    │
          └─────────────────────┘    │ build_fingerprint()  │
                                     └───────────┬──────────┘
                                                  │
                                     ┌────────────▼────────────┐
                                     │ required_fields check    │
                                     │ per finding              │
                                     └────────────┬────────────┘
                                                  │
                              ┌───────────────────┴──────────┐
                              │ Any finding fails validation? │
                   Yes ◄──────┘                               └──► No (all valid)
                    │                                               │
          ┌─────────▼─────────────┐               ┌───────────────▼──────────┐
          │ QUARANTINE             │               │ bulk_write to MongoDB     │
          │ reason: validation     │               │ (vuln_ops + asset_ops)    │
          │ sidecar lists bad rows │               └───────────────┬──────────┘
          └────────────────────────┘                               │
                                                    ┌──────────────┴───────────┐
                                                    │  bulk_write succeeded?   │
                                         Yes ◄──────┘                          └──► No
                                          │                                          │
                             ┌────────────▼──────────┐             ┌────────────────▼──┐
                             │ ARCHIVE                │             │ QUARANTINE          │
                             │ recalc_assets()        │             │ reason: db_error    │
                             │ mark_snapshot_dirty()  │             │ sidecar has         │
                             └───────────────────────┘             │ exception traceback │
                                                                    └─────────────────────┘
```

**Note on partial failures:** If 950 out of 1000 findings succeed and 50 fail `required_fields` check, the current policy is **fail-whole-file** (quarantine everything). This is safer than partial ingestion which can leave the DB in an inconsistent state. The sidecar lists exactly which rows failed and why, so the operator can fix the source and re-drop.

---

#### Quarantine Sidecar Format

Every quarantined file gets a `<filename>.error.json` sidecar written alongside it:

```json
{
  "quarantined_at": "2026-04-19T14:30:22Z",
  "original_filename": "nuclei_scan.json",
  "scanner": "nuclei",
  "reason": "validation_error",
  "summary": "3 findings failed required_fields check",
  "stats": {
    "total_findings":    1000,
    "failed_findings":   3,
    "succeeded_findings": 0
  },
  "errors": [
    {
      "finding_index": 41,
      "reason": "required_field_missing",
      "missing_fields": ["identity.standardized_rule_id"],
      "raw_finding_preview": { "template-id": null, "host": "example.com" }
    },
    {
      "finding_index": 207,
      "reason": "required_field_missing",
      "missing_fields": ["target.hostname", "severity"],
      "raw_finding_preview": { "info": { "severity": null }, "host": null }
    }
  ],
  "possible_causes": [
    "Scanner output format may have changed — check adapter YAML mappings",
    "Adapter: worker/app/adapters/configs/nuclei.yaml"
  ]
}
```

Other `reason` values:
```
no_adapter        → no YAML config found for this scanner folder name
validation_error  → one or more findings failed required_fields
db_error          → MongoDB bulk_write threw an exception
parse_error       → file is not valid JSON / JSONL
file_too_large    → file exceeds configured max_file_size_mb
```

---

#### `file_lifecycle.py` — Implementation Contract

```python
# worker/app/engine/file_lifecycle.py

def move_to_archive(
    file_path: Path,
    scanner: str,
    archive_root: Path,
) -> Path:
    """Move successfully processed file to archive with timestamp suffix."""
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    stem = file_path.stem          # "nuclei_scan"
    suffix = file_path.suffix      # ".json"
    dest_name = f"{stem}-{timestamp}{suffix}"
    dest = archive_root / scanner / dest_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    file_path.rename(dest)
    return dest


def move_to_quarantine(
    file_path: Path,
    scanner: str,
    quarantine_root: Path,
    error: QuarantineError,          # dataclass with reason, errors[], stats
) -> Path:
    """Move failed file to quarantine and write .error.json sidecar."""
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    stem = file_path.stem
    suffix = file_path.suffix
    dest_name = f"{stem}-{timestamp}{suffix}"
    dest = quarantine_root / scanner / dest_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    file_path.rename(dest)

    sidecar = dest.with_suffix("").with_suffix(".error.json")
    sidecar.write_text(
        json.dumps(error.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )
    return dest
```

---

#### Re-processing a Quarantined File

Manual recovery workflow:
```bash
# 1. Inspect the sidecar to understand what failed
cat worker/data/quarantine/nuclei/nuclei_scan-20260419T143022Z.error.json

# 2. Fix the adapter YAML if it was a mapping issue
vim worker/app/adapters/configs/nuclei.yaml

# 3. Re-drop the quarantined file back into incoming to reprocess
cp worker/data/quarantine/nuclei/nuclei_scan-20260419T143022Z.json \
   worker/data/incoming/nuclei/nuclei_scan-fixed.json
# Watchdog picks it up automatically
```

---

## 9. Implementation Plan (Step-by-Step)

### Phase 0 — Preparation (before writing any new code)
**Goal:** Ensure tests pass; establish baseline.

- [ ] **0.1** Run existing tests; record baseline pass rate
- [ ] **0.2** Add `pytest` + `pytest-asyncio` to `worker/requirements.txt` if not present
- [ ] **0.3** Create `worker/tests/` directory with `conftest.py` (MongoDB test fixtures)
- [ ] **0.4** Write integration test that ingests the existing Nuclei sample file and asserts MongoDB state
  - This test must PASS against the OLD code (baseline)
  - Same test will be used to verify the NEW code after refactor

---

### Phase 1 — Universal Data Model
**Goal:** Define the Pydantic v2 UDM. Zero runtime behavior change.

- [ ] **1.1** Create `worker/app/udm/enums.py`
  - `SeverityLevel` enum + `SEVERITY_RANK` dict
  - `FindingType` Literal type
  
- [ ] **1.2** Create `worker/app/udm/models.py`
  - `UDMTarget`, `UDMIdentity`, `UDMEvidence`, `EvidenceSnapshot`
  - `UniversalFinding` with all fields and `model_config`
  
- [ ] **1.3** Create `worker/app/udm/fingerprint.py`
  - `build_fingerprint(finding_type, target, identity, evidence) -> str`
  - Unit tests: one test case per finding_type variant

- [ ] **1.4** Add `worker/app/core/jsonpath_utils.py`
  - Thin wrapper around `jsonpath-ng` library
  - `extract(obj, path) -> Any | None`
  - `extract_all(obj, path) -> list[Any]`

**Deliverable:** `from worker.app.udm.models import UniversalFinding` works; all unit tests pass.

---

### Phase 2 — Adapter Config System
**Goal:** YAML configs load and produce valid `UniversalFinding` objects.

- [ ] **2.1** Create `worker/app/adapters/base.py`
  - `AdapterConfig` Pydantic model (validates YAML structure)
  - Sub-models: `ExtractionConfig`, `LookupConfig`, `FieldMapping`, `Transform`
  
- [ ] **2.2** Create `worker/app/adapters/loader.py`
  - `load_adapter(scanner_name: str) -> AdapterConfig`
  - Searches `worker/app/adapters/configs/<scanner_name>.yaml`
  - Validates against `AdapterConfig` schema; raises `AdapterConfigError` on invalid

- [ ] **2.3** Create `worker/app/adapters/extractor.py`
  - `extract_findings(file_path, config) -> Iterator[dict]`
  - Implements `flat`, `nested_join`, `envelope` modes
  - Handles `json_array`, `jsonl`, `json_object`, `auto` input formats

- [ ] **2.4** Create `worker/app/adapters/mapper.py`
  - `map_finding(raw_dict, config) -> UniversalFinding`
  - Evaluates all `mappings` from config
  - Runs transform pipeline per field
  - Calls `build_fingerprint()` at end

- [ ] **2.5** Write adapter YAML files
  - `configs/nuclei.yaml` (must produce identical output to old adapter)
  - `configs/nmap.yaml`
  - `configs/invicti.yaml`
  - `configs/trufflehog.yaml`
  - `configs/burp.yaml`

- [ ] **2.6** Unit tests per adapter
  - `tests/adapters/test_nuclei_adapter.py` — use sample Nuclei JSONL
  - `tests/adapters/test_invicti_adapter.py` — use `invicti-scan.json`
  - `tests/adapters/test_trufflehog_adapter.py` — use sample TruffleHog output

**Deliverable:** `map_finding(raw, nuclei_config)` produces a valid `UniversalFinding` with correct fingerprint.

---

### Phase 3 — New Ingestion Engine
**Goal:** Replace per-finding individual DB ops with bulk upserts.

- [ ] **3.1** Create `worker/app/engine/upsert.py`
  - `build_vuln_upsert(finding, now) -> UpdateOne`
  - `build_asset_upsert(...) -> UpdateOne`
  - `build_severity_max_update(fingerprint, severity) -> UpdateOne`

- [ ] **3.2** Create `worker/app/engine/processor.py`
  - `process_file(file_path, scanner_name) -> ProcessingSummary`
  - Replaces `worker/app/scanners/nuclei/processor.py`
  - Steps: load adapter → extract → map → collect ops → bulk_write → recalc → **move to archive or quarantine**

- [ ] **3.3** Create `worker/app/engine/file_lifecycle.py`
  - `move_to_archive(file_path, scanner, archive_root) -> Path`
  - `move_to_quarantine(file_path, scanner, quarantine_root, error) -> Path`
  - Timestamp format: `%Y%m%dT%H%M%SZ` appended to original stem
  - On quarantine: write `<filename>.error.json` sidecar (see §8.3)
  - Bootstrap: `ensure_dirs(data_root)` creates all `incoming/archive/quarantine/<scanner>/` on startup

- [ ] **3.4** Create `worker/app/engine/recalculator.py`
  - `recalculate_assets(db, touched_hosts: set[str]) -> None`
  - Aggregation pipeline to compute `highest_severity`, `vulnerability_count`
  - Uses MongoDB `$group` + `$set` instead of Python-side aggregation

- [ ] **3.4** Add `_severity_rank` index to MongoDB
  - Add to `worker/app/db.py`'s `ensure_indexes()`

- [ ] **3.5** Update `ingestion_worker.py`
  - Replace `NucleiScannerAdapter` routing with `get_adapter_config(scanner_name)`
  - `process_file` now calls `engine.processor.process_file`

**Deliverable:** The Phase 0 integration test still passes with the new engine.

---

### Phase 4 — Remove Old Code (Cleanup)
**Goal:** Delete dead code.

- [ ] **4.1** Delete `worker/app/scanners/nuclei/` directory
- [ ] **4.2** Delete shim files: `worker/app/models.py`, `worker/app/parser.py`, `worker/app/processor.py`
- [ ] **4.3** Delete `worker/app/fingerprint.py` (replaced by `udm/fingerprint.py`)
- [ ] **4.4** Update all imports throughout `worker/`
- [ ] **4.5** Verify no import of deleted modules remains

---

### Phase 5 — Backend Sync
**Goal:** Backend API uses UDM field names; remove duplicated logic.

- [ ] **5.1** Update `backend/app/schemas/vulnerability.py` to reflect new field names
  - `target.*` nested structure instead of flat `host`, `url`, `ip`, `port`
  - `identity.*` instead of flat `template_id`, `name`
  - `evidence.*` instead of flat `request`, `response`
  
- [ ] **5.2** Update `backend/app/routes/vulns.py` queries to use new field paths

- [ ] **5.3** Extract shared `host_classification.py` to a location importable by both
  - Options: copy to both (simple) OR create `shared/` package with Docker volume
  - Recommendation: duplicate is acceptable; add TODO comment for future mono-repo

- [ ] **5.4** Update `backend/app/services/assets_inventory.py` recalc logic
  - Use same aggregation pipeline as `engine/recalculator.py`

---

### Phase 6 — Add New Scanner (Validation)
**Goal:** Prove the zero-code-change promise works.

- [ ] **6.1** Add `configs/semgrep.yaml` adapter
- [ ] **6.2** Drop a Semgrep JSON report into `incoming/semgrep/`
- [ ] **6.3** Verify findings appear correctly in dashboard
- [ ] **6.4** Confirm NO Python code was changed

---

## 10. Migration Strategy

### For Existing Data in MongoDB

The refactor changes field names significantly (`template_id` → `identity.standardized_rule_id`, `matched_at` → `evidence.matched_at`, etc.). Two options:

**Option A: Clean start (Recommended for dev/staging)**
```bash
# Drop and recreate all collections
db.vulnerabilities.drop()
db.assets.drop()
db.dashboard_snapshots.drop()
```

**Option B: Migration script (for production with existing data)**
```python
# worker/scripts/migrate_v1_to_v2.py
# For each v1 document:
#   1. Build UDMTarget from old flat fields
#   2. Build UDMIdentity from template_id, name, etc.
#   3. Compute new SHA-256 fingerprint
#   4. Insert v2 document with schema_version=2
#   5. Archive v1 document
```

Schema version field (`schema_version`) enables coexistence:
- API reads both v1 (`schema_version: 1`) and v2 (`schema_version: 2`) documents
- Old documents served with backward-compatible serialization
- Migration runs as background job; switch API to v2-only after completion

---

## 11. Testing Checklist

### Unit Tests
- [ ] `build_fingerprint()` deterministic for same input
- [ ] `build_fingerprint()` different for same vuln on different URLs
- [ ] `build_fingerprint()` same for same vuln same URL (re-run)
- [ ] `SeverityLevel` MAX resolution: `critical` beats `high`
- [ ] JSONPath extraction: nested path, array path, missing path → None
- [ ] Transform `integer_map`: 0→info, 4→critical, out-of-range→unknown
- [ ] Transform `regex_extract`: match, no-match fallback, group capture

### Adapter Tests (per adapter YAML)
- [ ] Nuclei JSONL: correct fingerprint, finding_type, severity
- [ ] Nuclei JSON array: same result as JSONL for same findings
- [ ] Invicti: loc_id JOIN resolved correctly
- [ ] Invicti: 12 XSS findings on 12 different URLs → 12 different fingerprints
- [ ] TruffleHog: `Raw` field NOT stored in evidence (redacted)
- [ ] Burp: envelope extraction, host context injected

### Integration Tests (MongoDB required)
- [ ] New finding → inserted with correct fields
- [ ] Re-scan same finding → `last_seen` updated, `first_seen` unchanged (`$setOnInsert`)
- [ ] Same vuln found by Nuclei then Shodan → 1 document, `discovery_tools: ["nuclei", "shodan"]`
- [ ] Severity: Nuclei says `medium`, Shodan says `critical` → final severity = `critical`
- [ ] Asset upsert: Nmap finds ports [21, 23, 24]; Naabu re-scans finds only [21] → `port_metadata` still has 21, 23, 24 — ports 23 and 24 become `status: stale` after recalc, NOT deleted
- [ ] Port `first_seen` preserved: port 443 seen on day 1, re-scanned on day 7 → `port_metadata["443/tcp"].first_seen` remains day 1 date (not overwritten by $min)
- [ ] Status immutability: ingest scan A (finding X → Open); user sets finding X → Resolved; ingest scan B (unrelated findings) → finding X.status still Resolved
- [ ] Status immutability: ingest scan A (finding X → Open); user sets finding X → Resolved; ingest scan A again (finding X re-detected) → finding X.status still Resolved, only last_seen updated
- [ ] Evidence truncation: finding with response > 512KB → `evidence.raw_truncated = True`, stored response ≤ 512KB
- [ ] Binary skip: finding with application/zip response → response field = "[BINARY SKIPPED: ...]" not raw bytes
- [ ] Bulk write: 1000 findings → single `bulk_write` call (not 1000 individual ops)

### File Lifecycle Tests
- [ ] Success path: file in `incoming/nuclei/` → after processing, file moved to `archive/nuclei/<stem>-<timestamp>.json`
- [ ] Success path: original file no longer exists in `incoming/` after processing
- [ ] DB error path: simulated `bulk_write` exception → file moved to `quarantine/nuclei/` with `.error.json` sidecar
- [ ] Validation error path: finding missing `required_fields` → file quarantined, sidecar lists `missing_fields` and `finding_index`
- [ ] No adapter path: file dropped into `incoming/unknown_scanner/` → quarantined with `reason: no_adapter`
- [ ] Parse error path: malformed JSON file → quarantined with `reason: parse_error`
- [ ] Archive filename uniqueness: same filename processed twice → two timestamped files in archive, no overwrite
- [ ] Re-drop recovery: copy quarantined file back to `incoming/` → watchdog reprocesses it

### Regression Tests
- [ ] Existing Nuclei files in `incoming/nuclei/` still process correctly
- [ ] Dashboard snapshots still compute correctly after new schema

---

## Dependencies to Add

```txt
# worker/requirements.txt additions
jsonpath-ng==1.7.0      # JSONPath evaluation
pyyaml==6.0.2           # YAML adapter loading
```

---

*End of Specification*
