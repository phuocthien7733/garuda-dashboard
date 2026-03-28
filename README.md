# EASM Dashboard (Test And Watch)

Enterprise-style External Attack Surface Management (EASM) platform focused on Red Team / Pentest operations.

This system ingests scanner reports (currently Nuclei), normalizes findings, stores them in MongoDB, and provides a tactical SOC-style dashboard for triage, tracking, and attack-path exploration.

## 1. What This Project Solves

- Centralize external exposure findings (assets + vulnerabilities).
- Keep analyst triage decisions durable (`status`, `override_severity`).
- Separate active workload (hot findings) from archive.
- Provide high-signal visualizations for daily offensive operations:
  - priority pie
  - trend timeline
  - tech stack treemap
  - asset network spider
  - global GeoIP threat map
- Enforce RBAC (`admin`, `viewer`) with JWT sessions and optional MFA via email.

## 2. Core Architecture

High-level runtime:

1. Scanner drops JSON report into `worker/data/incoming/<scanner>/`.
2. Worker detects scanner adapter from folder name, parses report, canonicalizes fields.
3. Worker upserts `vulnerabilities` + recalculates `assets`.
4. Worker updates dashboard snapshot collections.
5. FastAPI serves APIs with RBAC and cursor pagination.
6. Vue frontend renders dashboard/inventory/detail pages via `/api`.
7. Caddy handles TLS and reverse proxy in production.

## 3. Tech Stack

- Backend: Python 3.11, FastAPI, Motor, Pydantic v2, PyJWT, bcrypt.
- Worker: Python 3.11, watchdog polling observer, Motor.
- DB: MongoDB 6.
- Frontend: Vue 3 + Vite + Pinia + Vue Router + ECharts.
- Infra: Docker + Docker Compose.
- Geo IP: MaxMind GeoLite2 City/ASN (`geoip2`) with weekly updater container.

## 4. Repository Structure

```text
backend/
  app/
    core/               # config, security, RBAC
    db/                 # mongo client + indexes
    routes/             # auth, stats, vulns, assets, users, map-data, graph
    schemas/            # API contracts
    services/           # snapshots, MFA, mailer, geoip, rate limiter
frontend/
  src/
    components/         # layout + charts + graphs
    stores/             # auth/session store
    views/              # dashboard, inventories, asset detail, users, login/mfa
worker/
  app/
    scanners/
      nuclei/           # nuclei adapter/parser/models/processor
      base.py           # scanner adapter protocol
    core/               # canonical normalization + host classification
    archive.py          # hot -> archive + retention purge
    snapshots.py        # recompute dashboard snapshots
  ingestion_worker.py   # queue consumer + watchdog loop
infra/caddy/Caddyfile   # TLS reverse proxy
docker-compose.yml      # dev stack
docker-compose.prod.yml # production stack
DEPLOYMENT.md           # production runbook
```

## 5. Data Model (Current)

Main collections:

- `assets`
  - `host`, `type`, `ip_addresses`, `open_ports`, `services`
  - `highest_severity`, `vulnerability_count`
  - `first_seen`, `last_seen`, `template_ids`

- `vulnerabilities` (hot set)
  - `fingerprint` (unique)
  - `asset_id`, `host`, `ip`, `port`
  - `template_id`, `matched_at`, `name`
  - `severity`, `override_severity`, `status`
  - `first_seen`, `last_seen`
  - scanner-specific fields are accepted with flexible schema

- `vulnerabilities_archive`
  - same shape as vulnerabilities + `archived_at`, `archived_reason`
  - TTL policy for long-term retention cleanup

- `users`
  - `username`, `email`, `role`
  - `password_hash`, `mfa_enabled`

Support collections:
- `dashboard_snapshots`, `dashboard_snapshot_state`
- `mfa_challenges`
- `revoked_tokens`
- `auth_rate_limits`

## 6. Worker Ingestion Behavior

### Input convention

Reports must be dropped into scanner folder:

- `worker/data/incoming/nuclei/*.json`

### Fingerprint and dedup

- Unique vulnerability ID:
  - `MD5(template_id + matched_at)`
- Never uses timestamp as unique key.

### Upsert logic

- New finding:
  - insert with `first_seen=now`, `last_seen=now`, `status=Open`, `severity=<normalized>`.
- Existing finding:
  - update only `last_seen`.
- Manual triage lock:
  - worker does not overwrite analyst `status` / `override_severity`.

### Parser resilience

- Core required fields are enforced.
- Non-core scanner fields are optional and tolerated.
- Unknown extra fields are accepted (`extra='allow'`) to survive scanner schema drift.

### Archive policy

- Non-open findings older than configured threshold are moved from `vulnerabilities` to `vulnerabilities_archive`.
- Archived records older than retention window are purged.
- Admin can manually archive/restore/delete via API/UI.

### Error handling

- Retry with capped attempts.
- Invalid or repeatedly failing files are moved to `worker/data/quarantine/<scanner>/` with error report.

## 7. Backend API and RBAC

Base:
- health: `/health`
- app APIs: `/api/*`

Auth:
- `POST /api/auth/login`
- `POST /api/auth/mfa/verify`
- `POST /api/auth/mfa/resend`
- `GET /api/auth/me`
- `PATCH /api/auth/me`
- `POST /api/auth/logout`

Read endpoints (`admin` + `viewer`):
- stats/trend/tech stack
- vulnerabilities list/recent/archive list
- assets list/detail/network/top
- graph/map-data

Write endpoints (`admin` only):
- vuln patch, bulk triage, archive/restore/delete (single + bulk)
- asset bulk triage
- user management (create/update/delete/password reset)

Session model:
- JWT includes `sub`, `role`, `exp`, `jti`.
- token lifetime: 18 hours.
- logout revokes token in `revoked_tokens`.
- optional MFA challenge flow before token issuance.

## 8. Frontend UX Modules

Major pages:

- Login + MFA verify.
- Dashboard:
  - Severity priority chart.
  - Attack surface trend.
  - Exposed tech stack treemap.
  - Top exposed assets.
  - PewPew global threat map.
- Asset Inventory.
- Asset Detail:
  - profile cards
  - vulnerability inventory
  - asset spider network graph
- Vulnerability Inventory:
  - hot/archive toggle
  - advanced filters + cursor pagination
  - bulk actions.
- User Profile + User Management.

RBAC in UI:
- viewer can inspect data only.
- admin can execute triage/archive/user actions.

## 9. Performance Design (Current)

- Cursor pagination (no heavy deep `skip` pagination).
- Canonical indexes for hot query paths.
- Snapshot-based dashboard endpoints to reduce expensive realtime aggregation.
- Worker-triggered snapshot refresh and dirty-flag strategy.
- Hot/archive split to keep active views responsive.

## 10. Local Development

Start dev stack:

```bash
docker compose up -d --build
```

Default ports:
- frontend: `http://localhost:5173`
- backend: `http://localhost:8000`
- mongodb: `localhost:27017` (dev only)

Useful logs:

```bash
docker compose logs --tail=200 backend
docker compose logs --tail=200 worker
docker compose logs --tail=200 frontend
```

Stop:

```bash
docker compose down
```

## 11. Production Deployment

Use the full runbook in:
- [`DEPLOYMENT.md`](./DEPLOYMENT.md)

Recommended command:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

## 12. GeoIP / PewPew Map Notes

- Backend endpoint: `GET /api/map-data`.
- GeoIP readers use:
  - `GeoLite2-City.mmdb`
  - `GeoLite2-ASN.mmdb`
- `geoip_updater` updates DB files on weekly cron (`GEOIP_UPDATE_CRON`).

## 13. Multi-Scanner Expansion Plan

Current worker already uses adapter-based scanner dispatch by folder (`incoming/<scanner>/`).

### A. Contract to add a new scanner

For scanner `X`, create:

```text
worker/app/scanners/x/
  __init__.py
  adapter.py
  parser.py
  models.py
  processor.py
```

Implement adapter contract from `worker/app/scanners/base.py`:
- `name`
- `incoming_folder`
- `supports(file_path)`
- `detect_input_format(file_path)`
- `process_file(file_path)`

Register scanner in:
- `worker/app/scanners/__init__.py`

This automatically activates folder routing:
- `worker/data/incoming/x/*.json`

### B. Canonical mapping requirements

Each new scanner parser/processor should map to canonical fields:
- `host`
- `severity`
- `name`
- stable fingerprint components (tool-specific, deterministic)
- `matched_at`/evidence equivalent

Normalize to project enums:
- severity: `critical|high|medium|low|info|unknown`
- status: `Open|Investigating|Accepted Risk|Resolved`

### C. Storage strategy for new scanners

Recommended:
- Keep single canonical `vulnerabilities` hot collection for unified triage/search/charts.
- Keep scanner identity fields (`source_tool`, `scanner`, `schema_version`) per document.
- Avoid storing massive raw blob metadata by default.

### D. Future implementation phases

Phase 1:
- Add adapters for `subfinder`, `httpx`, `naabu`.
- Expand asset enrichment (ports/services/host metadata).

Phase 2:
- Add templates for web app scanners (e.g., Nikto/ZAP normalized exports).
- Add scanner-specific quality scoring + confidence.

Phase 3:
- Add queue decoupling (Redis/Rabbit/Kafka) for horizontal worker scaling.
- Introduce per-scanner dead-letter queue and replay tools.

Phase 4:
- Add automated schema migration/version tooling per scanner format.
- Add integration tests per scanner fixture set.

## 14. Security and Operations Notes

- Do not commit real `.env` files or credentials.
- Rotate JWT/Mongo/SMTP credentials regularly.
- Keep `MONGO_SEED_DEFAULT_USERS=false` in production after bootstrap.
- Keep worker runtime folders writable by worker UID/GID.
- Monitor:
  - backend 401/403/429 patterns
  - worker quarantine rate
  - Mongo index health and snapshot freshness

---

If you plan to add a new scanner soon, start with an adapter skeleton under `worker/app/scanners/<scanner>/` and one fixture in `incoming/<scanner>/` to validate the full ingest-to-dashboard path quickly.
