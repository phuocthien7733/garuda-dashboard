# EASM Dashboard - Production Deployment Runbook

## 1. Scope

This document is the full deployment checklist for EASM Dashboard v1.0 on Linux VPS with domain + SSL.

Target stack:
- `backend` (FastAPI)
- `frontend` (Vue + Nginx)
- `worker` (ingestion)
- `mongodb` (MongoDB 6)
- `geoip_updater` (weekly MaxMind DB update)
- `caddy` (reverse proxy + TLS)

## 2. Prerequisites

Required on VPS:
- Docker Engine + Docker Compose plugin installed.
- Public DNS `A` record pointing to VPS IP for your domain (example: `falcon.foxysec.dev`).
- Firewall/security group open for TCP `80` and `443`.
- No other reverse proxy occupying port `80` or `443`.

Quick checks:

```bash
docker --version
docker compose version
sudo ss -ltnp | grep -E ':80|:443' || true
```

If another platform is using `80/443`, stop it first (do not remove volumes):

```bash
docker ps
docker stop <container_name_or_id>
```

## 3. Get Source

```bash
git clone <your-repo-url> easm-dashboard
cd easm-dashboard
```

## 4. Prepare Environment

Create production env file:

```bash
cp .env.production.example .env.production
```

Edit `.env.production` with real values.

Minimum required variables:
- `DOMAIN`
- `ACME_EMAIL`
- `MONGO_ROOT_USERNAME`
- `MONGO_ROOT_PASSWORD`
- `MONGO_DB_NAME`
- `MONGO_APP_USERNAME`
- `MONGO_APP_PASSWORD`
- `JWT_SECRET`
- `CORS_ORIGINS`

Recommended:
- `MAXMIND_LICENSE_KEY` for GeoIP map quality.
- SMTP variables if MFA email is enabled.

Example `CORS_ORIGINS`:

```env
CORS_ORIGINS=["https://falcon.foxysec.dev"]
```

Validate env interpolation before deploying:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml config >/dev/null
```

## 5. Worker Data Permissions

Create ingestion folders and set ownership for worker container user:

```bash
mkdir -p worker/data/incoming/nuclei worker/data/archive/nuclei worker/data/quarantine/nuclei
sudo chown -R 1000:1000 worker/data
sudo chmod -R 755 worker/data
```

## 6. First-Time Admin Strategy

By default, production disables default admin seed:
- `MONGO_SEED_DEFAULT_USERS=false`

For first bootstrap only, you have two options:
- Option A: temporarily set `MONGO_SEED_DEFAULT_USERS=true` in `.env.production`, deploy on empty Mongo volume, login, create real admin accounts, then switch back to `false`.
- Option B: keep `false` and create admin user directly in Mongo manually before first login flow.

Important:
- `mongo-init.js` runs only on first DB initialization for a new volume.

## 7. Build and Start Production

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

Check container status:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml ps
```

## 8. Post-Deploy Verification

Backend health:

```bash
curl -k -I https://falcon.foxysec.dev/health
```

UI:
- Open `https://falcon.foxysec.dev`
- Login with admin account
- Verify Dashboard, Asset Inventory, Vulnerability Inventory, Asset Detail, PewPew Map.

Worker flow:
- Drop a nuclei file into `worker/data/incoming/nuclei/`
- Confirm worker archives it into `worker/data/archive/nuclei/`
- Confirm vulnerabilities/assets updated in UI.

GeoIP updater:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail=120 geoip_updater
```

## 9. Operational Commands

Tail logs:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail=200 backend
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail=200 frontend
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail=200 worker
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail=200 caddy
```

Restart single service:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml restart backend
docker compose --env-file .env.production -f docker-compose.prod.yml restart frontend
docker compose --env-file .env.production -f docker-compose.prod.yml restart worker
```

Rolling redeploy after git pull:

```bash
git pull
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

## 10. Common Troubleshooting

`502 Bad Gateway` on login/API:
- Check backend logs.
- Verify Mongo credentials in `.env.production`.
- Confirm backend container is healthy and listening on `8000`.

`Authentication failed` (Mongo):
- `MONGO_APP_USERNAME`, `MONGO_APP_PASSWORD`, `MONGO_DB_NAME`, `MONGO_AUTH_SOURCE` must match seeded DB user.
- If DB volume already exists with old credentials, update env to match DB or recreate DB volume intentionally.

SSL warning / cert not issued:
- Confirm domain DNS points to VPS.
- Ensure ports `80/443` are reachable externally.
- Check caddy logs.

Worker `Permission denied` moving to archive:
- Re-apply `chown/chmod` on `worker/data`.

PewPew map empty:
- Check `MAXMIND_LICENSE_KEY`.
- Check `geoip_updater` logs and `backend` logs for GeoIP loading.

## 11. Backup and Rollback

Backup Mongo volume:

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml exec -T mongodb \
  mongodump --archive --gzip --db "$MONGO_DB_NAME" > backup-$(date +%F-%H%M).archive.gz
```

Emergency rollback to previous images:
- Revert git commit/tag.
- Run `docker compose ... up -d --build`.
- If schema/data issue occurs, restore Mongo backup.

## 12. Security Notes

- Never commit `.env.production`.
- Rotate `JWT_SECRET`, Mongo, SMTP credentials periodically.
- Keep `MONGO_SEED_DEFAULT_USERS=false` after first bootstrap.
- Prefer unique per-environment secrets (dev/staging/prod).
- Monitor logs for repeated `401/403/429` patterns.

## 13. Architecture Notes

- MongoDB is private to Docker network in production (not exposed to host port).
- Frontend and backend are same-origin through Caddy (`/api` reverse proxy).
- TLS certificates are managed automatically by Caddy.
- GeoIP databases are updated by `geoip_updater` on weekly cron (`GEOIP_UPDATE_CRON`).
