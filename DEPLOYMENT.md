# Production Deployment

## Target

- Domain: `falcon.foxysec.dev`
- SSL: automatic Let's Encrypt via Caddy

## Before first deploy

1. Point DNS `A` record of `falcon.foxysec.dev` to the VPS public IP.
2. Open inbound ports `80` and `443` on the VPS firewall/security group.
3. Copy `.env.production.example` to `.env.production` and fill real secrets.
4. Ensure worker folders stay writable by the deployment user:

```bash
mkdir -p worker/data/incoming/nuclei worker/data/archive/nuclei
sudo chown -R $USER:$USER worker/data
chmod -R 755 worker/data
chown -R 1000:1000 worker/data
```

## Start production stack

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

## Notes

- In production, MongoDB is not published to the host.
- Frontend and backend are served through the same origin, so browser CORS pressure is minimized.
- SSL certificates are managed automatically by Caddy and stored in Docker volumes.
- `worker/data` remains a bind mount so scanner reports can be dropped into:
  - `worker/data/incoming/nuclei/`
  - future scanners can use their own folders under `incoming/`
- Existing `mongo_data/` bind mount from local dev should not be copied to production. Production compose uses a named volume instead to avoid host permission drift.
