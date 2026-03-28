#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env.production}"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_ROOT/docker-compose.prod.yml}"
MONGO_SERVICE="${MONGO_SERVICE:-mongodb}"

usage() {
  cat <<'EOF'
Usage:
  ./backup-mongo.sh [output_file]

Options via env:
  ENV_FILE        Path to env file (default: ./.env.production)
  COMPOSE_FILE    Path to compose file (default: ./docker-compose.prod.yml)
  MONGO_SERVICE   Mongo service name in compose (default: mongodb)
  MONGO_DB_NAME   Override target DB name (optional)

Examples:
  ./backup-mongo.sh
  ./backup-mongo.sh ./backups/easm-prod.archive.gz
  MONGO_DB_NAME=easm_db ./backup-mongo.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: ENV file not found: $ENV_FILE" >&2
  exit 1
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "ERROR: Compose file not found: $COMPOSE_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${MONGO_ROOT_USERNAME:?MONGO_ROOT_USERNAME is required}"
: "${MONGO_ROOT_PASSWORD:?MONGO_ROOT_PASSWORD is required}"
: "${MONGO_DB_NAME:?MONGO_DB_NAME is required}"

timestamp="$(date -u +%Y%m%d-%H%M%S)"
default_output="$PROJECT_ROOT/backups/easm-${MONGO_DB_NAME}-${timestamp}.archive.gz"
output_file="${1:-$default_output}"

mkdir -p "$(dirname "$output_file")"

echo "Starting Mongo backup..."
echo "  DB:      $MONGO_DB_NAME"
echo "  Output:  $output_file"
echo "  Service: $MONGO_SERVICE"

docker compose \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  exec -T \
  -e MONGO_ROOT_USERNAME="$MONGO_ROOT_USERNAME" \
  -e MONGO_ROOT_PASSWORD="$MONGO_ROOT_PASSWORD" \
  -e MONGO_DB_NAME="$MONGO_DB_NAME" \
  "$MONGO_SERVICE" \
  sh -lc 'mongodump \
    --host localhost \
    --port 27017 \
    --username "$MONGO_ROOT_USERNAME" \
    --password "$MONGO_ROOT_PASSWORD" \
    --authenticationDatabase admin \
    --db "$MONGO_DB_NAME" \
    --archive \
    --gzip' > "$output_file"

size_bytes="$(wc -c < "$output_file")"
if [[ "$size_bytes" -le 0 ]]; then
  rm -f "$output_file"
  echo "ERROR: Backup file is empty." >&2
  exit 1
fi

echo "Backup completed successfully."
echo "  Size: ${size_bytes} bytes"
