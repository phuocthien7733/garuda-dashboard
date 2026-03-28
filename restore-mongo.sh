#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env.production}"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_ROOT/docker-compose.prod.yml}"
MONGO_SERVICE="${MONGO_SERVICE:-mongodb}"

backup_file=""
target_db_override=""
auto_yes="false"
drop_before_restore="true"

usage() {
  cat <<'EOF'
Usage:
  ./restore-mongo.sh <backup_file> [options]

Options:
  --db <name>        Target DB name override (default: MONGO_DB_NAME in env)
  --no-drop          Do not drop collections before restore
  --yes              Skip interactive confirmation
  -h, --help         Show help

Env overrides:
  ENV_FILE           Path to env file (default: ./.env.production)
  COMPOSE_FILE       Path to compose file (default: ./docker-compose.prod.yml)
  MONGO_SERVICE      Mongo service in compose (default: mongodb)

Examples:
  ./restore-mongo.sh ./backups/easm-20260328-120000.archive.gz
  ./restore-mongo.sh ./backups/easm.archive.gz --db easm_db --yes
  ./restore-mongo.sh ./backups/easm.archive.gz --no-drop
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --db)
      [[ $# -ge 2 ]] || { echo "ERROR: --db requires a value" >&2; exit 1; }
      target_db_override="$2"
      shift 2
      ;;
    --no-drop)
      drop_before_restore="false"
      shift
      ;;
    --yes)
      auto_yes="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -z "$backup_file" ]]; then
        backup_file="$1"
        shift
      else
        echo "ERROR: Unexpected argument: $1" >&2
        usage
        exit 1
      fi
      ;;
  esac
done

if [[ -z "$backup_file" ]]; then
  echo "ERROR: Missing <backup_file>" >&2
  usage
  exit 1
fi

if [[ ! -f "$backup_file" ]]; then
  echo "ERROR: Backup file not found: $backup_file" >&2
  exit 1
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

target_db="${target_db_override:-$MONGO_DB_NAME}"
drop_arg=""
if [[ "$drop_before_restore" == "true" ]]; then
  drop_arg="--drop"
fi

echo "Mongo restore plan:"
echo "  Backup:  $backup_file"
echo "  DB:      $target_db"
echo "  Service: $MONGO_SERVICE"
echo "  Drop:    $drop_before_restore"

if [[ "$auto_yes" != "true" ]]; then
  echo
  echo "WARNING: This operation can overwrite existing data."
  read -r -p "Type RESTORE to continue: " confirmation
  if [[ "$confirmation" != "RESTORE" ]]; then
    echo "Restore cancelled."
    exit 1
  fi
fi

cat "$backup_file" | docker compose \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE_FILE" \
  exec -T \
  -e MONGO_ROOT_USERNAME="$MONGO_ROOT_USERNAME" \
  -e MONGO_ROOT_PASSWORD="$MONGO_ROOT_PASSWORD" \
  -e MONGO_DB_NAME_TARGET="$target_db" \
  "$MONGO_SERVICE" \
  sh -lc "mongorestore \
    --host localhost \
    --port 27017 \
    --username \"\$MONGO_ROOT_USERNAME\" \
    --password \"\$MONGO_ROOT_PASSWORD\" \
    --authenticationDatabase admin \
    --db \"\$MONGO_DB_NAME_TARGET\" \
    --archive \
    --gzip \
    $drop_arg"

echo "Restore completed successfully."
