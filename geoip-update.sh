#!/bin/sh
set -eu

REASON="${1:-scheduled}"
GEOIP_DIR="${GEOIP_DIR:-/geoip}"
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"

log() {
  printf '%s [geoip-updater] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1"
}

if [ -z "$MAXMIND_LICENSE_KEY" ]; then
  log "MAXMIND_LICENSE_KEY is missing. Skip update ($REASON)."
  exit 0
fi

mkdir -p "$GEOIP_DIR"

download_edition() {
  edition="$1"
  destination="$2"
  tmp_dir="$(mktemp -d)"
  archive_file="$tmp_dir/${edition}.tar.gz"
  checksum_file="$tmp_dir/${edition}.sha256"
  url="https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

  log "Downloading ${edition}..."
  curl -fsSL "$url" -o "$archive_file"

  if curl -fsSL "${url}.sha256" -o "$checksum_file"; then
    expected="$(awk '{print $1}' "$checksum_file" | head -n 1)"
    actual="$(sha256sum "$archive_file" | awk '{print $1}')"
    if [ -n "$expected" ] && [ "$expected" != "$actual" ]; then
      rm -rf "$tmp_dir"
      log "Checksum mismatch for ${edition}. Keeping current database."
      exit 1
    fi
  fi

  tar -xzf "$archive_file" -C "$tmp_dir"
  mmdb_path="$(find "$tmp_dir" -type f -name "${edition}.mmdb" | head -n 1)"
  if [ -z "$mmdb_path" ]; then
    rm -rf "$tmp_dir"
    log "Cannot find ${edition}.mmdb in downloaded archive."
    exit 1
  fi

  cp "$mmdb_path" "${destination}.tmp"
  mv "${destination}.tmp" "$destination"
  rm -rf "$tmp_dir"
  log "Updated ${edition}."
}

download_edition "GeoLite2-City" "${GEOIP_DIR}/GeoLite2-City.mmdb"
download_edition "GeoLite2-ASN" "${GEOIP_DIR}/GeoLite2-ASN.mmdb"

date -u '+%Y-%m-%dT%H:%M:%SZ' > "${GEOIP_DIR}/last_update_utc.txt"
log "GeoIP update completed ($REASON)."
