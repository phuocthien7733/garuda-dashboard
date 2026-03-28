#!/bin/sh
set -eu

GEOIP_UPDATE_CRON="${GEOIP_UPDATE_CRON:-0 3 * * 4}"

cat > /etc/crontabs/root <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${GEOIP_UPDATE_CRON} /usr/local/bin/update-geoip.sh scheduled >> /var/log/geoip-update.log 2>&1
EOF

/usr/local/bin/update-geoip.sh startup || true

exec crond -f -l 8
