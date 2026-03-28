FROM alpine:3.21

RUN apk add --no-cache bash curl tar ca-certificates coreutils tzdata

COPY geoip-update.sh /usr/local/bin/update-geoip.sh
COPY geoip-updater-entrypoint.sh /usr/local/bin/geoip-updater-entrypoint.sh

RUN chmod +x /usr/local/bin/update-geoip.sh /usr/local/bin/geoip-updater-entrypoint.sh \
    && mkdir -p /geoip

CMD ["/usr/local/bin/geoip-updater-entrypoint.sh"]
