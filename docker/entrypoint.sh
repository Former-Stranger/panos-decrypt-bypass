#!/bin/sh
# Runs as root only long enough to make /data owned by PUID:PGID, then drops
# to that user. If the container is started with --user, it runs as-is.
set -e

if [ "$(id -u)" = "0" ]; then
    PUID="${PUID:-1000}"
    PGID="${PGID:-1000}"
    mkdir -p "${DATA_DIR:-/data}"
    # Only touch ownership when it's wrong, so large data dirs start fast.
    if [ "$(stat -c %u:%g "${DATA_DIR:-/data}")" != "${PUID}:${PGID}" ]; then
        chown -R "${PUID}:${PGID}" "${DATA_DIR:-/data}"
    fi
    exec setpriv --reuid="${PUID}" --regid="${PGID}" --clear-groups -- "$@"
fi
exec "$@"
