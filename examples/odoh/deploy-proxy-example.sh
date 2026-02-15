#!/bin/sh
set -eu

# RFC 9230 trust separation warning:
# Deploy this proxy under a different operator and infrastructure than the target.
# Do not co-host proxy and target in production.

DOHPROXYD_BIN="${DOHPROXYD_BIN:-/usr/local/sbin/dohproxyd}"
RUN_AS="${RUN_AS:-dohd}"
LISTEN_PORT="${LISTEN_PORT:-8443}"

TLS_CERT="${TLS_CERT:-/etc/dohd/proxy.crt}"
TLS_KEY="${TLS_KEY:-/etc/dohd/proxy.key}"

# mTLS identity presented by this proxy to targets (if targets require it).
TARGET_CERT="${TARGET_CERT:-/etc/dohd/proxy-client.crt}"
TARGET_KEY="${TARGET_KEY:-/etc/dohd/proxy-client.key}"

# Optional legacy RFC8484 targets:
# export TARGET_URLS="https://target-a.example/dns-query https://target-b.example/dns-query"
# export TARGETS_FILE="/etc/dohd/dodh_targets"
TARGET_URLS="${TARGET_URLS:-}"
TARGETS_FILE="${TARGETS_FILE:-}"

set -- \
    "$DOHPROXYD_BIN" \
    -F \
    -u "$RUN_AS" \
    -c "$TLS_CERT" \
    -k "$TLS_KEY" \
    -p "$LISTEN_PORT" \
    --target-cert "$TARGET_CERT" \
    --target-key "$TARGET_KEY"

if [ -n "$TARGETS_FILE" ]; then
    set -- "$@" --targets-file "$TARGETS_FILE"
fi

if [ -n "$TARGET_URLS" ]; then
    for u in $TARGET_URLS; do
        set -- "$@" --target-url "$u"
    done
fi

echo "Launching ODoH proxy:"
printf '  %s\n' "$@"
exec "$@"
