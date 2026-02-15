#!/bin/sh
set -eu

# RFC 9230 trust separation warning:
# Run ODoH target and ODoH proxy in different administrative domains.
# This script is only an example of target launch/configuration.

DOHD_BIN="${DOHD_BIN:-/usr/local/sbin/dohd}"
RUN_AS="${RUN_AS:-dohd}"
LISTEN_PORT="${LISTEN_PORT:-8053}"
UPSTREAM_DNS="${UPSTREAM_DNS:-1.1.1.1}"

TLS_CERT="${TLS_CERT:-/etc/dohd/target.crt}"
TLS_KEY="${TLS_KEY:-/etc/dohd/target.key}"

ODOH_CONFIG="${ODOH_CONFIG:-/etc/dohd/odoh-target.config}"
ODOH_SECRET="${ODOH_SECRET:-/etc/dohd/odoh-target.secret}"
AUTHORIZED_PROXY_DIR="${AUTHORIZED_PROXY_DIR:-/etc/dohd/proxies}"

echo "Launching ODoH target resolver:"
echo "  binary: $DOHD_BIN"
echo "  tls:    $TLS_CERT / $TLS_KEY"
echo "  odoh:   $ODOH_CONFIG / $ODOH_SECRET"
echo "  authz:  $AUTHORIZED_PROXY_DIR"
echo
echo "Reminder: install proxy client-cert public keys in:"
echo "  $AUTHORIZED_PROXY_DIR"
echo "One PEM file per authorized proxy key."
echo

exec "$DOHD_BIN" \
    -F \
    -u "$RUN_AS" \
    -c "$TLS_CERT" \
    -k "$TLS_KEY" \
    -p "$LISTEN_PORT" \
    -d "$UPSTREAM_DNS" \
    -O \
    --odoh-config "$ODOH_CONFIG" \
    --odoh-secret "$ODOH_SECRET" \
    --authorized-proxies-dir "$AUTHORIZED_PROXY_DIR"
