#!/bin/sh
set -eu

# LOCAL PROTOCOL EVALUATION ONLY
# RFC 9230 recommends separating proxy and target operators.
# This script intentionally runs both on one host for quick protocol plumbing tests.
# Do not use this topology in production.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"

DOHD_BIN="${DOHD_BIN:-$REPO_ROOT/src/dohd}"
DOHPROXYD_BIN="${DOHPROXYD_BIN:-$REPO_ROOT/proxy/dohproxyd}"

WORKDIR="${WORKDIR:-/tmp/dohd-odoh-selftest}"
TARGET_PORT="${TARGET_PORT:-18053}"
PROXY_PORT="${PROXY_PORT:-18443}"

TARGET_URL="https://[::1]:${TARGET_PORT}/dns-query"
QUERY_HEX="123401000001000000000000076578616d706c6503636f6d0000010001"

log() {
    printf '[selftest] %s\n' "$*"
}

dump_logs() {
    log "--- target.log ---"
    cat "$WORKDIR/target.log" 2>/dev/null || true
    log "--- proxy.log ---"
    cat "$WORKDIR/proxy.log" 2>/dev/null || true
    log "--- curl.headers ---"
    cat "$WORKDIR/curl.headers" 2>/dev/null || true
    log "--- curl.stderr ---"
    cat "$WORKDIR/curl.stderr" 2>/dev/null || true
}

fail() {
    log "FAIL: $*"
    dump_logs
    exit 1
}

cleanup() {
    set +e
    log "cleanup: stopping child processes"
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "${TARGET_PID:-}" ] && kill "$TARGET_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

wait_pid_alive() {
    p="$1"
    name="$2"
    n=0
    while [ "$n" -lt 30 ]; do
        st="$(ps -o stat= -p "$p" 2>/dev/null | tr -d ' ' || true)"
        if [ -z "$st" ]; then
            log "$name process $p disappeared"
            return 1
        fi
        case "$st" in
            Z*|*Z*)
                log "$name process $p is zombie (state=$st)"
                return 1
                ;;
        esac
        if ! kill -0 "$p" 2>/dev/null; then
            log "$name process $p is not alive"
            return 1
        fi
        n=$((n + 1))
        sleep 0.1
    done
    log "$name process $p stayed alive during warmup"
    return 0
}

wait_tcp_listen() {
    port="$1"
    name="$2"
    n=0
    if ! command -v ss >/dev/null 2>&1; then
        log "ss not available, skipping listen-state check for $name"
        return 0
    fi
    while [ "$n" -lt 50 ]; do
        if ss -ltnH "( sport = :$port )" 2>/dev/null | grep -q .; then
            log "$name is listening on TCP port $port"
            return 0
        fi
        n=$((n + 1))
        sleep 0.1
    done
    log "$name did not start listening on TCP port $port"
    return 1
}

mkdir -p "$WORKDIR"
rm -f "$WORKDIR/target.log" "$WORKDIR/proxy.log" "$WORKDIR/curl.headers" "$WORKDIR/curl.stderr" \
      "$WORKDIR/q.bin" "$WORKDIR/r.bin" "$WORKDIR/target.csr" "$WORKDIR/ca.srl"
log "workdir: $WORKDIR"
log "repo root: $REPO_ROOT"
log "target url for proxy: $TARGET_URL"
log "dohd binary: $DOHD_BIN"
log "dohproxyd binary: $DOHPROXYD_BIN"
if command -v ss >/dev/null 2>&1; then
    log "pre-check listeners on target/proxy ports (if any):"
    ss -ltnH "( sport = :$TARGET_PORT or sport = :$PROXY_PORT )" 2>/dev/null || true
fi

if ! command -v curl >/dev/null 2>&1; then
    fail "curl not found"
    exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
    fail "openssl not found"
    exit 1
fi
if ! command -v xxd >/dev/null 2>&1; then
    fail "xxd not found"
    exit 1
fi

log "generating ephemeral target TLS certificate"
log "generating ephemeral local CA for upstream verification"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORKDIR/ca.key" \
    -out "$WORKDIR/ca.crt" \
    -subj "/CN=dohd-selftest-ca" >/dev/null 2>&1

log "generating target key and CSR, then signing with local CA"
openssl req -newkey rsa:2048 -nodes \
    -keyout "$WORKDIR/target.key" \
    -out "$WORKDIR/target.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -days 1 \
    -in "$WORKDIR/target.csr" \
    -CA "$WORKDIR/ca.crt" \
    -CAkey "$WORKDIR/ca.key" \
    -CAcreateserial \
    -out "$WORKDIR/target.crt" >/dev/null 2>&1

log "generating ephemeral proxy TLS certificate"
openssl req -nodes -newkey rsa:2048 \
    -keyout "$WORKDIR/proxy.key" \
    -x509 -days 1 \
    -out "$WORKDIR/proxy.crt" \
    -subj "/CN=localhost" >/dev/null 2>&1

log "building DNS query payload"
printf "%s" "$QUERY_HEX" | xxd -r -p > "$WORKDIR/q.bin"
QSIZE="$(wc -c < "$WORKDIR/q.bin" | tr -d ' ')"
log "query payload size: ${QSIZE} bytes"
log "query payload hexdump:"
xxd -g1 "$WORKDIR/q.bin" || true

log "starting target dohd on [::]:$TARGET_PORT"
"$DOHD_BIN" \
    -F \
    -v \
    -c "$WORKDIR/target.crt" \
    -k "$WORKDIR/target.key" \
    -p "$TARGET_PORT" \
    -d 1.1.1.1 >"$WORKDIR/target.log" 2>&1 &
TARGET_PID=$!

"$DOHPROXYD_BIN" \
    -F \
    -v \
    -c "$WORKDIR/proxy.crt" \
    -k "$WORKDIR/proxy.key" \
    -p "$PROXY_PORT" \
    -A "$WORKDIR/ca.crt" \
    --target-url "$TARGET_URL" >"$WORKDIR/proxy.log" 2>&1 &
PROXY_PID=$!
log "proxy pid: $PROXY_PID"

if ! wait_pid_alive "$TARGET_PID" "target"; then
    fail "target exited early"
fi
if ! wait_tcp_listen "$TARGET_PORT" "target"; then
    fail "target did not listen"
fi
if ! wait_pid_alive "$PROXY_PID" "proxy"; then
    fail "proxy exited early"
fi
if ! wait_tcp_listen "$PROXY_PORT" "proxy"; then
    fail "proxy did not listen"
fi

log "sending DNS over HTTPS request to proxy"
HTTP_CODE="$(
curl --http2 -k -v \
    -D "$WORKDIR/curl.headers" \
    -o "$WORKDIR/r.bin" \
    --write-out "%{http_code}" \
    -H "content-type: application/dns-message" \
    -H "accept: application/dns-message" \
    --data-binary @"$WORKDIR/q.bin" \
    "https://[::1]:${PROXY_PORT}/dns-query" \
    2>"$WORKDIR/curl.stderr"
)"
log "curl HTTP status: $HTTP_CODE"

if [ ! -s "$WORKDIR/r.bin" ]; then
    fail "empty DNS reply body"
fi

RSIZE="$(wc -c < "$WORKDIR/r.bin" | tr -d ' ')"
log "reply payload size: ${RSIZE} bytes"
log "reply payload hexdump:"
xxd -g1 "$WORKDIR/r.bin" || true

RCODE_HEX="$(xxd -p -l 4 "$WORKDIR/r.bin" | cut -c7-8)"
if [ "$RCODE_HEX" = "00" ]; then
    log "PASS: proxy+target returned DNS NOERROR"
else
    log "completed with DNS flags low-byte=0x$RCODE_HEX"
fi

log "artifacts:"
log "  $WORKDIR/q.bin"
log "  $WORKDIR/r.bin"
log "  $WORKDIR/target.log"
log "  $WORKDIR/proxy.log"
log "  $WORKDIR/curl.headers"
log "  $WORKDIR/curl.stderr"
