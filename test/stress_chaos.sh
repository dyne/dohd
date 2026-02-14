#!/bin/bash
# Chaos test - random connection patterns to find edge cases
#
# Simulates chaotic real-world behavior:
# - Random delays between requests
# - Abrupt connection drops
# - Partial requests
# - Mixed GET/POST
# - Concurrent connect/disconnect
#
# Usage: ./stress_chaos.sh [options]
#   Options:
#     --duration N    Test duration in seconds (default: 120)
#     --workers N     Number of chaos workers (default: 30)
#     --asan          Build with AddressSanitizer
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
DOHD_BIN="$ROOT_DIR/src/dohd"
CERT="$SCRIPT_DIR/test.crt"
KEY="$SCRIPT_DIR/test.key"

# Defaults
DURATION=120
WORKERS=30
PORT=18083
DNS_SERVER="${DNS_SERVER:-1.1.1.1}"
ASAN_MODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION="$2"; shift 2 ;;
        --workers) WORKERS="$2"; shift 2 ;;
        --asan) ASAN_MODE=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DNS_QUERIES=(
    "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
    "AAABAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ"
    "AAABAAABAAAAAAAABWdpdGh1YgNjb20AAAEAAQ"
)

RESULTS_DIR=$(mktemp -d)
DOHD_PID=0

trap "cleanup" EXIT

cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
    
    if [ $DOHD_PID -ne 0 ]; then
        kill -USR1 $DOHD_PID 2>/dev/null || true
        sleep 1
        kill -TERM $DOHD_PID 2>/dev/null || true
        wait $DOHD_PID 2>/dev/null || true
    fi
    
    # Aggregate stats
    local total=0 ok=0 fail=0 timeout=0 aborted=0
    for f in "$RESULTS_DIR"/worker_*.stats 2>/dev/null; do
        if [ -f "$f" ]; then
            read t o f to ab < "$f"
            ((total += t)) || true
            ((ok += o)) || true
            ((fail += f)) || true
            ((timeout += to)) || true
            ((aborted += ab)) || true
        fi
    done
    
    echo ""
    echo "========================================="
    echo "         CHAOS TEST RESULTS"
    echo "========================================="
    echo "Total requests:  $total"
    echo "Successful:      $ok"
    echo "Failed:          $fail"
    echo "Timeouts:        $timeout"
    echo "Aborted:         $aborted"
    echo "========================================="
    
    rm -rf "$RESULTS_DIR"
}

# Chaos worker - behaves unpredictably
chaos_worker() {
    local id=$1
    local end_time=$(($(date +%s) + DURATION))
    local stats_file="$RESULTS_DIR/worker_$id.stats"
    
    local total=0 ok=0 fail=0 timeout=0 aborted=0
    
    while [ $(date +%s) -lt $end_time ]; do
        ((total++))
        
        # Random behavior selection
        local behavior=$((RANDOM % 10))
        local dns_q=${DNS_QUERIES[$((RANDOM % ${#DNS_QUERIES[@]}))]}
        
        case $behavior in
            0|1|2|3)
                # Normal GET request
                local result=$(curl -s -k --http2 \
                    --connect-timeout 2 --max-time 5 \
                    -o /dev/null -w "%{http_code}" \
                    "https://localhost:$PORT/?dns=$dns_q" 2>&1)
                ;;
            4|5)
                # Very short timeout (may cause partial reads)
                local result=$(curl -s -k --http2 \
                    --connect-timeout 1 --max-time 2 \
                    -o /dev/null -w "%{http_code}" \
                    "https://localhost:$PORT/?dns=$dns_q" 2>&1)
                ;;
            6)
                # POST request
                local result=$(echo -n "$dns_q" | base64 -d 2>/dev/null | \
                    curl -s -k --http2 \
                    --connect-timeout 2 --max-time 5 \
                    -X POST -H "Content-Type: application/dns-message" \
                    --data-binary @- -o /dev/null -w "%{http_code}" \
                    "https://localhost:$PORT/dns-query" 2>&1)
                ;;
            7)
                # Abort mid-request (connect then kill)
                timeout 0.5 curl -s -k --http2 \
                    "https://localhost:$PORT/?dns=$dns_q" \
                    -o /dev/null 2>/dev/null &
                local pid=$!
                sleep 0.1
                kill -9 $pid 2>/dev/null || true
                ((aborted++))
                continue
                ;;
            8)
                # Invalid/truncated query
                local result=$(curl -s -k --http2 \
                    --connect-timeout 2 --max-time 5 \
                    -o /dev/null -w "%{http_code}" \
                    "https://localhost:$PORT/?dns=AAAA" 2>&1)
                ;;
            9)
                # Multiple rapid requests on same connection (HTTP/2 multiplexing)
                curl -s -k --http2 \
                    --connect-timeout 2 --max-time 5 \
                    "https://localhost:$PORT/?dns=${DNS_QUERIES[0]}" \
                    "https://localhost:$PORT/?dns=${DNS_QUERIES[1]}" \
                    "https://localhost:$PORT/?dns=${DNS_QUERIES[2]}" \
                    -o /dev/null -o /dev/null -o /dev/null 2>/dev/null
                local result="200"
                ;;
        esac
        
        # Count result
        case "$result" in
            200) ((ok++)) ;;
            000|"") ((timeout++)) ;;
            *) ((fail++)) ;;
        esac
        
        # Random delay (0-500ms)
        sleep $(echo "scale=3; $((RANDOM % 500)) / 1000" | bc)
    done
    
    echo "$total $ok $fail $timeout $aborted" > "$stats_file"
}

echo "========================================="
echo "       DOHD CHAOS STRESS TEST"
echo "========================================="
echo "Workers:   $WORKERS"
echo "Duration:  ${DURATION}s"
echo "ASAN:      $ASAN_MODE"
echo "========================================="
echo ""

# Build
if [ $ASAN_MODE -eq 1 ]; then
    echo "Building with ASAN..."
    make -C "$ROOT_DIR" asan >/dev/null 2>&1
    export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:log_path=$RESULTS_DIR/asan"
else
    echo "Building release..."
    make -C "$ROOT_DIR" >/dev/null 2>&1
fi

# Generate certs
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    "$SCRIPT_DIR/gen_test_certs.sh" "$SCRIPT_DIR" >/dev/null 2>&1
fi

# Start dohd
echo "Starting dohd..."
"$DOHD_BIN" -c "$CERT" -k "$KEY" -p "$PORT" -d "$DNS_SERVER" -F \
    > "$RESULTS_DIR/dohd.log" 2>&1 &
DOHD_PID=$!
sleep 2

if ! kill -0 $DOHD_PID 2>/dev/null; then
    echo "ERROR: dohd failed to start"
    cat "$RESULTS_DIR/dohd.log"
    exit 1
fi

# Wait for ready
for i in {1..10}; do
    if curl -s -k --http2 "https://localhost:$PORT/?dns=${DNS_QUERIES[0]}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "dohd running (PID: $DOHD_PID)"
echo ""

# Start chaos workers
echo "Starting $WORKERS chaos workers..."
for ((w=1; w<=WORKERS; w++)); do
    chaos_worker $w &
done

echo "Chaos test running for ${DURATION}s..."
echo ""

# Monitor
START_TIME=$(date +%s)
CRASHED=0

while [ $(($(date +%s) - START_TIME)) -lt $DURATION ]; do
    sleep 10
    
    # Check dohd
    if ! kill -0 $DOHD_PID 2>/dev/null; then
        echo ""
        echo "!!! DOHD CRASHED !!!"
        CRASHED=1
        break
    fi
    
    ELAPSED=$(($(date +%s) - START_TIME))
    echo "[$ELAPSED/${DURATION}s] dohd PID $DOHD_PID running"
done

# Wait for workers
wait 2>/dev/null || true

# Check ASAN
if [ $ASAN_MODE -eq 1 ] && ls "$RESULTS_DIR"/asan.* 1>/dev/null 2>&1; then
    if grep -q "ERROR:" "$RESULTS_DIR"/asan.* 2>/dev/null; then
        echo ""
        echo "!!! ASAN ERRORS !!!"
        cat "$RESULTS_DIR"/asan.*
        CRASHED=1
    fi
fi

echo ""
if [ $CRASHED -eq 1 ]; then
    echo "TEST RESULT: FAILURE"
    echo ""
    echo "dohd log tail:"
    tail -50 "$RESULTS_DIR/dohd.log"
    exit 1
else
    echo "TEST RESULT: SURVIVED chaos test"
    exit 0
fi
