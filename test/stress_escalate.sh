#!/bin/bash
# Escalating stress test - finds the breaking point
#
# Starts with few threads and keeps adding more until dohd fails.
# Reports the maximum sustainable load.
#
# Usage: ./stress_escalate.sh [options]
#   Options:
#     --start N       Starting number of threads (default: 5)
#     --step N        Threads to add each round (default: 5)
#     --max N         Maximum threads to try (default: 200)
#     --round-time N  Seconds per round (default: 30)
#     --asan          Build with AddressSanitizer
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
DOHD_BIN="$ROOT_DIR/src/dohd"
CERT="$SCRIPT_DIR/test.crt"
KEY="$SCRIPT_DIR/test.key"

# Defaults
START_THREADS=5
STEP=5
MAX_THREADS=200
ROUND_TIME=30
PORT=18081
DNS_SERVER="${DNS_SERVER:-1.1.1.1}"
ASAN_MODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --start) START_THREADS="$2"; shift 2 ;;
        --step) STEP="$2"; shift 2 ;;
        --max) MAX_THREADS="$2"; shift 2 ;;
        --round-time) ROUND_TIME="$2"; shift 2 ;;
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
MAX_SUSTAINED=0
FAILURE_THREADS=0

trap "cleanup" EXIT

cleanup() {
    echo ""
    # Kill workers
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Kill dohd
    if [ $DOHD_PID -ne 0 ]; then
        kill -TERM $DOHD_PID 2>/dev/null || true
        wait $DOHD_PID 2>/dev/null || true
    fi
    
    rm -rf "$RESULTS_DIR"
    
    echo "========================================="
    echo "        ESCALATION TEST RESULTS"
    echo "========================================="
    echo "Maximum sustained threads: $MAX_SUSTAINED"
    if [ $FAILURE_THREADS -gt 0 ]; then
        echo "Failed at threads:         $FAILURE_THREADS"
    fi
    echo "========================================="
}

worker() {
    local id=$1
    local duration=$2
    local end_time=$(($(date +%s) + duration))
    
    while [ $(date +%s) -lt $end_time ]; do
        local dns_q=${DNS_QUERIES[$((RANDOM % ${#DNS_QUERIES[@]}))]}
        curl -s -k --http2 \
            --connect-timeout 3 \
            --max-time 5 \
            "https://localhost:$PORT/?dns=$dns_q" \
            -o /dev/null 2>/dev/null || true
        sleep 0.01
    done
}

check_health() {
    local attempts=3
    local success=0
    
    for ((i=0; i<attempts; i++)); do
        if curl -s -k --http2 \
            --connect-timeout 2 \
            --max-time 5 \
            -o /dev/null \
            "https://localhost:$PORT/?dns=${DNS_QUERIES[0]}" 2>/dev/null; then
            ((success++))
        fi
    done
    
    # Need at least 2/3 successful
    [ $success -ge 2 ]
}

echo "========================================="
echo "    DOHD ESCALATING STRESS TEST"
echo "========================================="
echo "Start threads:  $START_THREADS"
echo "Step size:      $STEP"
echo "Max threads:    $MAX_THREADS"
echo "Round time:     ${ROUND_TIME}s"
echo "ASAN mode:      $ASAN_MODE"
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
echo "Beginning escalation test..."
echo ""

CURRENT_THREADS=$START_THREADS

while [ $CURRENT_THREADS -le $MAX_THREADS ]; do
    echo "=== Round: $CURRENT_THREADS threads ===" 
    
    # Start workers
    for ((t=1; t<=CURRENT_THREADS; t++)); do
        worker $t $ROUND_TIME &
    done
    
    # Monitor during round
    local round_end=$(($(date +%s) + ROUND_TIME))
    local failed=0
    
    while [ $(date +%s) -lt $round_end ]; do
        sleep 5
        
        # Check dohd process
        if ! kill -0 $DOHD_PID 2>/dev/null; then
            echo "  !!! DOHD CRASHED !!!"
            failed=1
            break
        fi
        
        # Health check
        if ! check_health; then
            echo "  !!! HEALTH CHECK FAILED !!!"
            failed=1
            break
        fi
        
        echo "  OK at $(date +%H:%M:%S)"
    done
    
    # Stop workers
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
    
    if [ $failed -eq 1 ]; then
        FAILURE_THREADS=$CURRENT_THREADS
        echo ""
        echo "FAILURE at $CURRENT_THREADS threads!"
        break
    fi
    
    MAX_SUSTAINED=$CURRENT_THREADS
    echo "  PASSED: $CURRENT_THREADS threads sustained for ${ROUND_TIME}s"
    echo ""
    
    # Increase threads
    ((CURRENT_THREADS += STEP))
    
    # Brief pause between rounds
    sleep 2
done

# Get final stats
kill -USR1 $DOHD_PID 2>/dev/null || true
sleep 1

echo ""
if [ $FAILURE_THREADS -gt 0 ]; then
    echo "TEST RESULT: BREAKING POINT FOUND"
    echo "  Last stable:  $MAX_SUSTAINED threads"
    echo "  Failed at:    $FAILURE_THREADS threads"
    
    echo ""
    echo "dohd log tail:"
    tail -30 "$RESULTS_DIR/dohd.log"
    exit 1
else
    echo "TEST RESULT: SURVIVED up to $MAX_THREADS threads"
    exit 0
fi
