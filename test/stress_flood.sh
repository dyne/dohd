#!/bin/bash
# Connection flood test - opens many connections rapidly without waiting
#
# This tests resource exhaustion scenarios:
# - File descriptor limits
# - Memory exhaustion
# - Connection table overflow
#
# Usage: ./stress_flood.sh [options]
#   Options:
#     --rate N        Connections per second (default: 100)
#     --duration N    Test duration in seconds (default: 60)
#     --asan          Build with AddressSanitizer
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
DOHD_BIN="$ROOT_DIR/src/dohd"
CERT="$SCRIPT_DIR/test.crt"
KEY="$SCRIPT_DIR/test.key"

# Defaults
RATE=100
DURATION=60
PORT=18082
DNS_SERVER="${DNS_SERVER:-1.1.1.1}"
ASAN_MODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --rate) RATE="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --asan) ASAN_MODE=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DNS_QUERY="AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

RESULTS_DIR=$(mktemp -d)
DOHD_PID=0

trap "cleanup" EXIT

cleanup() {
    # Kill background jobs
    jobs -p | xargs -r kill 2>/dev/null || true
    
    if [ $DOHD_PID -ne 0 ]; then
        kill -USR1 $DOHD_PID 2>/dev/null || true
        sleep 1
        kill -TERM $DOHD_PID 2>/dev/null || true
        wait $DOHD_PID 2>/dev/null || true
    fi
    
    # Show results
    if [ -f "$RESULTS_DIR/stats.txt" ]; then
        echo ""
        echo "========================================="
        echo "        CONNECTION FLOOD RESULTS"
        echo "========================================="
        cat "$RESULTS_DIR/stats.txt"
        echo "========================================="
    fi
    
    rm -rf "$RESULTS_DIR"
}

echo "========================================="
echo "     DOHD CONNECTION FLOOD TEST"
echo "========================================="
echo "Rate:      $RATE connections/second"
echo "Duration:  ${DURATION}s"
echo "Total:     ~$((RATE * DURATION)) connections"
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

# Increase file descriptor limit if possible
ulimit -n 65535 2>/dev/null || true

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
    if curl -s -k --http2 "https://localhost:$PORT/?dns=$DNS_QUERY" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "dohd running (PID: $DOHD_PID)"
echo ""

# Calculate delay between requests
DELAY=$(echo "scale=6; 1 / $RATE" | bc)

echo "Flooding at $RATE req/s (delay: ${DELAY}s)..."
echo ""

START_TIME=$(date +%s)
TOTAL_SENT=0
TOTAL_OK=0
TOTAL_FAIL=0
LAST_REPORT=0

# Flood loop
END_TIME=$((START_TIME + DURATION))

while [ $(date +%s) -lt $END_TIME ]; do
    # Fire and forget - don't wait for response
    curl -s -k --http2 \
        --connect-timeout 1 \
        --max-time 3 \
        "https://localhost:$PORT/?dns=$DNS_QUERY" \
        -o /dev/null 2>/dev/null &
    
    ((TOTAL_SENT++))
    
    # Throttle to target rate
    sleep $DELAY
    
    # Periodic status
    ELAPSED=$(($(date +%s) - START_TIME))
    if [ $((ELAPSED - LAST_REPORT)) -ge 10 ]; then
        LAST_REPORT=$ELAPSED
        
        # Count background jobs (active connections)
        ACTIVE=$(jobs -r | wc -l)
        
        # Check if dohd is alive
        if ! kill -0 $DOHD_PID 2>/dev/null; then
            echo ""
            echo "!!! DOHD CRASHED after $TOTAL_SENT requests !!!"
            echo ""
            echo "dohd log tail:"
            tail -50 "$RESULTS_DIR/dohd.log"
            
            echo "Sent: $TOTAL_SENT" > "$RESULTS_DIR/stats.txt"
            echo "Active connections: $ACTIVE" >> "$RESULTS_DIR/stats.txt"
            echo "Elapsed: ${ELAPSED}s" >> "$RESULTS_DIR/stats.txt"
            echo "Result: CRASHED" >> "$RESULTS_DIR/stats.txt"
            exit 1
        fi
        
        # Check responsiveness
        if curl -s -k --http2 --connect-timeout 2 --max-time 5 \
            "https://localhost:$PORT/?dns=$DNS_QUERY" >/dev/null 2>&1; then
            STATUS="OK"
        else
            STATUS="SLOW"
        fi
        
        CURRENT_RATE=$((TOTAL_SENT / ELAPSED))
        echo "[$ELAPSED/${DURATION}s] Sent: $TOTAL_SENT | Rate: $CURRENT_RATE/s | Active: $ACTIVE | Health: $STATUS"
    fi
done

# Wait for pending requests (max 10s)
echo ""
echo "Waiting for pending requests..."
sleep 5

# Count final stats
ACTIVE=$(jobs -r | wc -l)
ELAPSED=$(($(date +%s) - START_TIME))

# Final health check
FINAL_OK=0
for i in {1..5}; do
    if curl -s -k --http2 --connect-timeout 2 --max-time 5 \
        "https://localhost:$PORT/?dns=$DNS_QUERY" >/dev/null 2>&1; then
        ((FINAL_OK++))
    fi
done

# Write stats
cat > "$RESULTS_DIR/stats.txt" << EOF
Total sent:        $TOTAL_SENT
Duration:          ${ELAPSED}s
Avg rate:          $((TOTAL_SENT / ELAPSED))/s
Pending at end:    $ACTIVE
Health checks OK:  $FINAL_OK/5
Result:            $([ $FINAL_OK -ge 3 ] && echo "PASSED" || echo "DEGRADED")
EOF

# Check if dohd still running
if ! kill -0 $DOHD_PID 2>/dev/null; then
    echo "!!! DOHD DIED !!!"
    echo "Result: CRASHED" >> "$RESULTS_DIR/stats.txt"
    exit 1
fi

echo ""
if [ $FINAL_OK -ge 3 ]; then
    echo "TEST RESULT: SURVIVED flood test"
    exit 0
else
    echo "TEST RESULT: SERVER DEGRADED"
    exit 1
fi
