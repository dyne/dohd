#!/bin/bash
# Simple multi-threaded stress test for dohd
#
# Launches dohd and bombards it with requests from multiple threads
# until failure is detected or max duration reached.
#
# Usage: ./stress_test.sh [options]
#   --threads N     Number of worker threads (default: 20)
#   --duration N    Max duration in seconds (default: 60)
#   --asan          Build and run with AddressSanitizer
#   --port N        Port to use (default: 18080)
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
DOHD_BIN="$ROOT_DIR/src/dohd"
CERT="$SCRIPT_DIR/test.crt"
KEY="$SCRIPT_DIR/test.key"

# Defaults
THREADS=20
DURATION=60
PORT=18080
DNS_SERVER="${DNS_SERVER:-1.1.1.1}"
ASAN_MODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --threads) THREADS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --asan) ASAN_MODE=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# DNS queries
DNS_QUERIES=(
    "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
    "AAABAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ"
    "AAABAAABAAAAAAAABWdpdGh1YgNjb20AAAEAAQ"
)

RESULTS_DIR=$(mktemp -d)
DOHD_PID=0
START_TIME=0

send_signal() {
    local sig=$1
    local pid=$2
    /bin/kill -$sig $pid 2>/dev/null || true
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    
    # Stop background jobs
    jobs -p 2>/dev/null | while read pid; do
        send_signal TERM $pid
    done
    
    # Stop dohd
    if [ $DOHD_PID -ne 0 ]; then
        send_signal USR1 $DOHD_PID
        sleep 1
        send_signal TERM $DOHD_PID
        wait $DOHD_PID 2>/dev/null || true
    fi
    
    # Aggregate results
    local total=0 ok=0 fail=0
    for f in "$RESULTS_DIR"/worker_*.txt; do
        [ -f "$f" ] || continue
        while read t o f_cnt; do
            ((total += t)) || true
            ((ok += o)) || true
            ((fail += f_cnt)) || true
        done < "$f"
    done
    
    local elapsed=$(($(date +%s) - START_TIME))
    [ $elapsed -eq 0 ] && elapsed=1
    
    echo ""
    echo "========================================="
    echo "         STRESS TEST RESULTS"
    echo "========================================="
    echo "Duration:         ${elapsed}s"
    echo "Total requests:   $total"
    echo "Successful:       $ok"
    echo "Failed:           $fail"
    echo "Requests/second:  $((total / elapsed))"
    if [ $total -gt 0 ]; then
        echo "Failure rate:     $(echo "scale=2; $fail * 100 / $total" | bc)%"
    fi
    echo "========================================="
    
    rm -rf "$RESULTS_DIR"
}

trap cleanup EXIT

# Worker function
worker() {
    local id=$1
    local end_time=$2
    local stats_file="$RESULTS_DIR/worker_$id.txt"
    local requests=0 success=0 failed=0
    
    while [ $(date +%s) -lt $end_time ]; do
        local dns_q=${DNS_QUERIES[$((RANDOM % ${#DNS_QUERIES[@]}))]}
        local result
        result=$(curl -s -k --http2 -4 \
            --connect-timeout 2 \
            --max-time 5 \
            -H "Accept: application/dns-message" \
            -H "Content-Type: application/dns-message" \
            -o /dev/null \
            -w "%{http_code}" \
            "https://127.0.0.1:$PORT/?dns=$dns_q" 2>&1)
        
        ((requests++))
        if [[ "$result" == "200" ]]; then
            ((success++))
        else
            ((failed++))
        fi
    done
    
    echo "$requests $success $failed" > "$stats_file"
}

is_running() {
    local pid=$1
    [ -d "/proc/$pid" ]
}

echo "========================================="
echo "     DOHD MULTI-THREADED STRESS TEST"
echo "========================================="
echo "Threads:    $THREADS"
echo "Duration:   ${DURATION}s"
echo "Port:       $PORT"
echo "ASAN:       $ASAN_MODE"
echo "========================================="
echo ""

# Build
if [ $ASAN_MODE -eq 1 ]; then
    echo "Building with ASAN..."
    make -C "$ROOT_DIR" asan >/dev/null 2>&1 || { echo "Build failed"; exit 1; }
    export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:log_path=$RESULTS_DIR/asan"
else
    echo "Building release..."
    make -C "$ROOT_DIR" >/dev/null 2>&1 || { echo "Build failed"; exit 1; }
fi

# Generate certs
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "Generating test certificates..."
    "$SCRIPT_DIR/gen_test_certs.sh" "$SCRIPT_DIR" >/dev/null 2>&1
fi

# Start dohd
echo "Starting dohd on port $PORT..."
"$DOHD_BIN" -c "$CERT" -k "$KEY" -p "$PORT" -d "$DNS_SERVER" -F \
    > "$RESULTS_DIR/dohd.log" 2>&1 &
DOHD_PID=$!

sleep 2
if ! is_running $DOHD_PID; then
    echo "ERROR: dohd failed to start"
    cat "$RESULTS_DIR/dohd.log"
    exit 1
fi

# Verify responding
echo "Verifying dohd is responsive..."
for i in {1..5}; do
    if timeout 5 curl -s -k --http2 -4 -H "Accept: application/dns-message" -H "Content-Type: application/dns-message" "https://127.0.0.1:$PORT/?dns=${DNS_QUERIES[0]}" -o /dev/null 2>&1; then
        echo "dohd is responding"
        break
    fi
    if [ $i -eq 5 ]; then
        echo "ERROR: dohd not responding"
        cat "$RESULTS_DIR/dohd.log"
        exit 1
    fi
    sleep 1
done

echo "dohd running (PID: $DOHD_PID)"
echo ""

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

# Start workers
echo "Starting $THREADS workers for ${DURATION}s..."
for ((t=1; t<=THREADS; t++)); do
    worker $t $END_TIME &
done

echo "Test running... Press Ctrl+C to abort"
echo ""

# Monitor loop
CRASHED=0
while [ $(date +%s) -lt $END_TIME ]; do
    sleep 5
    
    # Check dohd alive
    if ! is_running $DOHD_PID; then
        echo ""
        echo "!!! DOHD CRASHED !!!"
        CRASHED=1
        break
    fi
    
    # Health check
    if ! timeout 5 curl -s -k --http2 -4 -H "Accept: application/dns-message" -H "Content-Type: application/dns-message" "https://127.0.0.1:$PORT/?dns=${DNS_QUERIES[0]}" -o /dev/null 2>&1; then
        echo "WARNING: Health check failed at $(date +%H:%M:%S)"
    fi
    
    ELAPSED=$(($(date +%s) - START_TIME))
    echo "[$ELAPSED/${DURATION}s] dohd PID $DOHD_PID OK"
done

# Wait for workers
echo ""
echo "Waiting for workers to finish..."
wait

# Check ASAN
if [ $ASAN_MODE -eq 1 ]; then
    if ls "$RESULTS_DIR"/asan.* 1>/dev/null 2>&1; then
        if grep -q "ERROR:" "$RESULTS_DIR"/asan.* 2>/dev/null; then
            echo ""
            echo "!!! ASAN ERRORS DETECTED !!!"
            cat "$RESULTS_DIR"/asan.*
            CRASHED=1
        fi
    fi
fi

echo ""
if [ $CRASHED -eq 1 ]; then
    echo "TEST RESULT: FAILURE"
    echo ""
    echo "dohd log:"
    cat "$RESULTS_DIR/dohd.log"
    exit 1
else
    echo "TEST RESULT: PASSED"
    exit 0
fi
