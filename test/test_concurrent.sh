#!/bin/bash
# Integration test: Concurrent connections stress test
#
# Tests handling of many simultaneous connections
#
# Requirements: curl with HTTP/2 support, dohd running
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="${DOH_HOST:-localhost}"
PORT="${DOH_PORT:-8053}"
CONCURRENT="${DOH_CONCURRENT:-50}"
DURATION="${DOH_DURATION:-10}"

DNS_QUERY="AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

echo "=== Concurrent Connections Stress Test ==="
echo "Host: $HOST:$PORT"
echo "Concurrent connections: $CONCURRENT"
echo "Duration: ${DURATION}s"
echo ""

# Check connectivity
if ! curl -s -k --http2 "https://$HOST:$PORT/dns-query?dns=$DNS_QUERY" >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to dohd at $HOST:$PORT"
    exit 1
fi

# Create temp files for results
RESULTS_DIR=$(mktemp -d)
trap "rm -rf $RESULTS_DIR" EXIT

# Worker function: make continuous requests
worker() {
    local id=$1
    local result_file="$RESULTS_DIR/worker_$id"
    local success=0
    local failed=0
    local end_time=$(($(date +%s) + DURATION))

    while [ $(date +%s) -lt $end_time ]; do
        if curl -s -k --http2 \
            --connect-timeout 5 \
            --max-time 10 \
            "https://$HOST:$PORT/dns-query?dns=$DNS_QUERY" \
            -o /dev/null 2>/dev/null; then
            ((success++))
        else
            ((failed++))
        fi
    done

    echo "$success $failed" > "$result_file"
}

echo "Starting $CONCURRENT workers for ${DURATION}s..."
start_time=$(date +%s)

# Start workers
for ((i=1; i<=CONCURRENT; i++)); do
    worker $i &
done

# Wait for all workers
wait

end_time=$(date +%s)
actual_duration=$((end_time - start_time))

# Aggregate results
total_success=0
total_failed=0

for result_file in "$RESULTS_DIR"/worker_*; do
    read success failed < "$result_file"
    ((total_success += success))
    ((total_failed += failed))
done

total_requests=$((total_success + total_failed))
rps=$((total_requests / actual_duration))

echo ""
echo "=== Results ==="
echo "Duration: ${actual_duration}s"
echo "Total requests: $total_requests"
echo "Successful: $total_success"
echo "Failed: $total_failed"
echo "Requests/second: $rps"

# Get final stats
if command -v pkill &>/dev/null && [ "$HOST" = "localhost" ]; then
    echo ""
    echo "Final dohd stats:"
    pkill -USR1 dohd 2>/dev/null || true
    sleep 1
fi

# Evaluate results
if [ $total_failed -gt $((total_requests / 10)) ]; then
    echo ""
    echo "FAIL: More than 10% of requests failed"
    exit 1
fi

echo ""
echo "PASS: Concurrent connections test completed"
exit 0
