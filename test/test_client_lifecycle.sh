#!/bin/bash
# Integration test: Client lifecycle stress test
#
# Tests rapid connect/disconnect to detect leaks in client_data handling
#
# Requirements: curl with HTTP/2 support, dohd running
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="${DOH_HOST:-localhost}"
PORT="${DOH_PORT:-8053}"
ITERATIONS="${DOH_ITERATIONS:-100}"
PARALLEL="${DOH_PARALLEL:-5}"

# DNS query for example.com A record (base64url encoded)
DNS_QUERY="AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

echo "=== Client Lifecycle Stress Test ==="
echo "Host: $HOST:$PORT"
echo "Iterations: $ITERATIONS"
echo "Parallel connections: $PARALLEL"
echo ""

# Check if dohd is running
if ! curl -s -k --http2 "https://$HOST:$PORT/?dns=$DNS_QUERY" >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to dohd at $HOST:$PORT"
    echo "Make sure dohd is running with test certificates"
    exit 1
fi

# Function to make a single request
do_request() {
    local i=$1
    curl -s -k --http2 \
        --connect-timeout 5 \
        --max-time 10 \
        "https://$HOST:$PORT/?dns=$DNS_QUERY" \
        -o /dev/null \
        -w "%{http_code}" 2>/dev/null
}

echo "Running rapid connect/disconnect tests..."
success=0
failed=0

for ((i=1; i<=ITERATIONS; i++)); do
    # Run PARALLEL requests in background
    pids=()
    for ((j=0; j<PARALLEL; j++)); do
        do_request $((i * PARALLEL + j)) &
        pids+=($!)
    done

    # Wait for all and count results
    for pid in "${pids[@]}"; do
        if wait $pid; then
            ((success++))
        else
            ((failed++))
        fi
    done

    # Progress indicator
    if ((i % 10 == 0)); then
        echo "  Progress: $i/$ITERATIONS iterations (success: $success, failed: $failed)"
    fi
done

echo ""
echo "=== Results ==="
echo "Total requests: $((success + failed))"
echo "Successful: $success"
echo "Failed: $failed"

# Send SIGUSR1 to get stats (if running locally)
if command -v pkill &>/dev/null && [ "$HOST" = "localhost" ]; then
    echo ""
    echo "Requesting dohd stats (SIGUSR1)..."
    pkill -USR1 dohd 2>/dev/null || true
    sleep 1
fi

if [ $failed -gt 0 ]; then
    echo ""
    echo "WARNING: Some requests failed. Check dohd logs for details."
    exit 1
fi

echo ""
echo "PASS: All requests completed successfully"
exit 0
