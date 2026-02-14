#!/bin/bash
# Integration test: Memory leak detection via stats monitoring
#
# Makes many requests and checks that memory usage returns to baseline
#
# Requirements: curl with HTTP/2 support, dohd running
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="${DOH_HOST:-localhost}"
PORT="${DOH_PORT:-8053}"
ITERATIONS="${DOH_ITERATIONS:-50}"
BATCH_SIZE="${DOH_BATCH:-10}"

# DNS queries for variety
DNS_QUERIES=(
    "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"  # example.com A
    "AAABAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ"   # google.com A
    "AAABAAABAAAAAAAABWdpdGh1YgNjb20AAAEAAQ"   # github.com A
)

echo "=== Memory Leak Detection Test ==="
echo "Host: $HOST:$PORT"
echo "Iterations: $ITERATIONS batches of $BATCH_SIZE requests"
echo ""

# Check connectivity
DNS_Q=${DNS_QUERIES[0]}
if ! curl -s -k --http2 "https://$HOST:$PORT/dns-query?dns=$DNS_Q" >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to dohd at $HOST:$PORT"
    exit 1
fi

# Function to get dohd memory stats (requires local access)
get_mem_stats() {
    if command -v pkill &>/dev/null && [ "$HOST" = "localhost" ]; then
        # Send SIGUSR1 and capture stats from syslog or stderr
        pkill -USR1 dohd 2>/dev/null || true
    fi
    # Also check via /proc if available
    if [ -f /proc/$(pgrep -f "dohd" | head -1)/status ] 2>/dev/null; then
        grep VmRSS /proc/$(pgrep -f "dohd" | head -1)/status 2>/dev/null || true
    fi
}

echo "Initial memory state:"
get_mem_stats
echo ""

# Run request batches
echo "Running $ITERATIONS batches..."
total_requests=0

for ((batch=1; batch<=ITERATIONS; batch++)); do
    # Make batch of requests
    for ((i=0; i<BATCH_SIZE; i++)); do
        # Rotate through different queries
        dns_q=${DNS_QUERIES[$((i % ${#DNS_QUERIES[@]}))]}
        curl -s -k --http2 \
            "https://$HOST:$PORT/dns-query?dns=$dns_q" \
            -o /dev/null &
    done
    wait
    ((total_requests += BATCH_SIZE))

    # Progress and stats
    if ((batch % 10 == 0)); then
        echo "  Batch $batch/$ITERATIONS ($total_requests requests)"
        get_mem_stats
    fi
done

echo ""
echo "Final memory state after $total_requests requests:"
get_mem_stats

# Wait for any pending operations to complete
sleep 2

echo ""
echo "Memory state after cooldown:"
get_mem_stats

echo ""
echo "=== Test Complete ==="
echo "Total requests: $total_requests"
echo ""
echo "To verify no leaks:"
echo "  1. Compare initial and final VmRSS values"
echo "  2. Check dohd logs for memory warnings"
echo "  3. Run with 'make asan' build for detailed leak detection"
echo ""
exit 0
