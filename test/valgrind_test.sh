#!/bin/bash
# Valgrind wrapper for dohd leak detection
#
# Runs dohd under valgrind and performs a short test sequence
#
# Usage: ./valgrind_test.sh [cert_file] [key_file]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOHD_BIN="${DOHD_BIN:-$SCRIPT_DIR/../src/dohd}"
CERT="${1:-$SCRIPT_DIR/test.crt}"
KEY="${2:-$SCRIPT_DIR/test.key}"
PORT="${DOH_PORT:-18053}"
DNS_SERVER="${DNS_SERVER:-1.1.1.1}"

# Valgrind options for leak detection
VALGRIND_OPTS="--leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1"
VALGRIND_LOG="$SCRIPT_DIR/valgrind.log"

echo "=== Valgrind Leak Detection Test ==="
echo ""

# Check for valgrind
if ! command -v valgrind &>/dev/null; then
    echo "ERROR: valgrind not found. Install with: apt install valgrind"
    exit 1
fi

# Check for dohd binary
if [ ! -x "$DOHD_BIN" ]; then
    echo "ERROR: dohd binary not found at $DOHD_BIN"
    echo "Build with: make debug"
    exit 1
fi

# Generate test certs if needed
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "Generating test certificates..."
    "$SCRIPT_DIR/gen_test_certs.sh" "$SCRIPT_DIR"
    CERT="$SCRIPT_DIR/test.crt"
    KEY="$SCRIPT_DIR/test.key"
fi

echo "Starting dohd under valgrind..."
echo "  Binary: $DOHD_BIN"
echo "  Port: $PORT"
echo "  DNS: $DNS_SERVER"
echo "  Log: $VALGRIND_LOG"
echo ""

# Start dohd under valgrind in background
valgrind $VALGRIND_OPTS \
    --log-file="$VALGRIND_LOG" \
    "$DOHD_BIN" -c "$CERT" -k "$KEY" -p "$PORT" -d "$DNS_SERVER" -F -v &
DOHD_PID=$!

# Give it time to start
sleep 3

# Check if it's running
if ! kill -0 $DOHD_PID 2>/dev/null; then
    echo "ERROR: dohd failed to start"
    cat "$VALGRIND_LOG"
    exit 1
fi

echo "dohd running (PID: $DOHD_PID)"

# Wait for it to be ready
for i in {1..10}; do
    if curl -s -k --http2 "https://localhost:$PORT/?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Run test sequence
echo ""
echo "Running test sequence..."
DNS_QUERY="AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

success=0
failed=0

# Make several requests
for i in {1..20}; do
    if curl -s -k --http2 \
        --connect-timeout 5 \
        --max-time 10 \
        "https://localhost:$PORT/?dns=$DNS_QUERY" \
        -o /dev/null 2>/dev/null; then
        ((success++))
    else
        ((failed++))
    fi
done

echo "  Requests: $((success + failed)) (success: $success, failed: $failed)"

# Request stats
kill -USR1 $DOHD_PID 2>/dev/null || true
sleep 1

# Graceful shutdown
echo ""
echo "Shutting down dohd..."
kill -TERM $DOHD_PID 2>/dev/null || true

# Wait for clean exit
wait $DOHD_PID 2>/dev/null
exit_code=$?

echo ""
echo "=== Valgrind Results ==="
echo ""

# Show summary from valgrind log
if [ -f "$VALGRIND_LOG" ]; then
    echo "Memory summary:"
    grep -A 10 "LEAK SUMMARY" "$VALGRIND_LOG" || true
    echo ""
    grep -A 5 "ERROR SUMMARY" "$VALGRIND_LOG" || true
    echo ""
    echo "Full log: $VALGRIND_LOG"
fi

# Check for leaks
if grep -q "definitely lost: [1-9]" "$VALGRIND_LOG" 2>/dev/null; then
    echo ""
    echo "WARNING: Memory leaks detected!"
    echo "Check $VALGRIND_LOG for details"
    exit 1
fi

if grep -q "ERROR SUMMARY: [1-9]" "$VALGRIND_LOG" 2>/dev/null; then
    echo ""
    echo "WARNING: Memory errors detected!"
    echo "Check $VALGRIND_LOG for details"
    exit 1
fi

echo ""
echo "PASS: No memory leaks detected"
exit 0
