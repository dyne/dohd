#!/bin/bash
# Run dohd with AddressSanitizer for memory error detection
#
# Usage: ./run_asan_test.sh [cert_file] [key_file]
#
# This script:
# 1. Builds dohd with ASAN
# 2. Starts dohd with test certificates
# 3. Runs a test sequence
# 4. Checks for ASAN errors
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
DOHD_BIN="$ROOT_DIR/src/dohd"
CERT="${1:-$SCRIPT_DIR/test.crt}"
KEY="${2:-$SCRIPT_DIR/test.key}"
PORT="${DOH_PORT:-18054}"
DNS_SERVER="${DNS_SERVER:-1.1.1.1}"

echo "=== ASAN Test Runner ==="
echo ""

# Build with ASAN
echo "Building with AddressSanitizer..."
make -C "$ROOT_DIR" asan >/dev/null 2>&1

# Generate test certs if needed
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "Generating test certificates..."
    "$SCRIPT_DIR/gen_test_certs.sh" "$SCRIPT_DIR"
    CERT="$SCRIPT_DIR/test.crt"
    KEY="$SCRIPT_DIR/test.key"
fi

# Configure ASAN options
export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:log_path=$SCRIPT_DIR/asan"

echo "Starting dohd with ASAN..."
echo "  Binary: $DOHD_BIN"
echo "  Port: $PORT"
echo "  ASAN log: $SCRIPT_DIR/asan.*"
echo ""

# Start dohd
"$DOHD_BIN" -c "$CERT" -k "$KEY" -p "$PORT" -d "$DNS_SERVER" -F -v &
DOHD_PID=$!

# Give it time to start
sleep 2

# Check if running
if ! kill -0 $DOHD_PID 2>/dev/null; then
    echo "ERROR: dohd failed to start. Check ASAN logs."
    cat "$SCRIPT_DIR"/asan.* 2>/dev/null || true
    exit 1
fi

echo "dohd running (PID: $DOHD_PID)"

# Wait for ready
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

for i in {1..50}; do
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

# Get stats
kill -USR1 $DOHD_PID 2>/dev/null || true
sleep 1

# Shutdown
echo ""
echo "Shutting down dohd..."
kill -TERM $DOHD_PID 2>/dev/null || true
wait $DOHD_PID 2>/dev/null || true

# Check ASAN output
echo ""
echo "=== ASAN Results ==="
if ls "$SCRIPT_DIR"/asan.* 1>/dev/null 2>&1; then
    if grep -q "ERROR:" "$SCRIPT_DIR"/asan.* 2>/dev/null; then
        echo ""
        echo "ASAN errors detected:"
        cat "$SCRIPT_DIR"/asan.*
        exit 1
    else
        echo "No ASAN errors in logs"
    fi
else
    echo "No ASAN log files created (no errors)"
fi

# Cleanup ASAN logs
rm -f "$SCRIPT_DIR"/asan.* 2>/dev/null

echo ""
echo "PASS: ASAN test completed without errors"
exit 0
