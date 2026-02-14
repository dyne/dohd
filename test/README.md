# DoHD Testing Guide

This directory contains unit tests, integration tests, and memory leak detection tools for dohd.

## Quick Start

```bash
# Run all unit tests
make check

# Run with ASAN (Address Sanitizer) for leak detection
make check-asan

# Run integration tests (requires running dohd instance)
make check-integration

# Run valgrind leak detection
make check-valgrind
```

## Unit Tests

Unit tests are self-contained and don't require a running dohd instance.

### test_url64.c / test_url64_extended.c

Tests the URL-safe base64 decoder used for DoH GET requests.

- Basic decoding functionality
- Edge cases (empty string, NULL, single char)
- Invalid character detection
- Length estimation
- DNS query encoding/decoding

### test_heap.c

Tests the min-heap implementation used for timer scheduling in libevquick.

- Heap initialization and destruction
- Insert/peek/delete operations
- Min-heap ordering verification
- Stress test with 1000 elements
- Memory reallocation during growth
- ID wraparound handling

### test_dns_parser.c

Tests DNS packet parsing functions for TTL extraction.

- DNS header parsing
- Question section skipping
- TTL extraction from responses
- Multiple record handling (returns minimum TTL)
- Truncated packet handling
- Compression pointer detection

## Integration Tests

Integration tests require a running dohd instance with TLS certificates.

### Setup

```bash
# Generate test certificates
./gen_test_certs.sh

# Start dohd (in another terminal)
../src/dohd -c test.crt -k test.key -p 8053 -d 8.8.8.8 -F -v
```

### test_client_lifecycle.sh

Stress test for rapid connect/disconnect cycles.

- Tests client_data allocation/deallocation
- Runs parallel connections
- Configurable via environment variables:
  - `DOH_HOST` - hostname (default: localhost)
  - `DOH_PORT` - port (default: 8053)
  - `DOH_ITERATIONS` - number of iterations (default: 100)
  - `DOH_PARALLEL` - parallel connections (default: 5)

### test_request_leaks.sh

Memory leak detection via request volume testing.

- Makes many DNS requests
- Monitors memory usage via /proc and dohd stats
- Tests request lifecycle (req_slot allocation/deallocation)

### test_concurrent.sh

Concurrent connection stress test.

- Multiple workers making continuous requests
- Measures requests per second
- Configurable:
  - `DOH_CONCURRENT` - number of concurrent workers (default: 50)
  - `DOH_DURATION` - test duration in seconds (default: 10)

## Memory Leak Detection

### AddressSanitizer (ASAN)

ASAN is the fastest way to detect memory errors during development.

```bash
# Build with ASAN
make asan

# Run the ASAN test script
./run_asan_test.sh

# Or manually test
export ASAN_OPTIONS="detect_leaks=1"
./dohd -c test.crt -k test.key -p 8053 -d 8.8.8.8 -F
```

### Valgrind

Valgrind provides detailed leak analysis but runs slower.

```bash
# Run automated valgrind test
./valgrind_test.sh

# Or manually
valgrind --leak-check=full --show-leak-kinds=all \
    ./dohd -c test.crt -k test.key -p 8053 -d 8.8.8.8 -F
```

### dmalloc

dohd supports dmalloc for detailed memory debugging.

```bash
# Build with dmalloc
make dmalloc

# Set dmalloc options
export DMALLOC_OPTIONS=debug=0x4f47d03,log=dmalloc.log

# Run dohd, then check dmalloc.log
```

## Key Areas for Leak Detection

Based on code analysis, these are the critical allocation/deallocation points:

1. **client_data** (dohd.c:1015, 285)
   - Allocated on new connection
   - Freed on disconnect or error
   - Contains SSL session, events, request list

2. **req_slot** (dohd.c:391, 589)
   - Allocated per DNS request
   - Freed after response sent or on timeout
   - Contains DNS socket, response data

3. **h2_response_data** (dohd.c:712, 613)
   - Allocated for HTTP/2 response body
   - Must be freed after transmission

4. **evquick events** (libevquick.c:179, 216)
   - Allocated when adding event handlers
   - Must be deleted before closing sockets

5. **nghttp2 sessions** (dohd.c:945, 347)
   - Created during TLS handshake
   - Must be deleted on client disconnect

## Flamethrower Testing

For performance and stress testing, use DNS-OARC flamethrower:

```bash
# Install: https://github.com/DNS-OARC/flamethrower
make check-flame HOST=localhost PORT=8053
```

## Writing New Tests

Unit tests should:
- Be self-contained (no external dependencies)
- Use the TEST_ASSERT macro pattern
- Return 0 on success, 1 on failure
- Print clear PASS/FAIL messages

Integration tests should:
- Check for connectivity before testing
- Be configurable via environment variables
- Clean up resources on exit
- Request dohd stats (SIGUSR1) for verification
