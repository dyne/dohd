#!/bin/bash
# Generate self-signed TLS certificates for testing
#
# Usage: ./gen_test_certs.sh [output_dir]
#

set -e

OUTPUT_DIR="${1:-.}"
CERT_FILE="$OUTPUT_DIR/test.crt"
KEY_FILE="$OUTPUT_DIR/test.key"

# Check if certs already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "Test certificates already exist: $CERT_FILE, $KEY_FILE"
    exit 0
fi

echo "Generating self-signed test certificates..."

openssl req -x509 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -nodes \
    -subj "/CN=localhost/O=DoHD Test/C=XX" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
    2>/dev/null

chmod 600 "$KEY_FILE"

echo "Generated: $CERT_FILE, $KEY_FILE"
