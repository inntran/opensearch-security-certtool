#!/usr/bin/env bash
# Converts a PKCS#8 private key encrypted with a legacy scheme this tool
# doesn't support (e.g. Java's pbeWithSHA1And3-KeyTripleDES-CBC) into
# standard PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC), which this tool and
# other standard PKCS#8 consumers (OpenSSL, the OpenSearch security plugin)
# can read.
#
# Usage: convert-legacy-ca-key.sh <input-key.pem> <output-key.pem>
#
# You will be prompted twice: once for the input key's existing password,
# once for the new password to protect the converted key.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <input-key.pem> <output-key.pem>" >&2
  exit 1
fi

input_key="$1"
output_key="$2"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl is required but not found in PATH" >&2
  exit 1
fi

if [ ! -f "$input_key" ]; then
  echo "Error: input key not found: $input_key" >&2
  exit 1
fi

tmp_decrypted="$(mktemp)"
cleanup() {
  if command -v shred >/dev/null 2>&1; then
    shred -u "$tmp_decrypted" 2>/dev/null || rm -f "$tmp_decrypted"
  else
    rm -f "$tmp_decrypted"
  fi
}
trap cleanup EXIT

echo "Decrypting $input_key (you will be prompted for its current password)..."
openssl pkcs8 -in "$input_key" -out "$tmp_decrypted"

echo "Re-encrypting as standard PKCS#8 PBES2 (AES-256-CBC + PBKDF2-HMAC-SHA256)..."
echo "You will be prompted for a new password for $output_key."
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 \
  -in "$tmp_decrypted" -out "$output_key"

echo "Done: $output_key"
