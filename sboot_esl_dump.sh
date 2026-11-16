#!/usr/bin/env bash
#
# esl-dump.sh - Dump UEFI EFI Signature List (.esl) files
#
# Dependencies: bash, python3, openssl
#
# Usage: ./esl-dump.sh file.esl

set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
    echo "Usage: $0 <file.esl>"
    exit 1
fi

ESL_FILE="$1"

python3 - "$ESL_FILE" <<'PY'
import sys
import struct
import uuid
import hashlib
import tempfile
import subprocess
import os

filename = sys.argv[1]

EFI_CERT_X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"

with open(filename, "rb") as f:
    data = f.read()

offset = 0
list_number = 0

print(f"UEFI ESL dump: {filename}")
print(f"File size: {len(data)} bytes")
print("=" * 70)

while offset < len(data):

    if len(data) - offset < 28:
        print(f"ERROR: Incomplete ESL header at offset {offset}")
        break

    sig_type = uuid.UUID(bytes_le=data[offset:offset+16])

    list_size, header_size, sig_size = struct.unpack_from(
        "<III", data, offset + 16
    )

    list_number += 1

    print(f"\nSignature List #{list_number}")
    print("-" * 70)
    print(f"Offset:              0x{offset:08x}")
    print(f"Signature Type GUID: {sig_type}")
    print(f"Signature List Size: {list_size}")
    print(f"Signature Header:    {header_size}")
    print(f"Signature Size:      {sig_size}")

    if list_size < 28 or offset + list_size > len(data):
        print("ERROR: Invalid signature list size")
        break

    if sig_size < 16:
        print("ERROR: Invalid signature size")
        break

    signatures_start = offset + 28 + header_size
    signatures_end = offset + list_size

    if signatures_start > signatures_end:
        print("ERROR: Invalid signature header size")
        break

    payload_size = signatures_end - signatures_start

    if payload_size % sig_size != 0:
        print("ERROR: Signature data is not aligned")
        break

    count = payload_size // sig_size

    print(f"Number of signatures: {count}")

    for i in range(count):

        pos = signatures_start + i * sig_size

        owner = uuid.UUID(bytes_le=data[pos:pos+16])
        signature = data[pos+16:pos+sig_size]

        print(f"\n  Signature #{i+1}")
        print(f"  Owner GUID: {owner}")
        print(f"  Data size:  {len(signature)} bytes")
        print(f"  SHA256:     {hashlib.sha256(signature).hexdigest()}")

        if str(sig_type) == EFI_CERT_X509:

            print("  Type: X.509 Certificate")

            with tempfile.NamedTemporaryFile() as cert:
                cert.write(signature)
                cert.flush()

                result = subprocess.run(
                    ["openssl", "x509", "-inform", "DER",
                     "-in", cert.name, "-noout", "-text"],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        print("  " + line)
                else:
                    print("  Unable to decode certificate")
                    print("  " + result.stderr.strip())

        else:
            print("  Raw signature data:")
            for j in range(0, len(signature), 16):
                chunk = signature[j:j+16]
                print("  " + chunk.hex(" "))

    offset += list_size

print("\n" + "=" * 70)
print(f"Processed {list_number} signature list(s).")
PY

