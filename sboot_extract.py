#!/usr/bin/env python3

import argparse
import struct
import subprocess
import uuid
import re
import sys

from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import warnings
from cryptography.utils import CryptographyDeprecationWarning

import sboot_esp

warnings.filterwarnings(
    "ignore",
    category=CryptographyDeprecationWarning,
    message="Parsed a negative serial number.*"
)


EFIVARS = Path("/sys/firmware/efi/efivars")

EFI_GLOBAL_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

EFI_IMAGE_SECURITY_DATABASE_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"


# EFI signature type GUIDs
SIGNATURE_TYPES = {
    "a5c059a1-94e4-4aa7-87b5-ab155c2bf072": "X509",
    "826ca512-cf10-4ac9-b187-be01496631bd": "SHA1",
    "c1c41626-504c-4092-aca9-41f936934328": "SHA256",
    "ff3e0fae-a6c4-4f50-9f1b-d41e2b89c19a": "SHA384",
    "093e0fae-a6c4-4f50-9f1b-d41e2b89c19a": "SHA512",
}

VARIABLES = ("PK", "KEK", "db", "dbx")


def safe_filename(name):
    """Make a string suitable for use in a filename."""
    name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)
    return name.strip("._-")[:100] or "Unknown"


def extract_cn(certificate_data):
    """Extract the Subject Common Name from a DER certificate."""
    cert = x509.load_der_x509_certificate(certificate_data)

    attributes = cert.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME
    )

    return safe_filename(attributes[0].value) if attributes else "No-CN"


def read_variable(name):
    """Read a UEFI variable from efivars."""

    guid = (
        EFI_GLOBAL_GUID
        if name in ("PK", "KEK")
        else EFI_IMAGE_SECURITY_DATABASE_GUID
    )

    filename = EFIVARS / f"{name}-{guid}"

    if not filename.exists():
        raise FileNotFoundError(
            f"UEFI variable not found: {filename}"
        )

    data = filename.read_bytes()

    if len(data) < 4:
        raise ValueError(f"Invalid UEFI variable: {name}")

    return data[4:]



def extract_variable(name, destination):
    """Extract certificates and hashes from an EFI variable."""

    print(f"Extracting {name}...")

    output = destination / name
    output.mkdir(parents=True, exist_ok=True)

    # Remove previous extraction results.
    for file in output.glob("*.der"):
        file.unlink()

    hashes = []

    data = read_variable(name)

    offset = 0
    index = 0

    while offset < len(data):

        # EFI_SIGNATURE_LIST:
        #   SignatureType       (16 bytes)
        #   SignatureListSize   (4 bytes)
        #   SignatureHeaderSize (4 bytes)
        #   SignatureSize       (4 bytes)

        if offset + 28 > len(data):
            raise ValueError(f"{name}: incomplete signature list header")

        signature_guid = str(
            uuid.UUID(bytes_le=data[offset:offset + 16])
        )

        list_size, header_size, signature_size = struct.unpack_from(
            "<III", data, offset + 16
        )

        if list_size < 28 or offset + list_size > len(data):
            raise ValueError(f"{name}: invalid signature list size")

        if signature_size < 16:
            raise ValueError(f"{name}: invalid signature size")

        entries_offset = offset + 28 + header_size
        list_end = offset + list_size

        if entries_offset > list_end:
            raise ValueError(f"{name}: invalid signature header size")

        if (list_end - entries_offset) % signature_size:
            raise ValueError(f"{name}: invalid signature entry alignment")

        signature_type = SIGNATURE_TYPES.get(
            signature_guid, "UNKNOWN"
        )

        while entries_offset < list_end:

            # Skip the 16-byte SignatureOwner GUID.
            signature = data[
                entries_offset + 16:
                entries_offset + signature_size
            ]

            if signature_type == "X509":

                cn = extract_cn(signature)
                filename = output / f"{index}-{cn}.crt"

                result = subprocess.run(
                    ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                    input=signature,
                    capture_output=True,
                    check=True
                )

                filename.write_bytes(result.stdout)

                print(f"  Certificate: {filename.name}")

                index += 1
            elif signature_type.startswith("SHA"):

                digest = signature.hex()

                hashes.append(
                    f"{signature_type}|{digest}"
                )

                #print(f"  Hash: {signature_type} {digest}")

            else:
                print(
                    f"  Unsupported signature type: {signature_guid}"
                )

            
            entries_offset += signature_size

        offset += list_size

    # Write hashes for db and dbx.
    if name in ("db", "dbx") and len(hashes) > 0:

        hash_file = output / "hashes.txt"

        with hash_file.open("w") as file:
            file.write("# Algorithm|Hash\n")

            for entry in hashes:
                file.write(entry + "\n")
        print(f"  {len(hashes)} hashes placed in hashes.txt")



def main():

    parser = argparse.ArgumentParser(
        description="Extract UEFI Secure Boot variables."
    )

    parser.add_argument(
        "destination",
        type=Path,
        help="Destination directory"
    )

    args = parser.parse_args()

    destination = args.destination
    destination.mkdir(parents=True, exist_ok=True)

    for variable in VARIABLES:
        try:
            extract_variable(variable, destination)

        except FileNotFoundError as error:
            print(f"Warning: {error}", file=sys.stderr)

        except Exception as error:
            print(
                f"Error extracting {variable}: {error}",
                file=sys.stderr
            )
            sys.exit(1)

    mountpoints = sboot_esp.get_mounted_esp_native()

    if mountpoints:
        print("Get EFI programs.")

        for mp in mountpoints:
            efi_files = sorted(
                p for p in Path(mp).rglob("*.[eE][fF][iI]") if p.is_file()
            )

            if not efi_files:
                print(f"  No .efi files found under {mp}")
                continue

            hash_file = destination / "db" / "esp-programs.txt"

            with hash_file.open("w") as file:

                for efi_file in efi_files:
                    file.write(str(efi_file) + "\n")


    print(f"Extraction completed: {destination}")


if __name__ == "__main__":
    main()
