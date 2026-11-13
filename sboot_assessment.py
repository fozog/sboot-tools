#!/usr/bin/env python3
from __future__ import annotations

import warnings
warnings.filterwarnings("ignore")

import argparse
import glob
import os
import subprocess
import struct
import sys
import uuid
import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from pathlib import Path

from uefi_variable_api import (
    UEFIVariableError, UEFIVariableNotFoundError,
    get_firmware_variable,
)

import datetime

EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")

DB_CERTS = []
DB_HASHES = set()
DBX_CERTS = []
DBX_HASHES = set()

def parse_efivar(var_name):
    """Parse a Secure Boot variable through the common local UEFI API."""
    try:
        variable = get_firmware_variable(var_name)
    except UEFIVariableNotFoundError as exc:
        print(f"[{var_name}] {exc}\n")
        return
    except UEFIVariableError as exc:
        print(f"[{var_name}] Cannot access variable: {exc}\n")
        return

    entities = []
    now = datetime.datetime.now(datetime.timezone.utc)
    v_upper = var_name.upper()
    raw_data = variable.data
    offset = 0  # API has already removed efivarfs' 4-byte attributes prefix.

    while offset < len(raw_data):
        try:
            sig_type_bytes, list_size, header_size, sig_size = struct.unpack_from(
                "<16sIII", raw_data, offset
            )
        except struct.error:
            break
        if list_size < 28 or sig_size < 16 or offset + list_size > len(raw_data):
            break

        sig_type = uuid.UUID(bytes_le=sig_type_bytes)
        entry_offset = offset + 28 + header_size
        list_end = offset + list_size
        if entry_offset > list_end:
            break

        while entry_offset + sig_size <= list_end:
            payload = raw_data[entry_offset + 16 : entry_offset + sig_size]
            if sig_type == EFI_CERT_X509_GUID:
                try:
                    cert = x509.load_der_x509_certificate(payload)
                    issuer = cert.issuer.rfc4514_string()
                    subject = cert.subject.rfc4514_string()
                    expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d")
                    is_expired = cert.not_valid_after_utc < now
                    cert_info = {
                        "issuer": issuer,
                        "subject": subject,
                        "der": payload,
                        "expired": is_expired,
                    }
                    if v_upper == "DB":
                        DB_CERTS.append(cert_info)
                    elif v_upper == "DBX":
                        DBX_CERTS.append(cert_info)
                    entities.append(
                        f"'{subject}' issued by '{issuer}' (expired since {expiry})" if is_expired
                        else f"'{subject}' issued by '{issuer}' (expires {expiry})"
                    )
                except Exception:
                    pass
            elif sig_type == EFI_CERT_SHA256_GUID:
                digest = payload.hex().upper()
                if v_upper == "DB":
                    DB_HASHES.add(digest)
                elif v_upper == "DBX":
                    DBX_HASHES.add(digest)
                entities.append(f"Hash: {digest}")
            entry_offset += sig_size
        offset += list_size

    if v_upper == "DB":
        print("Boot policies (as defined in DB and DBX):")
        cert_entities = [e for e in entities if not e.startswith("Hash:")]
        hash_entities = [e for e in entities if e.startswith("Hash:")]
        if cert_entities:
            print("    Program signed by the following are accepted:")
            for entity in cert_entities:
                print(f"        {entity}")
        if hash_entities:
            print("\n    Programs that match the following hashes are accepted:")
            for entity in hash_entities:
                print(f"        {entity}")
    elif v_upper == "DBX":
        print("    Programs that match the following hashes are rejected:")
        for entity in entities or ["No blacklisted entries found."]:
            print(f"        {entity}")
    elif v_upper == "KEK":
        print("Authorities (KEK) that can change the above boot polices (i.e. update DB and DBX):")
        for entity in entities or ["No entries found."]:
            print(f"        {entity}")
    elif v_upper == "PK":
        print("Authority (PK) that can change the above authorities list (KEK):")
        for entity in entities or ["No entries found."]:
            print(f"        {entity}")
    print()

def parse_efi_signatures(filepath: Path):
    print(f"{filepath}")

    try:
        data = filepath.read_bytes()
    except PermissionError:
        print("  [Error] Permission denied. Run with sudo.")
        return
    except OSError as e:
        print(f"  [Error] Could not read file: {e}")
        return

    if len(data) < 0x40 or data[:2] != b"MZ":
        print("  [Skipped] Not a valid PE/EFI file.")
        print("  -> Secure Boot Prediction: FAIL (Not a valid PE file)\n")
        return

    authenticode_hash = None
    try:
        result = subprocess.run(
            ["osslsigncode", "verify", "-in", str(filepath)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        match = re.search(r"message digest\s*:\s*([A-F0-9]{64})", result.stdout, re.IGNORECASE)
        if match:
            authenticode_hash = match.group(1).upper()
            #print(f"  [Authenticode SHA-256]: {authenticode_hash}")
    except FileNotFoundError:
        print("  [Warning] 'osslsigncode' command not found.")

    hash_matched = authenticode_hash in DB_HASHES
    #if hash_matched:
    #    print("  [Hash Match]: Found in enrolled DB SHA-256 hashes!")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    opt_header_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, opt_header_offset)[0]
    data_dir_offset = opt_header_offset + (96 if magic == 0x10B else 112)
    sec_dir_offset = data_dir_offset + (4 * 8)
    cert_table_offset, cert_table_size = struct.unpack_from("<II", data, sec_dir_offset)

    cert_matched = False
    has_expired_cert = False

    if cert_table_offset > 0 and cert_table_size > 0:
        pos = cert_table_offset
        end = cert_table_offset + cert_table_size
        now = datetime.datetime.now(datetime.timezone.utc)

        while pos < end and pos + 8 <= len(data):
            dw_length, _, w_cert_type = struct.unpack_from("<IHH", data, pos)
            if dw_length < 8 or pos + dw_length > len(data):
                break

            if w_cert_type == 0x0002:
                pkcs7_bytes = data[pos + 8 : pos + dw_length]
                try:
                    certs = pkcs7.load_der_pkcs7_certificates(pkcs7_bytes)
                    for cert in certs:
                        issuer = cert.issuer.rfc4514_string()
                        expiry_dt = cert.not_valid_after_utc
                        is_expired = expiry_dt < now

                        if is_expired:
                            print(f"  '{issuer} (expired since {expiry_dt.strftime('%Y-%m-%d')})'")
                            has_expired_cert = True
                        else:
                            print(f"  '{issuer} (expires {expiry_dt.strftime('%Y-%m-%d')})'")

                        cert_der = cert.public_bytes(serialization.Encoding.DER)
                        for db_cert in DB_CERTS:
                            if db_cert["der"] == cert_der or db_cert["subject"] == cert.subject.rfc4514_string() or db_cert["subject"] == issuer:
                                cert_matched = True
                                if db_cert["expired"]:
                                    has_expired_cert = True
                except Exception:
                    pass
            pos += (dw_length + 7) & ~7

    if hash_matched:
        print("  -> Secure Boot Prediction: PASS (Verified via Authenticode Hash match in DB)")
    elif cert_matched:
        if has_expired_cert:
            print("  -> Secure Boot Prediction: FAIL (Matches DB certificate, but involves expired certificate)")
        else:
            print("  -> Secure Boot Prediction: PASS (Verified against DB certificate)")
    else:
        print("  -> Secure Boot Prediction: FAIL (Signature not trusted by DB and hash not enrolled)")
    print()

def get_mounted_esp_native() -> list[str]:
    """Finds active (mounted) EFI System Partitions using /proc and udev data."""
    esp_guid = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    mountpoints = []

    mountinfo_path = Path("/proc/self/mountinfo")
    if not mountinfo_path.exists():
        return mountpoints

    for line in mountinfo_path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        major_minor = parts[2]
        mountpoint = parts[4].replace("\\040", " ")

        udev_db_file = Path(f"/run/udev/data/b{major_minor}")
        if not udev_db_file.exists():
            continue

        for udev_line in udev_db_file.read_text(errors="ignore").splitlines():
            if udev_line.startswith("E:ID_PART_ENTRY_TYPE="):
                _, part_val = udev_line.split("=", 1)
                part_type = part_val.strip().lower()
                if part_type == esp_guid and mountpoint not in mountpoints:
                    mountpoints.append(mountpoint)
                break

    return mountpoints

def main():
    parser = argparse.ArgumentParser(description="Parse and predict Secure Boot status using Authenticode checks.")
    parser.add_argument("variables", nargs="*", default=["db", "dbx", "KEK", "PK"], help="UEFI variables to inspect")
    args = parser.parse_args()


    for var in args.variables:
        parse_efivar(var)

    if sys.platform.startswith("linux"):
        mountpoints = get_mounted_esp_native()

        if mountpoints:
            print("Assessment of installed EFI programs in active EFI System Partition(s):")

            for mp in mountpoints:
                efi_files = sorted(
                    p for p in Path(mp).rglob("*.[eE][fF][iI]") if p.is_file()
                )

                if not efi_files:
                    print(f"  No .efi files found under {mp}")
                    continue

                for efi_file in efi_files:
                    parse_efi_signatures(efi_file)
        else:
            print("No mounted EFI System Partition was identified; EFI program scan skipped.")


if __name__ == "__main__":
    main()
