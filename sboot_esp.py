import datetime
import re
import struct
import subprocess

from pathlib import Path

from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import serialization

from typing import Any

def get_authenticode_hash(filepath: Path) -> str | None:
    """Extract the Authenticode SHA-256 hash using osslsigncode."""

    try:
        result = subprocess.run(
            ["osslsigncode", "verify", "-in", str(filepath)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        match = re.search(
            r"message digest\s*:\s*([A-F0-9]{64})",
            result.stdout,
            re.IGNORECASE
        )

        if match:
            return match.group(1).upper()

    except FileNotFoundError:
        print("[Warning] 'osslsigncode' command not found.")

    return None
 
def parse_efi_signatures(filepath: Path, DB_CERTS: list[dict[str, Any]], DB_HASHES: set[str]):
    
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
