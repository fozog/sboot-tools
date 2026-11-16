import sys
import uuid
import struct
from collections import defaultdict

input_file, guid, output_file = sys.argv[1:4]

owner_guid = uuid.UUID(guid)

# EFI signature type GUIDs
signature_types = {
    "a5c059a1-94e4-4aa7-87b5-ab155c2bf072": "X509",
    "826ca512-cf10-4ac9-b187-be01496631bd": "SHA1",
    "c1c41626-504c-4092-aca9-41f936934328": "SHA256",
    "ff3e0fae-a6c4-4f50-9f1b-d41e2b89c19a": "SHA384",
    "093e0fae-a6c4-4f50-9f1b-d41e2b89c19a": "SHA512",
}

type_guids = {
    name: uuid.UUID(guid)
    for guid, name in signature_types.items()
}

hash_sizes = {
    "SHA1": 20,
    "SHA256": 32,
    "SHA384": 48,
    "SHA512": 64,
}

# Group signatures by type
signatures = defaultdict(list)

with open(input_file) as f:
    for line_number, line in enumerate(f, 1):

        if not line or line.startswith("#"):
            continue
        
        line = line.strip()

        if not line:
            continue

        fields = line.split("|", 1)

        if len(fields) != 2:
            raise ValueError(f"Invalid format at line {line_number}")

        hash_type = fields[0].strip().upper()
        hash_value = fields[1].strip()

        if hash_type not in type_guids:
            raise ValueError(
                f"Unsupported signature type at line {line_number}: {hash_type}"
            )

        try:
            data = bytes.fromhex(hash_value)
        except ValueError:
            raise ValueError(f"Invalid hexadecimal data at line {line_number}")

        if hash_type in hash_sizes:
            if len(data) != hash_sizes[hash_type]:
                raise ValueError(
                    f"Invalid {hash_type} length at line {line_number}: "
                    f"expected {hash_sizes[hash_type]}, got {len(data)}"
                )

        signatures[hash_type].append(data)

# Generate ESL
with open(output_file, "wb") as out:

    for hash_type, entries in signatures.items():

        signature_type_guid = type_guids[hash_type]

        signature_size = 16 + len(entries[0])

        list_size = 28 + len(entries) * signature_size

        out.write(signature_type_guid.bytes_le)
        out.write(struct.pack("<I", list_size))
        out.write(struct.pack("<I", 0))
        out.write(struct.pack("<I", signature_size))

        for data in entries:
            out.write(owner_guid.bytes_le)
            out.write(data)
