if [ ! -f GUID.txt ]; then
   uuidgen --random > GUID.txt
fi 

DATA=$(pwd)/data
mkdir -p $DATA

# ---------------------------------------------
# 1. Platform Key (PK)
openssl req -newkey rsa:2048 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj "/CN=Shokubai Infrastructure Authority/" -out PK.crt
cert-to-efi-sig-list -g "$(< GUID.txt)" PK.crt $DATA/PK.esl
sign-efi-sig-list -g "$(< GUID.txt)" -k PK.key -c PK.crt PK $DATA/PK.esl $DATA/PK.auth

# ---------------------------------------------
# 2. Key Exchange Key (KEK)
openssl req -newkey rsa:2048 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj "/CN=Shokubai Security Authority/" -out KEK.crt
cert-to-efi-sig-list -g "$(< GUID.txt)" KEK.crt $DATA/KEK.esl
sign-efi-sig-list -g "$(< GUID.txt)" -k PK.key -c PK.crt KEK $DATA/KEK.esl $DATA/KEK.auth

# ---------------------------------------------
# 3. Signature Database (db)

# 3.1 create the certificates

# 3.1.1 self signed cert for custom firmware, boot tools
openssl req -newkey rsa:2048 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj "/CN=Shokubai Engineering Authority/" -out db.crt
cert-to-efi-sig-list -g "$(< GUID.txt)" db.crt $DATA/db_base.esl

if [ ! -f soliddriver-UEFI-SIGN-Certificate.crt ]; then
    wget http://drivers.suse.com/keys/soliddriver-UEFI-SIGN-Certificate.crt
fi 
cert-to-efi-sig-list -g "$(< GUID.txt)"  soliddriver-UEFI-SIGN-Certificate.crt $DATA/soliddriver-UEFI-SIGN-Certificate.esl

# 3.1.2 select the certificates you want to keep from current KEK
# efi-readvar -v KEK -o current_kek.esl
# sig-to-cert current_kek.esl current_kek-%d.der
# check the one you are interested in: openssl x509 -inform DER -in current_kek-%d.der-0.der  -noout -subject -fingerprint
# remove the current_kek-%d.der you don't want
# at this stage it is assumed that all  current_kek-*.der in current directory will be added into custom db
# mokutil --export
# check the content with openssl x509 -inform DER -in MOK-0000.der  -noout -subject -fingerprint
# remove the MOK-xxx.der you don't want
# at this stage it is assumed that all  MOK-*.der in current directory will be added into custom db
for cert in current_kek-*.der MOK-*.der; do
    [ -f "$cert" ] || continue

    base=$(basename "${cert%.der}")
    pem="$DATA/$base.pem"
    esl="$DATA/$base.esl"

    echo "Converting $cert"

    openssl x509 \
        -inform DER \
        -in "$cert" \
        -out "$pem" || exit 1

    cert-to-efi-sig-list \
        -g "$(< GUID.txt)" \
        "$pem" "$esl" || exit 1

    echo "Generated $esl"
done

# 3.4 create  hashes
SHIM_PATH=$(sudo find /boot/efi/EFI -iname "shimx64.efi" | head -n 1)
sudo hash-to-efi-sig-list "$SHIM_PATH" $DATA/shim_hash.esl
sudo chown $USER $DATA/shim_hash.esl

# 3.5 Combine certificates and sign it with KEK
cat $DATA/db_base.esl $DATA/current_kek-*.esl $DATA/MOK-*.esl $DATA/soliddriver-UEFI-SIGN-Certificate.esl $DATA/*hash.esl > $DATA/db.esl
sign-efi-sig-list -g "$(< GUID.txt)" -k KEK.key -c KEK.crt db $DATA/db.esl $DATA/db.auth


# ---------------------------------------------
# 4 DBX

# 4.1 Parse hashes from dbx.txt and generate dbx.esl using Python
# you can seed dbx.txt from  efi-readvar -v dbx | grep Hash:
if [  -f "dbx.txt" ]; then
python3 - << 'EOF'
import uuid
import struct
import re

with open("GUID.txt") as f:
    owner_guid = uuid.UUID(f.read().strip())

with open("dbx.txt") as f:
    content = f.read()

hashes = [bytes.fromhex(h) for h in re.findall(r'[0-9a-fA-F]{64}', content)]
sha256_guid = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")

signature_size = 48  # 16 bytes owner GUID + 32 bytes SHA-256 hash
list_size = 28 + (len(hashes) * signature_size)

with open("data/dbx.esl", "wb") as out:
    out.write(sha256_guid.bytes_le)
    out.write(struct.pack("<I", list_size))
    out.write(struct.pack("<I", 0))
    out.write(struct.pack("<I", signature_size))
    for h in hashes:
        out.write(owner_guid.bytes_le)
        out.write(h)

print(f"Generated dbx.esl containing {len(hashes)} blacklisted hashes.")
EOF

# 4.3 Sign the combined dbx ESL with your KEK
sign-efi-sig-list -g "$PROJECT_GUID" -k KEK.key -c KEK.crt dbx $DATA/dbx.esl $DATA/dbx.auth

fi

# ---------------------------------------------
#install the variables
# this is only possible when in Setup mode as reported by mokutil --sb-state:
# SecureBoot disabled
# Platform is in Setup Mode
# i.e. you just cleared EFI secureboot environement from UEFI Firmware

sudo efi-updatevar -e -f $DATA/db.esl db
sudo efi-updatevar -e -f $DATA/dbx.esl dbx
sudo efi-updatevar -e -f $DATA/KEK.esl KEK
sudo efi-updatevar -e -f $DATA/PK.auth PK

