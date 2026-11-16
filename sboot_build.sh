#!/bin/bash

TARGET="$1"

BUILD_DIR="$TARGET/.build"

if [ ! -f $TARGET/GUID.txt ]; then
   uuidgen --random > $TARGET/GUID.txt
fi 

crt_to_esl() {
    local guid="$1"
    local file="$2"
    local output_dir="$3"

    local pem_file
    local cert_file
    local format
    local esl_file

    pem_file=$(mktemp) || return 1
    esl_file="$output_dir/$(basename "${file%.crt}").esle"

    format=$(file -b "$file")

    case "$format" in
        "PEM certificate"*)
            cert_file="$file"
            ;;
        "Certificate,"*)
            if ! openssl x509 -inform DER \
                -in "$file" -out "$pem_file"; then
                echo "ERROR: Cannot convert $file" >&2
                rm -f "$pem_file"
                return 1
            fi
            cert_file="$pem_file"
            ;;
        *)
            echo "WARNING: Unknown certificate format: $file ($format)" >&2
            rm -f "$pem_file"
            return 1
            ;;
    esac

    if ! cert-to-efi-sig-list -g "$guid" "$cert_file" "$esl_file"; then
        echo "ERROR: Failed to generate $esl_file" >&2
        rm -f "$esl_file"
        rm -f "$pem_file"
        return 1
    fi

    rm -f "$pem_file"
}

for dir in "$TARGET"/*; do

    [ -d "$dir" ] || continue
    #echo handling $dir 

    INSTALL_DIR="$BUILD_DIR/$(basename "$dir")"
    mkdir -p "$INSTALL_DIR"

    #echo "  dealing with certificates"
    for file in "$dir"/*.crt; do
        [ -f "$file" ] || continue
        crt_to_esl "$(< $TARGET/GUID.txt)" "$file" "$INSTALL_DIR"
    done

    if [ -f $dir/esp-programs.txt ]; then
        #echo "  dealing with ESP programs"
        mapfile -t efi_files < "$dir/esp-programs.txt"
        sudo hash-to-efi-sig-list "${efi_files[@]}" "$INSTALL_DIR/esp-programs.esle" > /dev/null
        sudo chown $USER "$INSTALL_DIR/esp-programs.esle"
    fi

    if [ -f $dir/hashes.txt ]; then
        #echo "  dealing with hashes"
        python3 sboot_hash_to_esl.py "$dir/hashes.txt" "$(< $TARGET/GUID.txt)" "$INSTALL_DIR/hashes.esle"
    fi

    #echo "  combining ESL files into  "$INSTALL_DIR"/$(basename "$INSTALL_DIR").esl"
    cat "$INSTALL_DIR"/*.esle > "$TARGET"/$(basename "$INSTALL_DIR").esl

done

#.esl is used to write the EFI variables except for PK, which uses .auth files
# signs db and dbx with KEK
sign-efi-sig-list -g "$(< $TARGET/GUID.txt)" -k $TARGET/KEK.key -c $TARGET/KEK.crt db $TARGET/db.esl $TARGET/db.auth > /dev/null
sign-efi-sig-list -g "$(< $TARGET/GUID.txt)" -k $TARGET/KEK.key -c $TARGET/KEK.crt dbx $TARGET/dbx.esl $TARGET/dbx.auth > /dev/null

#sign KEK and PK with PK
sign-efi-sig-list -g "$(< $TARGET/GUID.txt)" -k $TARGET/PK.key -c $TARGET/PK.crt KEK $TARGET/KEK.esl $TARGET/KEK.auth > /dev/null
sign-efi-sig-list -g "$(< $TARGET/GUID.txt)" -k $TARGET/PK.key -c $TARGET/PK.crt PK $TARGET/PK.esl $TARGET/PK.auth > /dev/null