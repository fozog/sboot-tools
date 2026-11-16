

# extracts existing UEFI certificates and hashes, as weel as UEFI boot programs
sboot_extract.py origin

cp -r origin newcd new

# customize DB
cd new/db
## Adds SUSE
wget http://drivers.suse.com/keys/pldp-UEFI-SIGN-Certificate.crt
## remove strange certificates
rm 1-Joe_s-Software-Emporium.crt 
## edit esp-programs.txt and hashes.txt (remoe or add as it is relevant)

## create your own certificates
sboot_create_key.sh new PK "/CN=Shokubai Infrastructure Authority"
sboot_create_key.sh new KEK "/CN=Shokubai Security Authority"
sboot_create_key.sh new db "/CN=Shokubai Engineering Authority"

# creates necessary signed and unsigned artifacts
sboot_build.sh new

# Install the new SecureBoot environe;ent

## reboot and place UEFI in setup mode (platform dependent)
mokutil --sb-state should answer "SecureBoot disabled\nPlatform is in Setup Mode"


## upate variables and reboot

sboot_install.sh