DATA=$(pwd)/data

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
