#!/bin/bash

TARGET=$1

# ---------------------------------------------
#install the variables
# this is only possible when in Setup mode as reported by mokutil --sb-state:
# SecureBoot disabled
# Platform is in Setup Mode
# i.e. you just cleared EFI secureboot environement from UEFI Firmware

echo Updating DB
sudo efi-updatevar -e -f $TARGET/db.esl db
echo Updating DBX
sudo efi-updatevar -e -f $TARGET/dbx.esl dbx
echo Updating KEK
sudo efi-updatevar -e -f $TARGET/KEK.esl KEK
echo Updating PK
#.esl is used to write the EFI variables except for PK, which uses .auth files
sudo efi-updatevar -f $TARGET/PK.auth PK
