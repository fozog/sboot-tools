#!/bin/bash

TARGET="$1"
TYPE=$2
SUBJECT="$3"
mkdir -p "$TARGET/$TYPE"
openssl req -newkey rsa:2048 -nodes -keyout "$TARGET/$TYPE.key" -new -x509 -sha256 -days 3650 -subj "$SUBJECT/" -out "$TARGET/$TYPE/$SUBJECT.crt"
cp "$TARGET/$TYPE/$SUBJECT.crt" "$TARGET/$TYPE.crt"