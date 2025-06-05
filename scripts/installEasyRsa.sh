#!/bin/zsh
#
#   Name:   installEasyRsa.sh
#   Author: Field Effect Transistor
#   Desc:   Install easy-rsa to Lumina directory
#   Creation Date: 06/05/25
#

# Load lumina.vars
CONFIG_FILE="$(dirname "$0")/lumina.vars"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "[ERROR] $CONFIG_FILE not found"
    exit 1
fi

# Clonning easy-rsa
curl -SL "$EASY_RSA_URL" -o "/tmp/easy-rsa.zip"
unzip "/tmp/easy-rsa.zip" -d "/tmp"
mkdir -p "$EASY_RSA_DIR"
mv "/tmp/easy-rsa-master/easyrsa3"/* "$EASY_RSA_DIR"
mv "$EASY_RSA_DIR"/vars.example "$EASY_RSA_DIR"/vars
rm -rf "/tmp/easy-rsa-master" "/tmp/easy-rsa.zip"
