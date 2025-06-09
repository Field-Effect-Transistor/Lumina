#!/bin/zsh
#
#   Name:   revokeClient.sh
#   Author: Field Effect Transistor
#   Desc:   Revoke client from openvpn server
#           ! U need to restart openvpn server service after revoking
#           ! Havent tested yet
#   Creation Date: 06/07/25
#

SCRIPTS_DIR=$(cd -- "$(dirname -- "$0")" &>/dev/null && pwd)

# Load lumina.vars
CONFIG_FILE="$SCRIPTS_DIR/lumina.vars"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "[ERROR] $CONFIG_FILE not found"
    exit 1
fi

# Load libs
if [ -f "$SCRIPTS_DIR/lib.sh" ]; then
    source "$SCRIPTS_DIR/lib.sh"
else
    echo "[ERROR] $SCRIPTS_DIR/lib.sh not found"
    exit 1
fi

# Check root
checkRoot

# Providing Client Name
if [ -z "$CLIENT_NAME" ]; then
    CLIENT_NAME="$1"
    if [ -z "$CLIENT_NAME" ]; then
        echo "[INPUT] Please provide client name: "
        read -r CLIENT_NAME
    fi
fi

# CA-Machine
echo "[INFO] Revoking client $CLIENT_NAME"
cd "$CA_MACHINE_DIR"
./easyrsa --revoke "$CLIENT_NAME"
./easyrsa gen-crl

# OpenVPN Server

# check if crl already exists
if [ -f "$OPENVPN_SERVER_DIR/crl.pem" ]; then
    echo "[INFO] crl.pem already exists. Removing it."
    rm "$OPENVPN_SERVER_DIR/crl.pem"
else 
    echo "[INFO] crl.pem does not exist. Suppose crl-verify is disabled."
    echo "crl-verify $OPENVPN_SERVER_DIR/crl.pem" >> "$OPENVPN_SERVER_DIR/server.conf"
fi

echo "[INFO] Copying crl.pem to $OPENVPN_SERVER_DIR"
cp "$CA_MACHINE_DIR/pki/crl.pem" "$OPENVPN_SERVER_DIR/crl.pem"
chown openvpn:network "$OPENVPN_SERVER_DIR/crl.pem"

#! U need to restart openvpn server service after revoking
