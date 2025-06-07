#!/bin/zsh
#
#   Name:   removeServer.sh
#   Author: Field Effect Transistor
#   Desc:   Remove Lumina, easy-rsa and service
#   Creation Date: 06/07/25
#

# Load lumina.vars
CONFIG_FILE="$(dirname "$0")/lumina.vars"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "[ERROR] $CONFIG_FILE not found"
    exit 1
fi

# Providing Server Name
if [ -z "$SERVER_NAME" ]; then
    echo "[INPUT] Please provide server name: "
    read -r SERVER_NAME

    if [ -z "$SERVER_NAME" ]; then
        echo "[ERROR] Server name cannot be empty. Exiting."
        exit 1
    fi
fi

if [ ! -d "$LUMINA_DIR" ]; then
    echo "[WARN] $LUMINA_DIR not found"
else 
    rm -rf "$LUMINA_DIR"
fi

if [ -d "$LUMINA_DIR_BACKUP" ]; then
    rm -rf "$LUMINA_DIR_BACKUP"
fi

if [ ! -d "$EASY_RSA_DIR" ]; then
    echo "[WARN] $EASY_RSA_DIR not found"
else
    rm -rf "$EASY_RSA_DIR"
fi

if [ ! -f "$SERVICE_FILE" ]; then
    echo "[WARN] $SERVICE_FILE not found, check your server name or remove it manually (/etc/systemd/system/openvpn-\$SERVER_NAME.service)"
else
    rm -rf "$SERVICE_FILE"
fi
