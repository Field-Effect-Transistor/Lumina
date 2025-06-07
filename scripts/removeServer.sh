#!/bin/zsh
#
#   Name:   removeServer.sh
#   Author: Field Effect Transistor
#   Desc:   Remove Lumina, easy-rsa and service
#   Creation Date: 06/07/25
#

SCRIPTS_DIR=$(cd -- "$(dirname -- "$0")" &>/dev/null && pwd)
echo "[INFO] Script directory: $SCRIPTS_DIR"

# Load lumina.vars
CONFIG_FILE="$SCRIPTS_DIR/lumina.vars"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "[ERROR] $CONFIG_FILE not found"
    exit 1
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root"
    exit 2
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
    echo "[INFO] Removing $LUMINA_DIR"
    rm -rf "$LUMINA_DIR"
fi

if [ -d "$LUMINA_DIR_BACKUP" ]; then
    echo "[INFO] Removing $LUMINA_DIR_BACKUP"
    rm -rf "$LUMINA_DIR_BACKUP"
fi

if [ ! -d "$EASY_RSA_DIR" ]; then
    echo "[WARN] $EASY_RSA_DIR not found"
else
    echo "[INFO] Removing $EASY_RSA_DIR"
    rm -rf "$EASY_RSA_DIR"
fi

if [ ! -f "$SERVICE_FILE" ]; then
    echo "[WARN] $SERVICE_FILE not found, check your server name or remove it manually (/etc/systemd/system/openvpn-\$SERVER_NAME.service)"
else
    echo "[INFO] Removing $SERVICE_FILE"
    rm -rf "$SERVICE_FILE"
fi
