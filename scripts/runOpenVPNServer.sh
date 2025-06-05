#!/bin/zsh
#
#   Name:   runOpenVPNServer.sh
#   Author: Field Effect Transistor
#   Desc:   run OpenVPN Server from $LUMINA directory
#           You should run ./initServerPart.sh first
#
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

# Check dependecies
dependecies=("openvpn")
all_installed=1

for packet in "${dependecies[@]}"; do
    if [ ! "$(pacman -Q $packet)" ]; then
        all_installed=0
        echo "[ERROR] $packet is not installed"
    fi
done

if [ "$all_installed" -eq 0 ]; then
    echo "[ERROR] Not all dependencies are installed. Exiting."
    exit 1
fi

echo "[INFO] All dependecies are installed"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root"
    exit 2
fi

cd "$OPENVPN_SERVER_DIR"
openvpn "$OPENVPN_SERVER_DIR/server.conf"
