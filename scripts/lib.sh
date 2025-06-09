#!/bin/zsh
#
#   Name:   lib.sh
#   Author: Field Effect Transistor
#   Desc:   Library for lumina scripts
#   Creation Date: 06/05/25
#

checkRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] This script must be run as root"
        exit 2
    fi
}

# call checkDependecies "dep1" "dep2" "dep3"...
checkDependecies() {
    local all_installed=1
    local packet

    echo "[INFO] Checking dependecies"

    for packet in "$@"; do
        if ! command -v $packet &> /dev/null; then
            echo "[WARN] $packet is not installed"
            all_installed=0
        fi
    done
    if [ $all_installed -eq 0 ]; then
        echo "[ERROR] Some dependecies are not installed"
        exit 1
    fi

    echo "[INFO] All dependecies are installed"
}
