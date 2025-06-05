#!/bin/zsh

set -e

# Check dependecies
dependecies=("openvpn" "openssl" "git" "unzip" "curl")
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

# Providing Server Name
SERVER_NAME=""
echo "[INPUT] Please provide server name: "
read -r SERVER_NAME

# Creating working directory
LUMINA_DIR="/root/.lumina"
LUMINA_DIR_BACKUP="${LUMINA_DIR}.bak"

if [ -d "$LUMINA_DIR" ]; then
    echo "[WARN] $LUMINA_DIR already exists"
    echo "[INPUT] Do you want to [Y]es (overwrite), [N]o (exit), or [B]ackup (default B)?"
    read -r choice_input

    choice_char_upper=$(echo "$choice_input" | tr '[:lower:]' '[:upper:]')

    if [[ -z "$choice_char_upper" ]]; then
        choice_char_upper="B"
    fi

    case "$choice_char_upper" in
        B)
            echo "[INFO] Backing up $LUMINA_DIR to $LUMINA_DIR_BACKUP"
            if [ -e "$LUMINA_DIR_BACKUP" ]; then
                echo "[WARN] Backup directory $LUMINA_DIR_BACKUP already exists. Overwriting it."
                rm -rf "$LUMINA_DIR_BACKUP"
            fi
            mv "$LUMINA_DIR" "$LUMINA_DIR_BACKUP"
            mkdir -p "$LUMINA_DIR"
            ;;
        Y)
            echo "[INFO] Removing $LUMINA_DIR"
            rm -rf "$LUMINA_DIR"
            mkdir -p "$LUMINA_DIR"
            ;;
        N)
            echo "[INFO] Exiting"
            exit 1
            ;;
        *) 
            echo "[ERROR] Invalid choice: '$choice_input'. Exiting."
            exit 1
            ;;
    esac
else
    echo "[INFO] Creating directory $LUMINA_DIR"
    mkdir -p "$LUMINA_DIR"
fi

# Clonning easy-rsa
cd "$LUMINA_DIR"
echo "[INFO] Installing easy-rsa"
curl -SL "https://github.com/OpenVPN/easy-rsa/archive/refs/heads/master.zip" -o "easy-rsa.zip"
unzip easy-rsa.zip
EASY_RSA_DIR="$LUMINA_DIR/easy-rsa-master/easyrsa3"
mv "$EASY_RSA_DIR"/vars.example "$EASY_RSA_DIR"/vars
rm easy-rsa.zip

# Create CA-Machine
CA_MACHINE_DIR="$LUMINA_DIR/ca-machine"

echo "[INFO] Creating directory $CA_MACHINE_DIR"
mkdir "$CA_MACHINE_DIR"
echo "[INFO] Copying easy-rsa to $CA_MACHINE_DIR"
cp -r "$EASY_RSA_DIR"/* "$CA_MACHINE_DIR"

# Create CA
echo "[INFO] Creating CA"
cd "$CA_MACHINE_DIR"
easyrsa init-pki
EASYRSA_REQ_CN=$SERVER_NAME easyrsa build-ca nopass <<< "$SERVER_NAME"

# Create OpenVPN Server
OPENVPN_SERVER_DIR="$LUMINA_DIR/openvpn/server"

echo "[INFO] Copying ca.crt to $OPENVPN_SERVER_DIR"
mkdir -p "$OPENVPN_SERVER_DIR"
cp "$CA_MACHINE_DIR/pki/ca.crt" "$OPENVPN_SERVER_DIR/ca.crt"

# Create Server Key
SERVER_DIR="$LUMINA_DIR/$SERVER_NAME"
echo "[INFO] Creating server directory $SERVER_DIR"
mkdir -p "$SERVER_DIR"
echo "[INFO] Copying easy-rsa to $SERVER_DIR"
cp -r "$EASY_RSA_DIR"/* "$SERVER_DIR"
echo "[INFO] Creating server key"
cd "$SERVER_DIR"
easyrsa init-pki
EASYRSA_REQ_CN=$SERVER_NAME easyrsa gen-req "$SERVER_NAME" nopass <<< "$SERVER_NAME"

echo "[INFO] Copying server key to $OPENVPN_SERVER_DIR"
cp "$SERVER_DIR/pki/private/$SERVER_NAME.key" "$OPENVPN_SERVER_DIR"

# Diffie-Hellman (DH) parameters file & Hash-based Message Authentication Code (HMAC) key
openssl dhparam -out "$OPENVPN_SERVER_DIR/dh.pem" 2048
openvpn --genkey secret "$OPENVPN_SERVER_DIR/ta.key"
chown openvpn:network "$OPENVPN_SERVER_DIR/ta.key"

# Sign server certificate
cd "$CA_MACHINE_DIR"
EASYRSA_REQ_CN=$SERVER_NAME easyrsa sign-req server "$SERVER_NAME" <<< "$SERVER_NAME"
