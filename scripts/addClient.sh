#!/bin/zsh
#
#   Name:   addClient.sh
#   Author: Field Effect Transistor
#   Desc:   Add client to openvpn server
#           You should run ./initServerPart.sh first
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

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root"
    exit 2
fi

# Providing Client Name
if [ -z "$CLIENT_NAME" ]; then
    CLIENT_NAME="$1"
    if [ -z "$CLIENT_NAME" ]; then
        echo "[INPUT] Please provide client name: "
        read -r CLIENT_NAME
        if [ -z "$CLIENT_NAME" ]; then
            echo "[ERROR] Client name cannot be empty. Exiting."
            exit 1
        fi
    fi
fi

# Providing remote ip
if [ -z "$HOST" ]; then
    HOST="$2"
    if [ -z "$HOST" ]; then
        echo "[INPUT] Please provide server host: "
        read -r HOST
        if [ -z "$HOST" ]; then
            echo "[ERROR] Server host cannot be empty. Exiting."
            exit 1
        fi
    fi
fi

# Providing port
if [ -z "$PORT" ]; then
    PORT="$3"
    if [ -z "$PORT" ]; then
        echo "[INPUT] Please provide server port: "
        read -r PORT
        if [ -z "$PORT" ]; then
            echo "[ERROR] Port cannot be empty. Exiting."
            exit 1
        fi
    fi
fi

# Providing Client ip to reservation
if [ -z "$CLIENT_IP" ]; then
    CLIENT="$4"
    if [ -z "$CLIENT_IP"]; then
        echo "[INPUT] Please provide client ip to reservation: "
	read -r CLIENT_IP
	if []; then
	    echo "[ERROR] Client ip cannot be empty!"
	    exit 1
	fi
    fi    
fi

# Check if ip already reserved
if ! grep -r -q "ifconfig-push $CLIENT_IP" "$CCD"; then
    echo "[ERROR] $CLIENT_IP already reserved"
    exit 1
fi

# Add client dir
CLIENT_DIR="$LUMINA_DIR/$CLIENT_NAME"
echo "[INFO] Creating client directory $CLIENT_DIR"
if [ -d "$CLIENT_DIR" ]; then
    echo "[ERROR] $CLIENT_DIR already exists"
    exit 1
fi
mkdir -p "$CLIENT_DIR"
echo "[INFO] Copying easy-rsa to $SERVER_DIR"
cp -r "$EASY_RSA_DIR"/* "$CLIENT_DIR"
# Create client key
echo "[INFO] Creating client key"
cd "$CLIENT_DIR"
./easyrsa init-pki
EASYRSA_REQ_CN=$CLIENT_NAME ./easyrsa gen-req "$CLIENT_NAME" nopass <<< "$CLIENT_NAME"

# Sing client certificate
echo "[INFO] Signing client certificate"
cd "$CA_MACHINE_DIR"
EASYRSA_REQ_CN=$CLIENT_NAME ./easyrsa import-req "$CLIENT_DIR/pki/reqs/$CLIENT_NAME.req" "$CLIENT_NAME"
EASYRSA_REQ_CN=$CLIENT_NAME ./easyrsa sign-req client "$CLIENT_NAME" <<< "yes" <<< "yes"

CA_SERTIFICATE="$(cat "$OPENVPN_SERVER_DIR/ca.crt")"
CLIENT_CERT="$(cat "$CA_MACHINE_DIR/pki/issued/$CLIENT_NAME.crt")"
CLIENT_KEY="$(cat "$CLIENT_DIR/pki/private/$CLIENT_NAME.key")"
TLS_CRYPT_KEY="$(cat "$OPENVPN_SERVER_DIR/ta.key")"

# ovpn file
echo "[INFO] Creating ovpn file"
cat << EOF > "$LUMINA_DIR/$CLIENT_NAME/$CLIENT_NAME.ovpn"
client
dev $TUN_NAME
proto $PROTOCOL

remote $HOST $PORT
resolv-retry infinite
remote-cert-tls server
nobind

cipher AES-256-GCM

persist-key
persist-tun

<ca>
$CA_SERTIFICATE
</ca>

<cert>
$CLIENT_CERT
</cert>

<key>
$CLIENT_KEY
</key>

<tls-crypt>
$TLS_CRYPT_KEY
</tls-crypt>
EOF

# Address reservation
echo << EOF >> "$CCD/$CLIENT_NAME.conf"
ifconfig-push $CLIENT_IP $NETWORK
EOF

# The end
echo "[INFO] Exit"
