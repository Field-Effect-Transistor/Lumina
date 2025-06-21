#!/bin/zsh
#
#   Name:   group.sh
#   Author: Field Effect Transistor
#   Desc:   manage groups
#   Creation Date: 06/08/25
#   Modified Date: 06/22/25
#

set -e

SCRIPTS_DIR=$(cd -- "$(dirname -- "$0")" &>/dev/null && pwd)
source "$SCRIPTS_DIR/lib.sh"
source "$SCRIPTS_DIR/lumina.vars"

case "$1" in
    # group init
    # створює основні групи, правило зберігати інші маршрути має викликатися лише раз
    init)
        checkRoot
        checkDependecies ipset iptables

        # Create admin group
        ipset create "$ADMIN_GROUP" hash:ip
        ipset add "$ADMIN_GROUP" "$ADMIN_IP"

        # main rules
        iptables -P FORWARD DROP
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

        iptables -A FORWARD -i ${TUN_NAME} -o ${TUN_NAME} -m set --match-set "$ADMIN_GROUP" src -d "$NETWORK/$NETMASK_" -m state --state NEW -j ACCEPT
    ;;

    forward)
        case "$2" in
            "on")
                echo "[INFO] Enabling IP forwarding"
                echo 1 > /proc/sys/net/ipv4/ip_forward
            ;;

            "off")
                echo "[INFO] Disabling IP forwarding"
                echo 0 > /proc/sys/net/ipv4/ip_forward
            ;;

            "status")
                echo "[INFO] IP forwarding status: $(cat /proc/sys/net/ipv4/ip_forward)"
            ;;

            *)
                echo "[ERROR] Unknown argument: $2"
                exit 1
            ;;
        esac
    ;;

    # group create <groupname> [<ip>]
    # Створює нову групу, налаштовує правила, додає ip першлго члену (потенційно користувач, що ініціював створення)
    create)
        ipset create "$2" hash:ip
        if [ -n "$3" ]; then
            ipset add "$2" "$3"
        fi
        iptables -A FORWARD -i ${TUN_NAME} -o ${TUN_NAME} -m set --match-set "$2" src -m set --match-set "$2" dst -m state --state NEW -j ACCEPT
    ;;

    # group destroy <groupname>
    # Видаляє групу
    destroy)
        iptables -D FORWARD -i "${TUN_NAME}" -o "${TUN_NAME}" -m set --match-set "$2" src -m set --match-set "$2" dst -m state --state NEW -j ACCEPT || true
        ipset destroy "$2"
    ;;

    # group add <groupname> <ip>
    # Додає ip до групи
    add)
        ipset add "$2" "$3"
    ;;

    # group remove <groupname> <ip>
    # Видаляє ip з групи
    remove)
        ipset del "$2" "$3"
    ;;

    # group list
    # Показує всі групи
    list)
        ipset list
    ;;

    # group save
    # Зберігає всі групи
    save)
        checkRoot
        checkDependecies

        mkdir -p "$FIREWALL"
        ipset save > "$GROUPS_FILE"
        iptables-save > "$IPTABLES_FILE"
    ;;

    # group restore
    # Відновлює збережені групи
    restore)
        checkRoot
        checkDependecies

        echo "[INFO] Destroying existing ipsets before restore..."
        if ipset list -n -q &>/dev/null; then
            ipset list -n -q | while read -r set_name; do
                echo "[INFO] Destroying ipset: $set_name"
                ipset destroy "$set_name"
            done
        else
            echo "[INFO] No existing ipsets to destroy."
        fi

        echo "[INFO] Restoring ipsets from $GROUPS_FILE"
        ipset restore < "$GROUPS_FILE"
        echo "[INFO] Restoring iptables rules from $IPTABLES_FILE"
        iptables-restore < "$IPTABLES_FILE"
        echo "[INFO] Restore complete."
    ;;

    *)
        echo "Usage: $0 {init|create|destroy|add|remove|list|save|restore}"
        exit 1
    ;;

esac