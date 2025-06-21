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

        echo "[INFO] --- Starting Restore Process ---"

        # 1. Очистити iptables, щоб видалити посилання на ipsets
        echo "[INFO] Stage 1: Clearing all iptables rules and setting default policies..."
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT # Встановіть потрібну вам політику за замовчуванням
        iptables -P OUTPUT ACCEPT
        iptables -F # Flush (видалити) всі правила з усіх ланцюжків
        iptables -X # Видалити всі користувацькі (не за замовчуванням) ланцюжки
        iptables -Z # Обнулити лічильники пакетів та байтів у всіх ланцюжках
        echo "[INFO] iptables cleared."

        # 2. Знищити існуючі ipsets
        echo "[INFO] Stage 2: Destroying existing ipsets..."
        if ipset list -n -q &>/dev/null; then
            ipset list -n -q | while read -r set_name; do
                echo "[INFO] Destroying ipset: $set_name"
                if ! ipset destroy "$set_name" 2>/dev/null; then
                    # Якщо після повного очищення iptables набір все ще використовується,
                    # це дивно і може вказувати на іншу проблему або компонент ядра.
                    echo "[ERROR] Could not destroy ipset '$set_name' even after clearing iptables. It might be in use by another kernel component or locked."
                else
                    echo "[INFO] Successfully destroyed ipset: $set_name"
                fi
            done
        else
            echo "[INFO] No existing ipsets to destroy."
        fi
        echo "[INFO] ipsets destruction phase complete."

        # 3. Відновити ipsets з файлу
        echo "[INFO] Stage 3: Restoring ipsets from $GROUPS_FILE..."
        if [ -f "$GROUPS_FILE" ]; then
            if ipset restore < "$GROUPS_FILE"; then
                echo "[INFO] ipsets successfully restored from $GROUPS_FILE."
            else
                echo "[ERROR] Failed to restore ipsets from $GROUPS_FILE. Check the file for errors."
                # Можна додати вихід з помилкою тут, якщо відновлення ipset є критичним
                # exit 1
            fi
        else
            echo "[WARNING] ipset groups file ($GROUPS_FILE) not found. Skipping ipset restore."
        fi

        # 4. Відновити iptables з файлу (тепер вони можуть посилатися на новостворені ipsets)
        echo "[INFO] Stage 4: Restoring iptables rules from $IPTABLES_FILE..."
        if [ -f "$IPTABLES_FILE" ]; then
            if iptables-restore < "$IPTABLES_FILE"; then
                echo "[INFO] iptables rules successfully restored from $IPTABLES_FILE."
            else
                echo "[ERROR] Failed to restore iptables rules from $IPTABLES_FILE. Check the file for errors."
                # exit 1
            fi
        else
            echo "[WARNING] iptables rules file ($IPTABLES_FILE) not found. Skipping iptables restore."
        fi

        echo "[INFO] --- Restore Process Complete ---"
    ;;

    *)
        echo "Usage: $0 {init|create|destroy|add|remove|list|save|restore}"
        exit 1
    ;;

esac