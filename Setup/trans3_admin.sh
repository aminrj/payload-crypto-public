#!/bin/bash
# ==============================================================================
# TRANS3 SMART ADMIN INTERFACE V3.2 (LAYER 3 ENCRYPTOR)
# ==============================================================================

RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'
WHITE='\e[1;37m'; MAGENTA='\e[1;35m'; BOLD='\e[1m'; NC='\e[0m'

exec 2>/dev/null

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] Access denied: Root privileges required (sudo trans3).${NC}"
    exit 1
fi

# ------------------------------------------------------------------------------
# Détection des interfaces réseau physiques
# ------------------------------------------------------------------------------
detect_physical_interfaces() {
    local interfaces=()
    for iface in /sys/class/net/*; do
        iface=$(basename "$iface")
        # Ignorer loopback
        [ "$iface" = "lo" ] && continue
        # Ignorer les interfaces virtuelles courantes (docker, veth, bridges, etc.)
        [[ "$iface" =~ ^(docker|veth|br-|virbr|tun|tap|bond) ]] && continue
        # Vérifier que l'interface est physique (présence du dossier device)
        if [ -d "/sys/class/net/$iface/device" ]; then
            interfaces+=("$iface")
        fi
    done
    printf '%s\n' "${interfaces[@]}"
}

# ------------------------------------------------------------------------------
# Choix de l'interface au démarrage
# ------------------------------------------------------------------------------
choose_interface_at_startup() {
    local interfaces=($(detect_physical_interfaces))
    if [ ${#interfaces[@]} -eq 0 ]; then
        echo -e "${RED}[-] Aucune interface réseau physique détectée.${NC}"
        exit 1
    fi

    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Sélectionnez l'interface à protéger par TRANS3   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    for i in "${!interfaces[@]}"; do
        echo -e "  ${BOLD}$((i+1)).${NC} ${interfaces[$i]}"
    done
    echo ""
    read -p "Votre choix (1-${#interfaces[@]}) : " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#interfaces[@]}" ]; then
        SELECTED_IF="${interfaces[$((choice-1))]}"
        echo -e "${GREEN}[+] Interface sélectionnée : ${BOLD}$SELECTED_IF${NC}"
    else
        echo -e "${RED}[-] Choix invalide.${NC}"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Initialisation réseau (appliquée à l'interface sélectionnée)
# ------------------------------------------------------------------------------
init_network() {
    modprobe nf_conntrack >/dev/null 2>&1 || true
    modprobe nf_defrag_ipv4 >/dev/null 2>&1 || true
    modprobe xt_TRANS3 >/dev/null 2>&1 || true

    # Désactivation des offloads matériels sur l'interface sélectionnée
    ethtool -K "$SELECTED_IF" tx off rx off tso off gso off gro off ufo off lro off tx-checksum-ip-generic off rx-checksum off >/dev/null 2>&1 || true

    # Augmentation du MTU pour absorber le +32B de TRANS3
    ip link set dev "$SELECTED_IF" mtu 1500 >/dev/null 2>&1 || true

    # TCP MSS Clamping global pour forcer les paquets à 1428 octets de payload
    iptables-legacy -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428 >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------------------
# Nettoyage (restauration interface + purge règles)
# ------------------------------------------------------------------------------
teardown() {
    iptables-legacy -t mangle -F POSTROUTING >/dev/null 2>&1 || true
    iptables-legacy -t mangle -F PREROUTING >/dev/null 2>&1 || true
    iptables-legacy -t mangle -F >/dev/null 2>&1 || true

    # Restauration de l'interface
    ip link set dev "$SELECTED_IF" mtu 1500 >/dev/null 2>&1 || true
    ethtool -K "$SELECTED_IF" tx one rx one tso one gso one gro one ufo one lro one tx-checksum-ip-generic one rx-checksum one  >/dev/null 2>&1 || true

    if command -v iptables-save >/dev/null 2>&1; then
        mkdir -p /etc/iptables >/dev/null 2>&1 || true
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

# ------------------------------------------------------------------------------
# Lancement au boot (option --boot)
# ------------------------------------------------------------------------------
if [[ "${1:-}" == "--boot" ]]; then
    # En mode boot, on a besoin de connaître l'interface.
    # On peut la définir via une variable d'environnement ou un fichier de configuration.
    # Par simplicité, on prend la première interface physique détectée.
    SELECTED_IF=$(detect_physical_interfaces | head -n1)
    if [ -z "$SELECTED_IF" ]; then
        echo -e "${RED}[-] No physical interface found for boot.${NC}"
        exit 1
    fi
    init_network
    exit 0
fi

# ------------------------------------------------------------------------------
# Choix de l'interface au démarrage
# ------------------------------------------------------------------------------
choose_interface_at_startup

# ------------------------------------------------------------------------------
# Fonctions d'affichage et menu
# ------------------------------------------------------------------------------
pause() {
    echo -e "\n${CYAN}Press Enter to continue...${NC}"
    read -r
}

print_menu() {
    clear
    local MOD_STATUS="${RED}Offline [X]${NC}"
    if lsmod | grep -q "xt_TRANS3"; then MOD_STATUS="${GREEN}Operational [V]${NC}"; fi

    local ACTIVE_RULES=$(iptables-legacy -t mangle -S POSTROUTING 2>/dev/null | grep "TRANS3 --mode e" | grep -oP -- '-d \K[0-9\.]+' | sort -u | wc -l)
    [ -z "$ACTIVE_RULES" ] && ACTIVE_RULES=0

    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         ${BOLD}TRANS3 SMART IP ENCRYPTOR V3.1 ${NC}${CYAN}          ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Protected Interface  : ${BOLD}$SELECTED_IF${NC} "
    echo -e "${CYAN}║${NC}  Kernel Engine        : $MOD_STATUS"
    echo -e "${CYAN}║${NC}  Active Target IPs    : ${YELLOW}${BOLD}$ACTIVE_RULES${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}ENCRYPTION MATRIX (POSTROUTING/PREROUTING):${NC}"

    if [ "$ACTIVE_RULES" -eq 0 ]; then
        echo -e "${CYAN}║${NC}  ${YELLOW}> Standard traffic (No encryption rules)${NC}"
    else
        iptables-legacy -t mangle -S POSTROUTING 2>/dev/null | grep "TRANS3 --mode e" | grep -oP -- '-d \K[0-9\.]+' | sort -u | while read -r ip; do
            if [ -n "$ip" ]; then
                echo -e "${CYAN}║${NC}  ${RED}[🔒] Encrypting (Out) ->${NC} ${BOLD}$ip${NC} (Mode e)"
                echo -e "${CYAN}║${NC}  ${GREEN}[🔓] Decrypting (In)  <-${NC} ${BOLD}$ip${NC} (Mode d)"
                echo -e "${CYAN}║${NC}"
            fi
        done
    fi

    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}1.${NC} Initialize kernel engine"
    echo -e "${CYAN}║${NC}  ${BOLD}2.${NC} Security Key Management"
    echo -e "${CYAN}║${NC}  ${BOLD}3.${NC} ${GREEN}Add an encryption rule (Target IP)${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}4.${NC} ${YELLOW}Real-time Encryption Telemetry${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}5.${NC} ${MAGENTA}Lock system configuration (ROM write)${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}6.${NC} ${RED}Purge matrix (Clear Text Mode)${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}7.${NC} Exit"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
}

# ------------------------------------------------------------------------------
# Initialisation réseau (appelée une fois au démarrage, mais peut être relancée)
# ------------------------------------------------------------------------------
init_network

# ------------------------------------------------------------------------------
# Boucle principale du menu
# ------------------------------------------------------------------------------
while true; do
    print_menu
    echo -ne "\n ${BOLD}Command (1-7):${NC} "
    read -r OPTION
    echo ""

    case $OPTION in
        1)
            echo -e "${YELLOW}[*] Re-initializing kernel engine...${NC}"
            init_network
            if lsmod | grep -q "xt_TRANS3"; then
                echo -e "${GREEN}[+] Engine restarted successfully."
            else
                echo -e "${RED}[-] Critical subsystem failure.${NC}"
            fi
            pause
            ;;
        2)
            echo -e "${CYAN}┌──────────────────────────────────────────┐${NC}"
            echo -e "${CYAN}│               KEY SECURITY               │${NC}"
            echo -e "${CYAN}└──────────────────────────────────────────┘${NC}"
            echo "  a) Check local signature status"
            echo "  b) Import external token (Air-Gap USB)"
            echo ""
            read -p "  Choice: " key_choice

            if [[ "$key_choice" == "a" ]]; then
                echo ""
                showkey3 || echo -e "${RED}[-] No valid signature found in /etc/.file/file3.${NC}"
            elif [[ "$key_choice" == "b" ]]; then
                echo -e "\n${YELLOW}[*] Scanning removable media...${NC}"
                USB_FILE=$(find /media /mnt /tmp -maxdepth 4 -name "my_raw_key.bin" -type f 2>/dev/null | head -n 1)

                if [[ -n "$USB_FILE" ]]; then
                    echo -e "${GREEN}[+] Hardware signature detected: $USB_FILE${NC}"
                    loadkey3 "$USB_FILE" >/dev/null 2>&1 && echo -e "${GREEN}[+] Import and memory lockdown successful.${NC}" || echo -e "${RED}[-] Synchronization failed.${NC}"
                else
                    echo -e "${RED}[-] No 'my_raw_key.bin' token detected.${NC}"
                fi
            else
                echo -e "${RED}[-] Unrecognized command.${NC}"
            fi
            pause
            ;;
        3)
            echo -e "${CYAN}┌──────────────────────────────────────────┐${NC}"
            echo -e "${CYAN}│         ADD L3 ENCRYPTION RULE           │${NC}"
            echo -e "${CYAN}└──────────────────────────────────────────┘${NC}"
            read -p "  Target IP to encrypt: " PEER_IP

            if [[ -n "$PEER_IP" ]]; then
                for proto in tcp udp icmp igmp gre; do
                    # Chiffrement sortant
                    iptables-legacy -t mangle -A POSTROUTING -d "$PEER_IP" -p $proto -j TRANS3 --mode e >/dev/null 2>&1
                    # Déchiffrement entrant
                    iptables-legacy -t mangle -A PREROUTING -s "$PEER_IP" -p $proto -j TRANS3 --mode d >/dev/null 2>&1
                done
                echo -e "${GREEN}[+] Rules added. Traffic to/from ${BOLD}$PEER_IP${NC}${GREEN} is now encrypted (Layer 3).${NC}"
            else
                echo -e "${RED}[-] Operation aborted. No IP provided.${NC}"
            fi
            pause
            ;;
        4)
            echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
            echo -e "${CYAN}║              ENCRYPTION TELEMETRY                    ║${NC}"
            echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
            OUTPUT_RULES=$(iptables-legacy -t mangle -L POSTROUTING -v -n | grep "TRANS3") || true
            if [ -z "$OUTPUT_RULES" ]; then
                echo -e "${YELLOW}  > Engine is idle. No traffic encrypted yet.${NC}"
            else
                echo -e "\n${BOLD}${YELLOW}[ OUTBOUND FLOWS (ENCRYPTING --mode e) ]${NC}"
                iptables-legacy -t mangle -L POSTROUTING -v -n | grep "TRANS3" | while read -r pkts bytes target prot opt in_if out_if src dst rest; do
                    if [ "$pkts" -gt 0 ]; then
                        echo -e "  ${RED}[TX]${NC} To: ${BOLD}$dst${NC} | Proto: $prot | Encrypted: ${CYAN}$pkts pkts${NC} ($bytes)"
                    fi
                done

                echo -e "\n${BOLD}${YELLOW}[ INBOUND FLOWS (DECRYPTING --mode d) ]${NC}"
                iptables-legacy -t mangle -L PREROUTING -v -n | grep "TRANS3" | while read -r pkts bytes target prot opt in_if out_if src dst rest; do
                    if [ "$pkts" -gt 0 ]; then
                        echo -e "  ${GREEN}[RX]${NC} From: ${BOLD}$src${NC} | Proto: $prot | Decrypted: ${CYAN}$pkts pkts${NC} ($bytes)"
                    fi
                done
            fi
            pause
            ;;
        5)
            echo -e "${YELLOW}[*] Writing to system ROM...${NC}"
            mkdir -p /etc/iptables >/dev/null 2>&1
            iptables-save > /etc/iptables/rules.v4 2>/dev/null && echo -e "${GREEN}[+] Encryption rules permanently sealed.${NC}" || echo -e "${RED}[-] Memory write failed.${NC}"
            pause
            ;;
        6)
            echo -e "${RED}[*] Purging encryption rules...${NC}"
            teardown
            echo -e "${GREEN}[+] Network interface restored to Clear Text Mode (MTU 1500).${NC}"
            pause
            ;;
        7)
            echo -e "\n${YELLOW}[?] Shutdown sequence:${NC}"
            read -p "  Keep encryption active in background? (Y/n): " quit_choice
            if [[ "$quit_choice" =~ ^[nN]$ ]]; then
                teardown
                echo -e "${RED}  > Encryption rules purged.${NC}"
            else
                echo -e "${GREEN}  > Encryption active in background.${NC}"
            fi
            echo -e "${CYAN}  Terminal disconnected.${NC}\n"
            exit 0
            ;;
        *)
            echo -e "${RED}[-] Invalid instruction code.${NC}"
            sleep 1
            ;;
    esac
done
