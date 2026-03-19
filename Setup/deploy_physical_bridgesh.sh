#!/usr/bin/env bash
# =============================================================================
# deploy_physical_bridge.sh — Déploiement "Bump-in-the-wire" avec xt_TRANS3
#
# Ce script configure la machine physique comme un pont invisible L2.
# Aucun service persistant n'est installé. Configuration perdue au reboot.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "\n${CYAN}[*]${NC} ${BOLD}$*${NC}"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

[[ $EUID -ne 0 ]] && { echo -e "${RED}[-] Root required: sudo $0${NC}"; exit 1; }

# =============================================================================
# 🛠️ CONFIGURATION UTILISATEUR (À MODIFIER SELON VOTRE MATÉRIEL)
# =============================================================================
LAN_IF="eth_lan"             # Remplacer par le vrai nom (ex: enp3s0)
WAN_IF="eth_wan"             # Remplacer par le vrai nom (ex: enp4s0)
TARGET_IP="203.0.113.50"     # L'adresse IP du serveur lointain à chiffrer

BRIDGE_IF="br0"

# (Optionnel) Si vous administrez ce serveur en SSH depuis le LAN, décommentez
# et renseignez l'IP pour que le script la transfère sur le bridge.
# MANAGEMENT_IP="192.168.1.254/24"
# MANAGEMENT_GW="192.168.1.1"

# =============================================================================

IPT="iptables"
command -v iptables-legacy &>/dev/null && IPT="iptables-legacy"

disable_offloads() {
    local IF=$1
    log "Désactivation des offloads matériels sur $IF"
    ethtool -K "$IF" tx off gso off tso off gro off lro off ufo off rx-gro-hw off \
                     tx-checksum-ip-generic off 2>/dev/null || true
}

cleanup() {
    info "Nettoyage de l'ancienne configuration..."
    $IPT -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428 2>/dev/null || true
    $IPT -t mangle -D FORWARD -m physdev --physdev-out "$WAN_IF" -d "$TARGET_IP" -j TRANS3 --mode e 2>/dev/null || true
    $IPT -t mangle -D FORWARD -m physdev --physdev-in  "$WAN_IF" -s "$TARGET_IP" -j TRANS3 --mode d 2>/dev/null || true
    
    if ip link show "$BRIDGE_IF" &>/dev/null; then
        ip link set "$LAN_IF" nomaster 2>/dev/null || true
        ip link set "$WAN_IF" nomaster 2>/dev/null || true
        ip link delete "$BRIDGE_IF" type bridge 2>/dev/null || true
    fi
}

setup() {
    info "Chargement des modules noyau"
    modprobe br_netfilter || warn "br_netfilter non disponible"
    modprobe xt_TRANS3 || { echo -e "${RED}[-] xt_TRANS3 n'est pas installé sur ce serveur !${NC}"; exit 1; }

    sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
    sysctl -w net.bridge.bridge-nf-call-ip6tables=1 >/dev/null

    info "Configuration des interfaces physiques"
    ip link set "$LAN_IF" up
    ip link set "$WAN_IF" up
    
    disable_offloads "$LAN_IF"
    disable_offloads "$WAN_IF"

    info "Création du Bridge Transparent ($BRIDGE_IF)"
    ip link add "$BRIDGE_IF" type bridge
    ip link set "$LAN_IF" master "$BRIDGE_IF"
    ip link set "$WAN_IF" master "$BRIDGE_IF"

    info "Application de la stratégie MTU (TRANS3 +32B Overhead)"
    ip link set "$LAN_IF" mtu 1468    # Force le LAN à envoyer de plus petits paquets
    ip link set "$WAN_IF" mtu 1500    # Le WAN reste standard pour absorber le chiffrement
    ip link set "$BRIDGE_IF" up
    ip link set "$BRIDGE_IF" mtu 1500

    # Option de Management (Évite la coupure SSH)
    if [[ -n "${MANAGEMENT_IP:-}" ]]; then
        info "Transfert de l'IP de Management sur le Bridge"
        ip addr flush dev "$LAN_IF" 2>/dev/null || true
        ip addr add "$MANAGEMENT_IP" dev "$BRIDGE_IF"
        [[ -n "${MANAGEMENT_GW:-}" ]] && ip route add default via "$MANAGEMENT_GW" 2>/dev/null || true
    fi

    info "Configuration Iptables (Mangle)"
    log "1. TCP MSS Clamping (1428 octets)"
    $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428

    log "2. Règle de Chiffrement (LAN -> WAN vers $TARGET_IP)"
    $IPT -t mangle -A FORWARD -m physdev --physdev-out "$WAN_IF" -d "$TARGET_IP" -j TRANS3 --mode e

    log "3. Règle de Déchiffrement (WAN -> LAN depuis $TARGET_IP)"
    $IPT -t mangle -A FORWARD -m physdev --physdev-in  "$WAN_IF" -s "$TARGET_IP" -j TRANS3 --mode d

    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Routeur Physique TRANS3 Activé !${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  Mode      : Transparent / Bridge L2"
    echo -e "  LAN Port  : $LAN_IF (MTU 1468)"
    echo -e "  WAN Port  : $WAN_IF (MTU 1500)"
    echo -e "  Cible IP  : $TARGET_IP"
    echo -e "  État      : Le trafic vers la cible est chiffré à la volée."
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
}

cleanup
case "${1:-setup}" in
    --clean|-c) log "Nettoyage terminé. Le bridge a été retiré." ;;
    setup|*)    setup ;;
esac
