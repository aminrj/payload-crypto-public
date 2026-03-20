#!/usr/bin/env bash
# =============================================================================
# deploy_physical_bridge.sh — Bump-in-the-wire deployment with xt_TRANS3
#
# Configures this machine as an invisible L2 transparent bridge.
# No persistent services are installed. Configuration is lost on reboot.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "\n${CYAN}[*]${NC} ${BOLD}$*${NC}"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

[[ $EUID -ne 0 ]] && { echo -e "${RED}[-] Root required: sudo $0${NC}"; exit 1; }

# =============================================================================
# USER CONFIGURATION (edit to match your hardware)
# =============================================================================
LAN_IF="eth_lan"             # Replace with actual interface name (e.g. enp3s0)
WAN_IF="eth_wan"             # Replace with actual interface name (e.g. enp4s0)
TARGET_IP="203.0.113.50"     # Remote IP address to encrypt traffic toward

BRIDGE_IF="br0"

# (Optional) If you manage this host via SSH from the LAN, uncomment and set
# the IP to transfer it onto the bridge interface to avoid losing connectivity.
# MANAGEMENT_IP="192.168.1.254/24"
# MANAGEMENT_GW="192.168.1.1"

# =============================================================================

IPT="iptables"
command -v iptables-legacy &>/dev/null && IPT="iptables-legacy"

disable_offloads() {
    local IF=$1
    log "Disabling hardware offloads on $IF"
    ethtool -K "$IF" tx off gso off tso off gro off lro off ufo off rx-gro-hw off \
                     tx-checksum-ip-generic off 2>/dev/null || true
}

cleanup() {
    info "Removing previous configuration"
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
    info "Loading kernel modules"
    modprobe br_netfilter || warn "br_netfilter not available"
    modprobe xt_TRANS3 || { echo -e "${RED}[-] xt_TRANS3 is not installed on this host!${NC}"; exit 1; }

    sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
    sysctl -w net.bridge.bridge-nf-call-ip6tables=1 >/dev/null

    info "Configuring physical interfaces"
    ip link set "$LAN_IF" up
    ip link set "$WAN_IF" up

    disable_offloads "$LAN_IF"
    disable_offloads "$WAN_IF"

    info "Creating transparent bridge ($BRIDGE_IF)"
    ip link add "$BRIDGE_IF" type bridge
    ip link set "$LAN_IF" master "$BRIDGE_IF"
    ip link set "$WAN_IF" master "$BRIDGE_IF"

    info "Applying MTU policy (TRANS3 +32-byte overhead)"
    ip link set "$LAN_IF" mtu 1468    # LAN: reduced to leave room for encryption overhead
    ip link set "$WAN_IF" mtu 1500    # WAN: standard 1500 absorbs the encrypted packet
    ip link set "$BRIDGE_IF" up
    ip link set "$BRIDGE_IF" mtu 1500

    # Management IP option (prevents SSH disconnection)
    if [[ -n "${MANAGEMENT_IP:-}" ]]; then
        info "Transferring management IP to bridge interface"
        ip addr flush dev "$LAN_IF" 2>/dev/null || true
        ip addr add "$MANAGEMENT_IP" dev "$BRIDGE_IF"
        [[ -n "${MANAGEMENT_GW:-}" ]] && ip route add default via "$MANAGEMENT_GW" 2>/dev/null || true
    fi

    info "Configuring iptables mangle rules"
    log "1. TCP MSS clamping (1428 bytes)"
    $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428

    log "2. Encryption rule (LAN -> WAN toward $TARGET_IP)"
    $IPT -t mangle -A FORWARD -m physdev --physdev-out "$WAN_IF" -d "$TARGET_IP" -j TRANS3 --mode e

    log "3. Decryption rule (WAN -> LAN from $TARGET_IP)"
    $IPT -t mangle -A FORWARD -m physdev --physdev-in  "$WAN_IF" -s "$TARGET_IP" -j TRANS3 --mode d

    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  TRANS3 Physical Bridge Active!${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  Mode      : Transparent / L2 Bridge"
    echo -e "  LAN Port  : $LAN_IF (MTU 1468)"
    echo -e "  WAN Port  : $WAN_IF (MTU 1500)"
    echo -e "  Target IP : $TARGET_IP"
    echo -e "  Status    : Traffic toward target is encrypted on-the-fly."
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
}

cleanup
case "${1:-setup}" in
    --clean|-c) log "Cleanup complete. Bridge removed." ;;
    setup|*)    setup ;;
esac
