#!/usr/bin/env bash
# =============================================================================
# setup_bridge_sim.sh — Simulation 100% Réaliste (Hôtes inaccessibles)
#
# Topology:
#  [ns_host_a]──veth-a0──[ns_bridge1]──veth-b1──[ns_bridge2]──veth-c1──[ns_host_b]
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "\n${CYAN}[*]${NC} ${BOLD}$*${NC}"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

IPT="iptables"; command -v iptables-legacy &>/dev/null && IPT="iptables-legacy"

NS_A="ns_host_a"; NS_B1="ns_bridge1"; NS_B2="ns_bridge2"; NS_B="ns_host_b"
IP_A="10.0.0.1"; IP_B="10.0.0.2"; PREFIX="/24"

VETH_A0="veth-a0"; VETH_A1="veth-a1"
VETH_B0="veth-b0"; VETH_B1="veth-b1"
VETH_C0="veth-c0"; VETH_C1="veth-c1"
BR1="br1"; BR2="br2"

disable_offloads() {
    local NS=$1; local IF=$2
    ip netns exec "$NS" ethtool -K "$IF" \
        tx off gso off tso off gro off lro off ufo off \
        tx-checksum-ip-generic off 2>/dev/null || true
    for feat in gro rx-gro-hw rx-gro-list rx-udp-gro-forwarding; do
        ip netns exec "$NS" ethtool -K "$IF" $feat off 2>/dev/null || true
    done
}

enable_rps() {
    local NS=$1; local IF=$2
    ip netns exec "$NS" bash -c "for f in /sys/class/net/$IF/queues/rx-*/rps_cpus; do echo 'f' > \$f 2>/dev/null || true; done"
    ip netns exec "$NS" bash -c "for f in /sys/class/net/$IF/queues/rx-*/rps_flow_cnt; do echo '32768' > \$f 2>/dev/null || true; done"
}

set_queuelen() {
    local NS=$1; local IF=$2
    ip netns exec "$NS" ip link set "$IF" txqueuelen 10000 2>/dev/null || true
}

print_help() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                     TOPOLOGIE DU LABORATOIRE TRANS3                          ${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}\n"
    
    echo -e " ${GREEN}[ HOST A (Client) ]${NC}                                              ${GREEN}[ HOST B (Serveur) ]${NC}"
    echo -e "   IP: $IP_A                                                     IP: $IP_B"
    echo -e "   MTU: 1500 (Standard)                                             MTU: 1500 (Standard)"
    echo -e "       │                                                                │"
    echo -e "   ($VETH_A0)                                                        ($VETH_C1)"
    echo -e "       │                                                                │"
    echo -e "   ($VETH_A1)                                                        ($VETH_C0)"
    echo -e " ${YELLOW}┌─────┴─────┐${NC}                                                    ${YELLOW}┌─────┴─────┐${NC}"
    echo -e " ${YELLOW}│ BRIDGE 1  │${NC}             ${MAGENTA}[ CÂBLE WAN / INTERNET ]${NC}               ${YELLOW}│ BRIDGE 2  │${NC}"
    echo -e " ${YELLOW}│(Chiffreur)├─${NC}($VETH_B0)──${MAGENTA}< TRAFIC 100% CHIFFRÉ >${NC}──($VETH_B1)─${YELLOW}┤(Déchiffreur)│${NC}"
    echo -e " ${YELLOW}│ MTU: 1550 │${NC}              MTU: 1550 (Baby Jumbo Frames)               ${YELLOW}│ MTU: 1550 │${NC}"
    echo -e " ${YELLOW}└───────────┘${NC}                                                    ${YELLOW}└───────────┘${NC}\n"

    echo -e "${BOLD}🛠️  COMMANDES UTILES POUR TESTER L'ARCHITECTURE :${NC}\n"
    
    echo -e "  ${BOLD}1. Tester le Ping (de A vers B) :${NC}"
    echo -e "     sudo ip netns exec $NS_A ping $IP_B\n"

    echo -e "  ${BOLD}2. Lancer le Serveur de test (sur l'Hôte B) :${NC}"
    echo -e "     sudo ip netns exec $NS_B iperf3 -s -p 7777\n"

    echo -e "  ${BOLD}3. Lancer le Client de test (Depuis l'Hôte A) :${NC}"
    echo -e "     sudo ip netns exec $NS_A iperf3 -c $IP_B -p 7777 -P 4\n"

    echo -e "  ${BOLD}4. 🕵️  Écouter le trafic chiffré comme un Hacker (Sur le WAN) :${NC}"
    echo -e "     sudo ip netns exec $NS_B1 tcpdump -i $VETH_B0 -n -XX tcp port 7777\n"

    echo -e "  ${BOLD}5. 🧹 Détruire la simulation :${NC}"
    echo -e "     sudo $0 --clean\n"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}\n"
}

teardown() {
    [[ $EUID -ne 0 ]] && err "Root required: sudo $0 --clean"
    info "Cleaning up simulation environment"
    for ns in "$NS_A" "$NS_B1" "$NS_B2" "$NS_B"; do ip netns del "$ns" 2>/dev/null || true; done
    for v in "$VETH_A0" "$VETH_B0" "$VETH_C0"; do ip link del "$v" 2>/dev/null || true; done
    log "Environment destroyed"
}

setup() {
    [[ $EUID -ne 0 ]] && err "Root required: sudo $0"
    
    info "Loading kernel modules"
    modprobe nf_conntrack    2>/dev/null || true
    modprobe nf_defrag_ipv4  2>/dev/null || true
    modprobe br_netfilter    2>/dev/null || warn "br_netfilter not available"
    modprobe xt_TRANS3 2>/dev/null || warn "xt_TRANS3 not loaded"

    info "Creating network namespaces"
    for ns in "$NS_A" "$NS_B1" "$NS_B2" "$NS_B"; do ip netns add "$ns"; done

    info "Creating virtual Ethernet cables (Multi-Queue enabled)"
    ip link add "$VETH_A0" numtxqueues 4 numrxqueues 4 type veth peer name "$VETH_A1" numtxqueues 4 numrxqueues 4
    ip link set "$VETH_A0" netns "$NS_A"; ip link set "$VETH_A1" netns "$NS_B1"

    ip link add "$VETH_B0" numtxqueues 4 numrxqueues 4 type veth peer name "$VETH_B1" numtxqueues 4 numrxqueues 4
    ip link set "$VETH_B0" netns "$NS_B1"; ip link set "$VETH_B1" netns "$NS_B2"

    ip link add "$VETH_C0" numtxqueues 4 numrxqueues 4 type veth peer name "$VETH_C1" numtxqueues 4 numrxqueues 4
    ip link set "$VETH_C0" netns "$NS_B2"; ip link set "$VETH_C1" netns "$NS_B"

    # =========================================================================
    # ── ZONE UTILISATEURS (Standard) ──
    # =========================================================================
    info "Configuring HOST_A ($IP_A) — MTU 1500"
    ip netns exec "$NS_A" ip addr add "${IP_A}${PREFIX}" dev "$VETH_A0"
    ip netns exec "$NS_A" ip link set "$VETH_A0" mtu 1500
    ip netns exec "$NS_A" ip link set "$VETH_A0" up
    ip netns exec "$NS_A" ip link set lo up
    set_queuelen "$NS_A" "$VETH_A0"; disable_offloads "$NS_A" "$VETH_A0"; enable_rps "$NS_A" "$VETH_A0"

    info "Configuring HOST_B ($IP_B) — MTU 1500"
    ip netns exec "$NS_B" ip addr add "${IP_B}${PREFIX}" dev "$VETH_C1"
    ip netns exec "$NS_B" ip link set "$VETH_C1" mtu 1500
    ip netns exec "$NS_B" ip link set "$VETH_C1" up
    ip netns exec "$NS_B" ip link set lo up
    set_queuelen "$NS_B" "$VETH_C1"; disable_offloads "$NS_B" "$VETH_C1"; enable_rps "$NS_B" "$VETH_C1"

    # =========================================================================
    # ── ZONE ROUTEURS CRYPTOGRAPHIQUES (Baby Jumbo Frames) ──
    # =========================================================================
    info "Configuring BRIDGE1 (Encryptor) — MTU 1550"
    ip netns exec "$NS_B1" ip link set "$VETH_A1" up
    ip netns exec "$NS_B1" ip link set "$VETH_B0" up; ip netns exec "$NS_B1" ip link set lo up
    ip netns exec "$NS_B1" ip link add "$BR1" type bridge
    ip netns exec "$NS_B1" ip link set "$VETH_A1" master "$BR1"
    ip netns exec "$NS_B1" ip link set "$VETH_B0" master "$BR1"
    ip netns exec "$NS_B1" ip link set "$BR1" up

    for IF in "$VETH_A1" "$VETH_B0" "$BR1"; do
        ip netns exec "$NS_B1" ip link set "$IF" mtu 1550
        set_queuelen "$NS_B1" "$IF"; disable_offloads "$NS_B1" "$IF"; enable_rps "$NS_B1" "$IF"
    done

    ip netns exec "$NS_B1" sysctl -w net.bridge.bridge-nf-call-iptables=1  >/dev/null 2>&1 || true
    ip netns exec "$NS_B1" sysctl -w net.core.gro_normal_batch_size=1      >/dev/null 2>&1 || true

    ip netns exec "$NS_B1" $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428
    ip netns exec "$NS_B1" $IPT -t mangle -A FORWARD -m physdev --physdev-out "$VETH_B0" -j TRANS3 --mode e
    ip netns exec "$NS_B1" $IPT -t mangle -A FORWARD -m physdev --physdev-in  "$VETH_B0" -j TRANS3 --mode d

    info "Configuring BRIDGE2 (Decryptor) — MTU 1550"
    ip netns exec "$NS_B2" ip link set "$VETH_B1" up
    ip netns exec "$NS_B2" ip link set "$VETH_C0" up; ip netns exec "$NS_B2" ip link set lo up
    ip netns exec "$NS_B2" ip link add "$BR2" type bridge
    ip netns exec "$NS_B2" ip link set "$VETH_B1" master "$BR2"
    ip netns exec "$NS_B2" ip link set "$VETH_C0" master "$BR2"
    ip netns exec "$NS_B2" ip link set "$BR2" up

    for IF in "$VETH_B1" "$VETH_C0" "$BR2"; do
        ip netns exec "$NS_B2" ip link set "$IF" mtu 1550
        set_queuelen "$NS_B2" "$IF"; disable_offloads "$NS_B2" "$IF"; enable_rps "$NS_B2" "$IF"
    done

    ip netns exec "$NS_B2" sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null 2>&1 || true
    ip netns exec "$NS_B2" sysctl -w net.core.gro_normal_batch_size=1     >/dev/null 2>&1 || true

    ip netns exec "$NS_B2" $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428
    ip netns exec "$NS_B2" $IPT -t mangle -A FORWARD -m physdev --physdev-in  "$VETH_B1" -j TRANS3 --mode d
    ip netns exec "$NS_B2" $IPT -t mangle -A FORWARD -m physdev --physdev-out "$VETH_B1" -j TRANS3 --mode e

    # ── TCP Buffers & Congestion Control ──
    for NS in "$NS_A" "$NS_B"; do
        ip netns exec "$NS" sysctl -w net.core.rmem_max=134217728      >/dev/null 2>&1 || true
        ip netns exec "$NS" sysctl -w net.core.wmem_max=134217728      >/dev/null 2>&1 || true
        ip netns exec "$NS" sysctl -w net.ipv4.tcp_rmem="4096 87380 67108864" >/dev/null 2>&1 || true
        ip netns exec "$NS" sysctl -w net.ipv4.tcp_wmem="4096 65536 67108864" >/dev/null 2>&1 || true
        ip netns exec "$NS" sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
    done

    print_help
}

case "${1:-setup}" in
    --clean|-c) teardown ;;
    --help|-h)  print_help ;;
    setup|*)    teardown 2>/dev/null || true; setup ;;
esac
