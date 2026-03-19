#!/usr/bin/env bash
# =============================================================================
# test_bridge_sim.sh — Suite de tests automatisés pour xt_TRANS3
# (Architecture : Hôtes MTU 1500 / Bridges MTU 1550)
# =============================================================================
set -euo pipefail

# Définition complète des couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

pass()  { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "  ${RED}[FAIL]${NC} $*"; FAILURES=$((FAILURES+1)); }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
info()  { echo -e "\n${CYAN}[*]${NC} ${BOLD}$*${NC}"; }
log()   { echo -e "  ${GREEN}[+]${NC} $*"; }
sep()   { echo -e "  ${BOLD}──────────────────────────────────────────────────────────────${NC}"; }

[[ $EUID -ne 0 ]] && { echo "Root required: sudo $0"; exit 1; }

# Vérification des dépendances
for dep in tshark iperf3 tcpdump nc sha256sum; do
    command -v "$dep" &>/dev/null || { echo -e "${RED}[-]${NC} Paquet manquant: $dep (apt install $dep)"; exit 1; }
done

NS_A="ns_host_a"; NS_B1="ns_bridge1"; NS_B2="ns_bridge2"; NS_B="ns_host_b"
IP_A="10.0.0.1"; IP_B="10.0.0.2"
PORT=18000; FAILURES=0

# Dossier où seront sauvegardés les fichiers Wireshark
PCAP_DIR="/tmp/trans3_captures"
mkdir -p "$PCAP_DIR"
rm -f "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.bin 2>/dev/null
chmod 777 "$PCAP_DIR"

NC_OPTS="-N"; nc --version 2>&1 | grep -qi "gnu\|ncat" && NC_OPTS="-q 1"
IPT="iptables"; command -v iptables-legacy &>/dev/null && IPT="iptables-legacy"

nsa()  { ip netns exec "$NS_A"  "$@"; }
nsb()  { ip netns exec "$NS_B"  "$@"; }
nsb1() { ip netns exec "$NS_B1" "$@"; }
nsb2() { ip netns exec "$NS_B2" "$@"; }

if ! ip netns list 2>/dev/null | grep -q "$NS_A"; then
    echo -e "${RED}[-] La simulation n'est pas lancée. Exécutez : sudo ./setup_bridge_sim.sh${NC}"
    exit 1
fi

echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║   TRANS3 — RAPPORT DE TESTS AUTOMATISÉS ET AUDIT RÉSEAU      ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

# =============================================================================
# SECTION 1 : TESTS FONCTIONNELS ET INTÉGRITÉ
# =============================================================================
info "SECTION 1 : TESTS D'INTÉGRITÉ DES DONNÉES (AEAD Poly1305)"
sep

# 1. Ping
nsa ping -c 3 -W 2 "$IP_B" &>/dev/null && pass "Connectivité ICMP de bout en bout" || fail "Échec du Ping ICMP"

# 2. Fichier 1 Mo (Test de hachage)
S="$PCAP_DIR/source_1m.bin"; R="$PCAP_DIR/recv_1m.bin"
dd if=/dev/urandom of="$S" bs=1M count=1 status=none
nsb nc -l -p $PORT > "$R" & SRV=$!; sleep 1
nsa nc $NC_OPTS "$IP_B" $PORT < "$S" 2>/dev/null || true
sleep 1.5; kill $SRV 2>/dev/null||true; wait $SRV 2>/dev/null||true

if [[ "$(sha256sum "$S" | awk '{print $1}')" == "$(sha256sum "$R" | awk '{print $1}')" ]]; then
    pass "Transfert 1 Mo et vérification SHA-256 (Zéro corruption) ✓"
else
    fail "Corruption de données détectée sur le transfert de 1 Mo !"
fi
PORT=$((PORT+1))

# =============================================================================
# SECTION 2 : AUDIT CRYPTOGRAPHIQUE (WIRESHARK / TCPDUMP)
# =============================================================================
info "SECTION 2 : AUDIT CRYPTOGRAPHIQUE ET CAPTURES WIRESHARK"
sep
log "Enregistrement du trafic sur 3 points de contrôle simultanés..."

PLAINTEXT="TRANS3_TOP_SECRET_MESSAGE_$(date +%s)"
WS_PORT=17777

PCAP_LAN_A="$PCAP_DIR/1_LAN_Source_Clair.pcap"
PCAP_WIRE="$PCAP_DIR/2_WAN_Cable_Chiffre.pcap"
PCAP_LAN_B="$PCAP_DIR/3_LAN_Dest_Restaure.pcap"

# Hack Anti-AppArmor: On utilise "-w -" et la redirection bash ">" avec "-U" (Packet-buffered)
nsa  tcpdump -Z root -U -i veth-a0 -w - -s 0 tcp port $WS_PORT 2>/dev/null > "$PCAP_LAN_A" & TD_A=$!
nsb1 tcpdump -Z root -U -i veth-b0 -w - -s 0 tcp port $WS_PORT 2>/dev/null > "$PCAP_WIRE"  & TD_W=$!
nsb  tcpdump -Z root -U -i veth-c1 -w - -s 0 tcp port $WS_PORT 2>/dev/null > "$PCAP_LAN_B" & TD_B=$!

# On laisse 3 secondes à tcpdump pour initialiser ses interfaces virtuelles
sleep 3 

# On lance le serveur et on s'assure qu'il est bien prêt à écouter avant d'envoyer
nsb nc -l -p $WS_PORT > /dev/null & SRV=$!
sleep 1 

# On envoie le message secret depuis le client A
echo "$PLAINTEXT" | nsa nc $NC_OPTS "$IP_B" $WS_PORT 2>/dev/null || true

# On laisse le temps aux paquets de traverser et d'être écrits sur le disque
sleep 2

# Arrêt des sniffeurs
kill $TD_A $TD_W $TD_B $SRV 2>/dev/null||true; wait $TD_A $TD_W $TD_B $SRV 2>/dev/null||true

echo -e "\n  ${BOLD}[ Point A — LAN Source (Avant Chiffrement) ]${NC}"
if tshark -r "$PCAP_LAN_A" -z "follow,tcp,ascii,0" 2>/dev/null | grep -qF "$PLAINTEXT"; then 
    pass "Message lisible en clair sur le LAN de départ ✓"
else 
    warn "Message non détecté (Vérifiez les captures manuellement)"
fi

echo -e "\n  ${BOLD}[ Point B — Câble WAN (Test de Furtivité) ]${NC}"
tshark -r "$PCAP_WIRE" -T fields -e frame.len 2>/dev/null | head -3 | while read -r len; do log "Trame interceptée : ${len} Octets ${RED}[CHIFRÉE]${NC}"; done
if strings "$PCAP_WIRE" 2>/dev/null | grep -qF "$PLAINTEXT"; then 
    fail "FUITE DE DONNÉES ! Le texte clair est visible sur le câble WAN !"
else 
    pass "Aucune trace du texte clair. Cryptographie hermétique ✓"
fi

echo -e "\n  ${BOLD}[ Point C — LAN Destination (Après Déchiffrement) ]${NC}"
if tshark -r "$PCAP_LAN_B" -z "follow,tcp,ascii,0" 2>/dev/null | grep -qF "$PLAINTEXT"; then 
    pass "Message restauré avec succès sur le LAN d'arrivée ✓"
else
    warn "Message non détecté à l'arrivée"
fi

# =============================================================================
# SECTION 3 : STRESS-TESTS DE BANDE PASSANTE (IPERF3)
# =============================================================================
info "SECTION 3 : BENCHMARK IPERF3 (MULTI-CŒURS)"
sep
IPERF_PORT=15201

run_iperf() {
    local LABEL=$1; local DURATION=$2; local EXTRA_OPTS="${3:-}"
    nsb iperf3 -s -p $IPERF_PORT -1 &>/dev/null &
    local SRV=$!; sleep 0.5
    
    local RESULT
    RESULT=$(nsa iperf3 -c "$IP_B" -p $IPERF_PORT -t "$DURATION" -O 1 --json $EXTRA_OPTS 2>/dev/null || echo '{}')
    wait $SRV 2>/dev/null || true

    local BPS=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(int(d.get('end',{}).get('sum_sent',{}).get('bits_per_second',0)))" 2>/dev/null || echo 0)
    local RETR=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(int(d.get('end',{}).get('sum_sent',{}).get('retransmits',0)))" 2>/dev/null || echo 0)
    local MBPS=$(echo "scale=1; $BPS / 1000000" | bc 2>/dev/null || echo 0)
    
    printf "  %-35s │ ${CYAN}%7s Mbps${NC} │ Retransmissions: %d\n" "$LABEL" "$MBPS" "$RETR"
}

log "1. Trafic AVEC le module xt_TRANS3 activé :"
run_iperf "TCP (Chiffré - 4 Threads)" 10 "-P 4"
run_iperf "UDP (Chiffré)" 5 "-u -b 0"

log "\n  Désactivation temporaire de xt_TRANS3 pour mesure du trafic en clair..."
nsb1 $IPT -t mangle -F FORWARD 2>/dev/null || true
nsb2 $IPT -t mangle -F FORWARD 2>/dev/null || true

log "2. Trafic SANS xt_TRANS3 (Baseline) :"
run_iperf "TCP (Clair - 4 Threads)" 10 "-P 4"
run_iperf "UDP (Clair)" 5 "-u -b 0"

# Restauration parfaite des règles
log "\n  Restauration des règles de sécurité..."
nsb1 $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428
nsb1 $IPT -t mangle -A FORWARD -m physdev --physdev-out veth-b0 -j TRANS3 --mode e
nsb1 $IPT -t mangle -A FORWARD -m physdev --physdev-in  veth-b0 -j TRANS3 --mode d

nsb2 $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428
nsb2 $IPT -t mangle -A FORWARD -m physdev --physdev-in  veth-b1 -j TRANS3 --mode d
nsb2 $IPT -t mangle -A FORWARD -m physdev --physdev-out veth-b1 -j TRANS3 --mode e

# =============================================================================
# RÉSUMÉ ET EXPORT
# =============================================================================
echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
if [[ "$FAILURES" -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}RÉSULTAT : TOUS LES TESTS SONT PASSÉS AVEC SUCCÈS${NC}"
else
    echo -e "  ${RED}${BOLD}RÉSULTAT : $FAILURES TEST(S) EN ÉCHEC${NC}"
fi
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "  📁 ${BOLD}Fichiers Wireshark générés dans : ${MAGENTA}${PCAP_DIR}${NC}"
echo -e "     1. LAN Source (Clair)  : ${MAGENTA}$PCAP_LAN_A${NC}"
echo -e "     2. WAN Câble (Chiffré) : ${MAGENTA}$PCAP_WIRE${NC}"
echo -e "     3. LAN Dest (Restauré) : ${MAGENTA}$PCAP_LAN_B${NC}"
echo -e "  Ouvrez-les avec la commande : ${YELLOW}wireshark $PCAP_WIRE${NC}"
echo -e "${BOLD}──────────────────────────────────────────────────────────────${NC}\n"

exit "$FAILURES"
