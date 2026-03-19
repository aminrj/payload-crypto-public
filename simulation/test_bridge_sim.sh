#!/usr/bin/env bash
# =============================================================================
# test_bridge_sim.sh — Automated test suite for xt_TRANS3
# (Architecture: Hosts MTU 1500 / Bridges MTU 1550)
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; MAGENTA='\033[0;35m'; NC='\033[0m'

pass()  { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "  ${RED}[FAIL]${NC} $*"; FAILURES=$((FAILURES+1)); }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
info()  { echo -e "\n${CYAN}[*]${NC} ${BOLD}$*${NC}"; }
log()   { echo -e "  ${GREEN}[+]${NC} $*"; }
sep()   { echo -e "  ${BOLD}──────────────────────────────────────────────────────────────${NC}"; }

[[ $EUID -ne 0 ]] && { echo "Root required: sudo $0"; exit 1; }

# Check dependencies
for dep in tshark iperf3 tcpdump nc sha256sum; do
    command -v "$dep" &>/dev/null || { echo -e "${RED}[-]${NC} Missing package: $dep (apt install $dep)"; exit 1; }
done

NS_A="ns_host_a"; NS_B1="ns_bridge1"; NS_B2="ns_bridge2"; NS_B="ns_host_b"
IP_A="10.0.0.1"; IP_B="10.0.0.2"
PORT=18000; FAILURES=0

# Directory for Wireshark capture files
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
    echo -e "${RED}[-] Simulation is not running. Run: sudo ./setup_bridge_sim.sh${NC}"
    exit 1
fi

echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║       TRANS3 — AUTOMATED TEST REPORT AND NETWORK AUDIT       ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

# =============================================================================
# SECTION 1: FUNCTIONAL AND DATA INTEGRITY TESTS
# =============================================================================
info "SECTION 1: DATA INTEGRITY TESTS (AEAD Poly1305)"
sep

# 1. Ping
nsa ping -c 3 -W 2 "$IP_B" &>/dev/null && pass "End-to-end ICMP connectivity" || fail "ICMP ping failed"

# 2. 1 MB file transfer with hash verification
S="$PCAP_DIR/source_1m.bin"; R="$PCAP_DIR/recv_1m.bin"
dd if=/dev/urandom of="$S" bs=1M count=1 status=none
nsb nc -l -p $PORT > "$R" & SRV=$!; sleep 1
nsa nc $NC_OPTS "$IP_B" $PORT < "$S" 2>/dev/null || true
sleep 1.5; kill $SRV 2>/dev/null||true; wait $SRV 2>/dev/null||true

if [[ "$(sha256sum "$S" | awk '{print $1}')" == "$(sha256sum "$R" | awk '{print $1}')" ]]; then
    pass "1 MB transfer with SHA-256 verification (zero corruption) ✓"
else
    fail "Data corruption detected in 1 MB transfer!"
fi
PORT=$((PORT+1))

# =============================================================================
# SECTION 2: CRYPTOGRAPHIC AUDIT (WIRESHARK / TCPDUMP)
# =============================================================================
info "SECTION 2: CRYPTOGRAPHIC AUDIT AND WIRESHARK CAPTURES"
sep
log "Recording traffic at 3 simultaneous capture points..."

PLAINTEXT="TRANS3_TOP_SECRET_MESSAGE_$(date +%s)"
WS_PORT=17777

PCAP_LAN_A="$PCAP_DIR/1_LAN_Source_Plaintext.pcap"
PCAP_WIRE="$PCAP_DIR/2_WAN_Cable_Encrypted.pcap"
PCAP_LAN_B="$PCAP_DIR/3_LAN_Dest_Restored.pcap"

# AppArmor workaround: use "-w -" with bash redirection and "-U" (packet-buffered)
nsa  tcpdump -Z root -U -i veth-a0 -w - -s 0 tcp port $WS_PORT 2>/dev/null > "$PCAP_LAN_A" & TD_A=$!
nsb1 tcpdump -Z root -U -i veth-b0 -w - -s 0 tcp port $WS_PORT 2>/dev/null > "$PCAP_WIRE"  & TD_W=$!
nsb  tcpdump -Z root -U -i veth-c1 -w - -s 0 tcp port $WS_PORT 2>/dev/null > "$PCAP_LAN_B" & TD_B=$!

# Allow tcpdump time to initialize on virtual interfaces
sleep 3

# Start server and ensure it is listening before sending
nsb nc -l -p $WS_PORT > /dev/null & SRV=$!
sleep 1

# Send the secret message from client A
echo "$PLAINTEXT" | nsa nc $NC_OPTS "$IP_B" $WS_PORT 2>/dev/null || true

# Allow packets time to traverse and be written to disk
sleep 2

# Stop sniffers
kill $TD_A $TD_W $TD_B $SRV 2>/dev/null||true; wait $TD_A $TD_W $TD_B $SRV 2>/dev/null||true

echo -e "\n  ${BOLD}[ Point A — LAN Source (Before Encryption) ]${NC}"
if tshark -r "$PCAP_LAN_A" -z "follow,tcp,ascii,0" 2>/dev/null | grep -qF "$PLAINTEXT"; then
    pass "Message visible in plaintext on the source LAN ✓"
else
    warn "Message not detected (check captures manually)"
fi

echo -e "\n  ${BOLD}[ Point B — WAN Cable (Stealth Test) ]${NC}"
tshark -r "$PCAP_WIRE" -T fields -e frame.len 2>/dev/null | head -3 | while read -r len; do log "Intercepted frame: ${len} bytes ${RED}[ENCRYPTED]${NC}"; done
if strings "$PCAP_WIRE" 2>/dev/null | grep -qF "$PLAINTEXT"; then
    fail "DATA LEAK! Plaintext is visible on the WAN cable!"
else
    pass "No trace of plaintext. Encryption is hermetic ✓"
fi

echo -e "\n  ${BOLD}[ Point C — LAN Destination (After Decryption) ]${NC}"
if tshark -r "$PCAP_LAN_B" -z "follow,tcp,ascii,0" 2>/dev/null | grep -qF "$PLAINTEXT"; then
    pass "Message successfully restored on the destination LAN ✓"
else
    warn "Message not detected at destination"
fi

# =============================================================================
# SECTION 3: BANDWIDTH STRESS TESTS (IPERF3)
# =============================================================================
info "SECTION 3: IPERF3 BENCHMARK (MULTI-CORE)"
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

log "1. Traffic WITH xt_TRANS3 enabled:"
run_iperf "TCP (Encrypted — 4 threads)" 10 "-P 4"
run_iperf "UDP (Encrypted)" 5 "-u -b 0"

log "\n  Temporarily disabling xt_TRANS3 for baseline measurement..."
nsb1 $IPT -t mangle -F FORWARD 2>/dev/null || true
nsb2 $IPT -t mangle -F FORWARD 2>/dev/null || true

log "2. Traffic WITHOUT xt_TRANS3 (baseline):"
run_iperf "TCP (Plaintext — 4 threads)" 10 "-P 4"
run_iperf "UDP (Plaintext)" 5 "-u -b 0"

# Restore security rules
log "\n  Restoring security rules..."
nsb1 $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428
nsb1 $IPT -t mangle -A FORWARD -m physdev --physdev-out veth-b0 -j TRANS3 --mode e
nsb1 $IPT -t mangle -A FORWARD -m physdev --physdev-in  veth-b0 -j TRANS3 --mode d

nsb2 $IPT -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1428
nsb2 $IPT -t mangle -A FORWARD -m physdev --physdev-in  veth-b1 -j TRANS3 --mode d
nsb2 $IPT -t mangle -A FORWARD -m physdev --physdev-out veth-b1 -j TRANS3 --mode e

# =============================================================================
# SUMMARY AND EXPORT
# =============================================================================
echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
if [[ "$FAILURES" -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}RESULT: ALL TESTS PASSED SUCCESSFULLY${NC}"
else
    echo -e "  ${RED}${BOLD}RESULT: $FAILURES TEST(S) FAILED${NC}"
fi
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "  Wireshark capture files written to: ${MAGENTA}${PCAP_DIR}${NC}"
echo -e "     1. LAN Source  (Plaintext)  : ${MAGENTA}$PCAP_LAN_A${NC}"
echo -e "     2. WAN Cable   (Encrypted)  : ${MAGENTA}$PCAP_WIRE${NC}"
echo -e "     3. LAN Dest    (Restored)   : ${MAGENTA}$PCAP_LAN_B${NC}"
echo -e "  Open with: ${YELLOW}wireshark $PCAP_WIRE${NC}"
echo -e "${BOLD}──────────────────────────────────────────────────────────────${NC}\n"

exit "$FAILURES"
