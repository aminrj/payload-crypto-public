# TRANS3 V1.0 — Authenticated In-Place Payload Encryptor

## Overview

TRANS3 is a Linux kernel Netfilter/iptables target implementing **XChaCha20-Poly1305** authenticated in-place payload encryption. It is the authenticated successor to TRANS1, adding replay protection and MAC verification.

| Feature | TRANS1 | TRANS3 |
|---|---|---|
| Algorithm | XChaCha20 (stream) | XChaCha20-Poly1305 (AEAD) |
| Authentication | None | Poly1305 MAC |
| Replay protection | None | 4096-packet sliding window |
| Overhead | **0 bytes** | **+32 bytes** |
| Nonce source | pkt_params (IP/port/ID) | RNONCE (random, per-packet) |
| Direction | Symmetric (XOR) | Asymmetric (`--mode e` / `--mode d`) |

---

## Wire Format

```
Before encryption:
  [ IP hdr ][ L4 hdr ][ plaintext payload (N bytes) ]

After encryption:
  [ IP hdr ][ L4 hdr ][ ciphertext(payload||SEQ) ][ MAC:16 ][ RNONCE:8 ]
                        ←── N+8 bytes encrypted ──→←── 24 bytes ──→
                                                    overhead total: +32 bytes
```

| Field | Size | Location | Description |
|---|---|---|---|
| `RNONCE` | 8 bytes | In clear at tail | Random per-packet, used only to derive nonce via blake2s |
| `SEQ` | 8 bytes | Encrypted in ciphertext | Hidden counter for replay detection |
| `MAC` | 16 bytes | After ciphertext | Poly1305 tag — rejects any tampered/foreign packet |
| `AAD` | 18 bytes | Not sent on wire | `"NEGENCRY.TRANS3.V1"` — proprietary signature authenticated by MAC |

---

## Nonce Derivation

```
nonce[24] = blake2s(key=nonce_key[32], in=RNONCE[8], outlen=24, inlen=8)
```

RNONCE provides full 64-bit entropy per packet — no wrap-around at 65535 unlike IP ID-based nonces.

---

## Installation

```bash
git clone <repo>
cd trans3
sudo ./install.sh
```

### Prerequisites

```bash
# Installed automatically by setup_deps.sh
apt install build-essential linux-headers-$(uname -r) libxtables-dev \
            ebtables bridge-utils tshark iperf3 shc

# Leancrypto (built from source by setup_deps.sh)
# https://github.com/smuellerDD/leancrypto
```

---

## Key Management

```bash
# Generate 64 random bytes (32 = XChaCha20 key, 32 = Blake2s nonce_key)
dd if=/dev/urandom of=/tmp/key3.bin bs=1 count=64

# Seal to this machine (bound to /etc/machine-id via SHA-256)
sudo loadkey3 /tmp/key3.bin

# Verify
sudo showkey3

# Destroy plain key immediately
shred -u /tmp/key3.bin
```

### Key file format (`/etc/.file/file3`, 136 bytes)

```
[ 0.. 15]  random prefix    (16 bytes)
[16.. 39]  nonce            (24 bytes — first 12 = IV, next 12 = AAD)
[40..103]  ciphertext       (64 bytes — encrypted raw_key)
[104..119] Poly1305 MAC     (16 bytes)
[120..135] random suffix    (16 bytes)
```

Machine binding: `master_key = SHA-256(/etc/machine-id)` — key becomes unreadable on another machine.

---

## Usage

### Layer 3 — iptables (host to host)

```bash
# Sender — encrypt outgoing
sudo iptables -t mangle -A POSTROUTING -d <PEER_IP> -p tcp -j TRANS3 --mode e
sudo iptables -t mangle -A POSTROUTING -d <PEER_IP> -p udp -j TRANS3 --mode e

# Receiver — decrypt incoming
sudo iptables -t mangle -A PREROUTING  -s <PEER_IP> -p tcp -j TRANS3 --mode d
sudo iptables -t mangle -A PREROUTING  -s <PEER_IP> -p udp -j TRANS3 --mode d

# MSS clamping (mandatory — TRANS3 adds +32 bytes)
sudo iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1428
```

### Layer 2 — Bridge (bump-in-the-wire, no IP needed)

```bash
# Setup bridge
ip link add br0 type bridge
ip link set eth0 master br0   # LAN port
ip link set eth1 master br0   # WAN port
ip link set eth0 up && ip link set eth1 up && ip link set br0 up

# Enable br_netfilter (mandatory)
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1

# MTU — asymmetric (critical)
ip link set eth0 mtu 1468   # LAN — pre-encryption
ip link set eth1 mtu 1500   # WAN — post-encryption (+32 bytes)
ip link set br0  mtu 1500   # bridge = max(members)

# physdev rules (mandatory on bridge — -i/-o always points to br0)
iptables -t mangle -A FORWARD -m physdev --physdev-out eth1 -j TRANS3 --mode e
iptables -t mangle -A FORWARD -m physdev --physdev-in  eth1 -j TRANS3 --mode d

# MSS clamping
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1428
```

---

## MTU / MSS Reference

| Value | Standard | TRANS3 | Note |
|---|---|---|---|
| Ethernet MTU | 1500 | **1468** LAN / **1500** WAN | LAN reduced by +32 overhead |
| TCP MSS | 1460 | **1428** | 1460 - 32 |
| UDP payload max | 1472 | **1440** | 1472 - 32 |
| IP payload max | 1480 | **1448** | 1480 - 32 |

### Why asymmetric MTU on bridge

```
Host sends 1428 bytes data:
  IP packet = 20(IP) + 20(TCP) + 1428 = 1468 bytes → fits LAN MTU 1468 ✓
After TRANS3 encrypt:
  1468 + 32 overhead = 1500 bytes → fits WAN MTU 1500 ✓

If LAN MTU = 1500: host sends 1460 bytes data
  IP packet = 1500 bytes → TRANS3 adds 32 → 1532 > 1500 → DROPPED ✗
```

---

## Layer 2 / Bridge / VLAN Support

TRANS3 only encrypts the IP payload — Ethernet header, IP header, and L4 headers stay in clear. This makes it transparent at Layer 2:

- **Switches and routers** forward normally (src/dst MAC unchanged)
- **VLAN tags** (802.1Q) stay in clear — trunks work without modification
- **The bridge is invisible** — no IP address required

### What stays in clear on the wire

```
[ Ethernet header ][ IP header ][ L4 header ][ CIPHERTEXT ][ MAC:16 ][ RNONCE:8 ]
  src/dst MAC        src/dst IP   sport/dport   encrypted      auth      random
  EtherType          proto,TTL    seq,ack        payload      tag       nonce
  VLAN tag
  (ALL IN CLEAR)
```

---

## Replay Protection

TRANS3 uses a **4096-bit sliding window** on the hidden SEQ field:

- SEQ is encrypted inside the ciphertext — attacker cannot see or predict it
- Extracted only after successful MAC verification
- Duplicate or replayed packets are silently dropped
- Window size: 4096 packets (handles reordering + burst delivery)

---

## Admin Interface

```bash
sudo trans3

Menu:
  1 — Initialize kernel engine (modprobe xt_TRANS3)
  2 — Key management (show / import from USB)
  3 — Add encryption rule (L3 target IP or L2 bridge physdev)
  4 — Real-time telemetry (packet counters per rule)
  5 — Persist rules (/etc/iptables/rules.v4)
  6 — Purge all rules (clear text mode)
  7 — Exit
```

---

## Project Structure

```
trans3/
├── README.md              ← this file
├── readme.md              ← developer reference
├── install.sh             ← automated installer
├── src/
│   ├── Makefile
│   ├── xt_TRANS3_main.c   ← kernel module
│   ├── libxt_TRANS3.h     ← shared header
│   ├── libxt_TRANS3.c     ← iptables plugin (.so)
│   ├── loadkey3.c         ← key sealing tool
│   └── showkey3.c         ← key verification tool
└── Setup/
    ├── setup_deps.sh      ← install deps + Leancrypto
    └── trans3_admin.sh    ← admin interface (compiled via shc)
```
