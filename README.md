# TRANS3 — Authenticated Network Payload Encryptor

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://kernel.org)
[![Kernel Module](https://img.shields.io/badge/type-Netfilter%20Target-orange.svg)](https://netfilter.org)

TRANS3 is a Linux kernel module that encrypts network packet payloads **in-place** using **XChaCha20-Poly1305** (AEAD). It plugs into iptables as a standard target and works transparently at both Layer 3 (host-to-host) and Layer 2 (bump-in-the-wire bridge), with no changes required to applications or network topology.

---

## Why TRANS3?

| Concern | How TRANS3 addresses it |
|---|---|
| **No agent / app changes** | Works at the kernel level — applications are unaware |
| **Authenticated encryption** | Poly1305 MAC rejects tampered or foreign packets silently |
| **Replay protection** | 4096-packet sliding window on a hidden, encrypted sequence number |
| **Bridge / L2 transparent** | No IP address needed on the bridge — invisible on the network |
| **VLAN compatible** | 802.1Q tags stay in clear — trunk links work without changes |
| **Auditable crypto** | Uses the kernel's built-in `xchacha20poly1305` — no custom crypto |

---

## How It Works

```
Host A (plaintext)                                    Host B (plaintext)
     │                                                      │
     ▼                                                      ▼
[ IP ][ TCP ][ payload ]   ──encrypt──►   [ IP ][ TCP ][ ciphertext ][ MAC:16 ][ RNONCE:8 ]
                                                           +32 bytes overhead
                            ◄──decrypt──
```

TRANS3 appends 32 bytes to each packet:
- **8 bytes** — encrypted sequence number (hidden, anti-replay)
- **16 bytes** — Poly1305 authentication tag
- **8 bytes** — random per-packet nonce (RNONCE, in clear)

The nonce is derived per packet via `blake2s(nonce_key, RNONCE)` — no IV wrap-around, no predictability.

---

## Quick Start

```bash
git clone https://github.com/aminrj/payload-crypto-public.git
cd payload-crypto-public
sudo ./install.sh
```

### Requirements

- Linux kernel 5.4+ with `br_netfilter` support
- Debian/Ubuntu (tested on Ubuntu 22.04+)
- [Leancrypto](https://github.com/smuellerDD/leancrypto) (installed automatically by `setup_deps.sh`)

Dependencies installed automatically:
```
build-essential  linux-headers  libxtables-dev  ebtables  bridge-utils  tshark  iperf3  shc
```

---

## Key Management

```bash
# 1. Generate a 64-byte key (32 = XChaCha20 key, 32 = Blake2s nonce_key)
dd if=/dev/urandom of=/tmp/key3.bin bs=1 count=64

# 2. Seal the key to this machine (bound to /etc/machine-id via SHA-256)
sudo loadkey3 /tmp/key3.bin

# 3. Verify the sealed key
sudo showkey3

# 4. Destroy the plaintext key
shred -u /tmp/key3.bin
```

The sealed key is stored at `/etc/.file/file3` (136 bytes, mode 0600). It cannot be read on a different machine — the decryption key is derived from `/etc/machine-id`.

---

## Usage

### Layer 3 — Host to Host

```bash
# Encrypt outgoing traffic to peer
sudo iptables -t mangle -A POSTROUTING -d <PEER_IP> -p tcp -j TRANS3 --mode e
sudo iptables -t mangle -A POSTROUTING -d <PEER_IP> -p udp -j TRANS3 --mode e

# Decrypt incoming traffic from peer
sudo iptables -t mangle -A PREROUTING  -s <PEER_IP> -p tcp -j TRANS3 --mode d
sudo iptables -t mangle -A PREROUTING  -s <PEER_IP> -p udp -j TRANS3 --mode d

# MSS clamping — required because TRANS3 adds +32 bytes per packet
sudo iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1428
```

### Layer 2 — Bump-in-the-Wire Bridge

```bash
# Create a transparent bridge
ip link add br0 type bridge
ip link set eth0 master br0 && ip link set eth1 master br0
ip link set eth0 up && ip link set eth1 up && ip link set br0 up

# Required for iptables to see bridged frames
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1

# Asymmetric MTU — LAN is smaller to absorb the +32 overhead on the WAN side
ip link set eth0 mtu 1468
ip link set eth1 mtu 1500

# Use physdev — -i/-o on a bridge always points to br0, not the physical port
iptables -t mangle -A FORWARD -m physdev --physdev-out eth1 -j TRANS3 --mode e
iptables -t mangle -A FORWARD -m physdev --physdev-in  eth1 -j TRANS3 --mode d

# MSS clamping
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1428
```

### Admin Interface

```bash
sudo trans3
```

Interactive menu for key management, rule configuration, telemetry, and persistence.

---

## MTU / MSS Reference

| Value | Standard | With TRANS3 |
|---|---|---|
| Ethernet MTU (LAN) | 1500 | **1468** |
| Ethernet MTU (WAN) | 1500 | 1500 (unchanged) |
| TCP MSS | 1460 | **1428** |
| UDP payload max | 1472 | **1440** |

The LAN MTU is reduced by 32 so that after encryption, the packet still fits within the WAN MTU of 1500.

---

## Simulation Lab

A self-contained virtual lab is included for testing and demonstration.

```bash
cd simulation

# Start the lab (two bridge nodes + two hosts in network namespaces)
sudo ./setup_bridge_sim.sh

# Run the full test suite
sudo ./test_bridge_sim.sh

# Tear down
sudo ./setup_bridge_sim.sh --clean
```

The test suite covers: ICMP connectivity, 1 MB file transfer with SHA-256 integrity, Wireshark captures at three simultaneous points, stealth verification (no plaintext on the WAN segment), iperf3 throughput comparison, and MSS clamping validation.

See [`simulation/readme.md`](simulation/readme.md) for the full topology diagram.

---

## Project Structure

```
payload-crypto-public/
├── README.md
├── install.sh                  ← one-command installer
├── src/
│   ├── Makefile
│   ├── xt_TRANS3_main.c        ← kernel module (Netfilter target)
│   ├── libxt_TRANS3.h          ← shared header
│   ├── libxt_TRANS3.c          ← iptables userspace plugin (.so)
│   ├── loadkey3.c              ← key sealing tool
│   ├── showkey3.c              ← key verification tool
│   └── readme.md               ← developer reference
├── Setup/
│   ├── setup_deps.sh           ← dependency installer
│   ├── trans3_admin.sh         ← admin interface source
│   └── deploy_physical_bridgesh.sh
└── simulation/
    ├── readme.md               ← lab topology and packet journey
    ├── setup_bridge_sim.sh     ← virtual lab setup
    └── test_bridge_sim.sh      ← automated test suite
```

---

## Security Design

- **Algorithm**: XChaCha20-Poly1305 (kernel built-in `crypto/chacha20poly1305.h`)
- **Key size**: 256-bit encryption key + 256-bit Blake2s nonce key
- **Nonce**: Per-packet random 64-bit RNONCE → expanded to 192-bit via Blake2s
- **AAD**: Proprietary `"NEGENCRY.TRANS3.V1"` signature (not sent on wire) — packets from unknown sources or wrong implementations fail MAC and are silently dropped
- **Replay protection**: 4096-bit sliding window on encrypted SEQ — checked after MAC verification to prevent timing oracles
- **Key binding**: `master_key = SHA-256(/etc/machine-id)` — sealed key is unreadable on another machine
- **Memory safety**: Sensitive buffers zeroed with `memzero_explicit()` / `lc_memset_secure()`

---

## Troubleshooting

**Packets dropped after enabling TRANS3**
- Check MTU: LAN interface must be set to 1468 (`ip link set ethX mtu 1468`)
- Check MSS clamping rule is in place
- Verify both endpoints share the same key (`sudo showkey3`)

**`ERROR: Can't insert ... No such file or directory`**
- Module not loaded: `sudo modprobe xt_TRANS3`
- Or run `sudo trans3` → option 1

**`Key verification failed (wrong machine?)`**
- The key was sealed on a different machine or `/etc/machine-id` changed
- Re-seal the key on the current machine with `loadkey3`

**Bridge rules not matching**
- Use `--physdev-out / --physdev-in` instead of `-o / -i` on bridge interfaces
- Ensure `sysctl net.bridge.bridge-nf-call-iptables=1` is set

---

## License

GPL-2.0 — see [LICENSE](LICENSE).
