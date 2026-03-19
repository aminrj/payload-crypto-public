# TRANS3 V1.0 — Developer Reference

## Architecture

### Kernel module (`xt_TRANS3_main.c`)

Registration: `NFPROTO_IPV4`, table `mangle`, target `TRANS3`.

With `br_netfilter` active, `NFPROTO_IPV4` also covers bridged IPv4 frames — no `NFPROTO_BRIDGE` registration needed.

### Per-packet encrypt path

```
handle_encrypt(skb, info):
  1. prepare_skb()            → parse IP/L4, compute offset
  2. pskb_expand_head()       → allocate +32 bytes at skb tail
  3. get_random_bytes(rnonce) → 8 random bytes per packet
  4. atomic64_inc(tx_seq)     → monotonic counter, seeded at boot
  5. derive_nonce()           → blake2s(nonce_key, rnonce) = 24-byte nonce
  6. put_unaligned_le64(seq)  → write SEQ at payload+payload_len (plaintext)
  7. xchacha20poly1305_encrypt(payload, payload, payload_len+SEQ_SIZE,
                               TRANS3_SIG, SIG_LEN, nonce, key)
     → overwrites buffer with: ciphertext(N+8) + MAC(16)
  8. memcpy(RNONCE)           → append 8-byte RNONCE after MAC
  9. recalc_checksums()       → IP + TCP/UDP/ICMP checksum
```

### Per-packet decrypt path

```
handle_decrypt(skb, info):
  1. prepare_skb()            → parse, ensure payload ≥ OVERHEAD bytes
  2. memcpy(rnonce)           → read RNONCE from last 8 bytes
  3. derive_nonce()           → blake2s(nonce_key, rnonce) = same nonce
  4. xchacha20poly1305_decrypt(payload, payload,
                               payload_len - RNONCE_SIZE,  ← ciphertext+MAC
                               TRANS3_SIG, SIG_LEN, nonce, key)
     → MAC failure → NF_DROP (wrong key, tampered, non-TRANS3 packet)
     → MAC success → buffer = plaintext(N) || SEQ(8)
  5. seq = get_unaligned_le64(payload + orig_len)
  6. check_replay(seq)        → sliding window, reject duplicates
  7. pskb_trim()              → remove OVERHEAD bytes from tail
  8. recalc_checksums()       → IP + TCP/UDP/ICMP checksum
```

---

## Cryptographic Design

### XChaCha20-Poly1305 (AEAD)

Uses the kernel's built-in `crypto/chacha20poly1305.h`:
- `xchacha20poly1305_encrypt()` / `xchacha20poly1305_decrypt()`
- 256-bit key, 192-bit (24-byte) nonce
- Poly1305 MAC covers ciphertext + AAD

### RNONCE vs IP-ID nonce (TRANS1 comparison)

| | TRANS1 nonce | TRANS3 nonce |
|---|---|---|
| Source | pkt_params (IP ID, ports...) | RNONCE (random bytes) |
| Entropy | ~16 bits (IP ID wraps at 65535) | 64 bits (cryptographic random) |
| Predictable | Partially (IP ID is sequential) | No |
| Wire | Not sent (both sides recompute) | Sent in clear (8 bytes at tail) |

### AAD — Proprietary signature

```c
static const uint8_t trans3_sig[] = "NEGENCRY.TRANS3.V1";  // 18 bytes
```

Authenticated by Poly1305 MAC but NOT sent on wire. Any packet not produced by TRANS3 (wrong AAD) fails MAC → `NF_DROP`. Packets from other tools, scanners, or wrong implementations are silently rejected.

### SEQ encryption

```c
// SEQ written in plaintext BEFORE calling xchacha20poly1305_encrypt
put_unaligned_le64(seq, payload + payload_len);

// xchacha20poly1305_encrypt encrypts payload+SEQ together
xchacha20poly1305_encrypt(dst, src, payload_len + SEQ_SIZE, ...);

// Result: ciphertext(payload||SEQ) — SEQ is completely hidden
```

---

## Anti-Replay Sliding Window

```c
#define REPLAY_WINDOW_BITS  4096u
#define REPLAY_BITMAP_WORDS (4096 / 64)   // 64 x uint64_t

static uint64_t rx_highest_seq   = 0;
static uint64_t rx_bitmap[64]    = {0};
static DEFINE_SPINLOCK(rx_lock);
```

- Window slides forward as new higher SEQ values arrive
- Duplicate detection via bitmap bit test-and-set
- Replay check is performed **after** MAC verification (prevents oracle attacks)
- `spinlock_bh` protects the bitmap for SMP safety

---

## Module Registration

```c
static struct xt_target xt_trans3_reg = {
    .name       = "TRANS3",
    .family     = NFPROTO_IPV4,   // covers routed + bridged IPv4
    .table      = "mangle",
    .target     = xt_trans3_target,
    .targetsize = sizeof(struct xt_crypt_info),
    .me         = THIS_MODULE,
};
```

`NFPROTO_IPV4` with `br_netfilter` covers:
- `PREROUTING` — incoming (routed or bridged)
- `FORWARD` — bridged frames (LAN↔WAN transparent bridge)
- `POSTROUTING` — outgoing (routed or bridged)

No `NFPROTO_BRIDGE` registration needed.

---

## Bridge / L2 Code Path

When called from `FORWARD` on a bridge:

```
Physical frame arrives on eth0 (LAN bridge port)
  → br_netfilter adjusts skb->data → points to IP header
  → iptables mangle FORWARD hook fires
  → TRANS3 handle_encrypt():
      prepare_skb() → same IP+L4 parsing as routed case
      get_random_bytes(rnonce) → fresh entropy per frame
      xchacha20poly1305_encrypt() → payload encrypted in-place
      recalc_checksums() → IP+TCP checksums updated
  → frame exits on eth1 (WAN bridge port) with encrypted payload
```

Frame size: `original + 32 bytes` → requires WAN port MTU = LAN port MTU + 32.

### physdev vs -i/-o on bridge

```bash
# WRONG — -i/-o always points to the bridge (br0), not the physical port
iptables -t mangle -A FORWARD -i eth0 -o eth1 -j TRANS3 --mode e

# CORRECT — physdev targets the actual Ethernet port
iptables -t mangle -A FORWARD -m physdev --physdev-out eth1 -j TRANS3 --mode e
```

---

## Userspace Key Sealing (`loadkey3.c` / `libxt_TRANS3.c`)

Both use Leancrypto's `LC_CHACHA20_POLY1305_CTX_ON_STACK` (12-byte nonce):

```
raw_key[64] (from file)
    ↓
master_key[32] = SHA-256(/etc/machine-id)
    ↓
ChaCha20-Poly1305:
  key   = master_key
  nonce = buffer[16..27]   (12 bytes)
  AAD   = buffer[28..39]   (12 bytes = nonce[12..23])
  plain = raw_key[64]
    ↓
/etc/.file/file3: prefix(16) || nonce(24) || ciphertext(64) || MAC(16) || suffix(16)
                                                                 136 bytes total
```

---

## Building

```bash
cd src
make          # builds kernel module + libxt_TRANS3.so + loadkey3 + showkey3
make install  # installs to system
make clean    # cleanup
make info     # show detected paths (XTABLES_DIR, LC_CFLAGS...)
```

### Makefile XTABLES_DIR detection (4-level fallback)

```makefile
XTABLES_DIR := $(shell \
    pkg-config --variable=xtlibdir xtables 2>/dev/null | grep -v '^$$' || \
    find /usr/lib/x86_64-linux-gnu -maxdepth 1 -name "xtables" -type d || \
    find /usr/lib -maxdepth 3 -name "libxt_standard.so" | xargs dirname || \
    echo "/usr/lib/x86_64-linux-gnu/xtables")
```
