// SPDX-License-Identifier: GPL-2.0
#pragma GCC optimize("O3,unroll-loops,inline-functions")

/* ============================================================================
 * xt_TRANS3 — Authenticated Payload Encryptor with Replay Protection
 *
 * Algorithm  : XChaCha20-Poly1305 (AEAD)
 * Nonce      : blake2s(nonce_key[32], RNONCE[8]) → 24 bytes
 * AAD        : TRANS3_SIGNATURE — proprietary, rejects foreign packets
 * Overhead   : +32 bytes  (SEQ:8 encrypted + MAC:16 + RNONCE:8 in clear)
 *
 * Wire format after encryption:
 *
 *   [ IP ][ L4 ][ ciphertext(payload ‖ SEQ) ][ MAC:16 ][ RNONCE:8 ]
 *               ←────── N + 8 bytes ────────→←── 24 bytes appended ──→
 *
 * Security properties:
 *   RNONCE  — 8 random bytes per packet, full entropy nonce, no wrap-around
 *   SEQ     — monotonic counter, encrypted (hidden), anti-replay window 4096
 *   MAC     — Poly1305 over ciphertext+SEQ, AAD=proprietary signature
 *   AAD     — NOT sent on wire, must match on both sides
 * ============================================================================ */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <net/gre.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/unaligned.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>

#include "libxt_TRANS3.h"

MODULE_AUTHOR("Abdo Abdel");
MODULE_DESCRIPTION("TRANS3 — XChaCha20-Poly1305 + Blake2s(RNONCE) + Replay");
MODULE_LICENSE("GPL");

/* Proprietary AAD — authenticated by MAC, never sent on wire */
static const uint8_t trans3_sig[TRANS3_SIG_LEN] = TRANS3_SIG;

/* =========================================================================
 * ANTI-REPLAY — 4096-bit sliding window
 * ========================================================================= */
#define REPLAY_WINDOW_BITS  4096u
#define REPLAY_BITMAP_WORDS (REPLAY_WINDOW_BITS / 64)

static atomic64_t      tx_seq;
static uint64_t        rx_highest_seq;
static uint64_t        rx_bitmap[REPLAY_BITMAP_WORDS];
static DEFINE_SPINLOCK(rx_lock);

static __always_inline bool check_replay(uint64_t seq)
{
    bool valid = false;

    if (unlikely(seq == 0))
        return false;

    spin_lock_bh(&rx_lock);

    if (seq > rx_highest_seq) {
        uint64_t diff   = seq - rx_highest_seq;
        uint64_t wshift = diff / 64;
        uint64_t bshift = diff % 64;
        int w;

        if (diff >= REPLAY_WINDOW_BITS) {
            memset(rx_bitmap, 0, sizeof(rx_bitmap));
        } else {
            if (wshift > 0) {
                for (w = REPLAY_BITMAP_WORDS - 1; w >= (int)wshift; w--)
                    rx_bitmap[w] = rx_bitmap[w - wshift];
                for (w = (int)wshift - 1; w >= 0; w--)
                    rx_bitmap[w] = 0;
            }
            if (bshift > 0) {
                for (w = REPLAY_BITMAP_WORDS - 1; w > 0; w--)
                    rx_bitmap[w] = (rx_bitmap[w] << bshift) |
                                   (rx_bitmap[w - 1] >> (64 - bshift));
                rx_bitmap[0] <<= bshift;
            }
        }
        rx_bitmap[0]   |= 1ULL;
        rx_highest_seq  = seq;
        valid = true;

    } else {
        uint64_t diff = rx_highest_seq - seq;
        if (diff < REPLAY_WINDOW_BITS) {
            int      w = (int)(diff / 64);
            uint64_t b = diff % 64;
            if (!(rx_bitmap[w] & (1ULL << b))) {
                rx_bitmap[w] |= (1ULL << b);
                valid = true;
            }
        }
    }

    spin_unlock_bh(&rx_lock);
    return valid;
}

/* =========================================================================
 * DERIVE_NONCE
 *
 *   nonce[24] = blake2s(key=nonce_key, in=rnonce[8], outlen=24, inlen=8)
 * ========================================================================= */
static __always_inline void derive_nonce(
        uint8_t nonce[XCHACHA20POLY1305_NONCE_SIZE],
        const uint8_t nonce_key[32],
        const uint8_t rnonce[RNONCE_SIZE])
{
    blake2s(nonce, rnonce, nonce_key,
            XCHACHA20POLY1305_NONCE_SIZE, RNONCE_SIZE, 32);
}

/* =========================================================================
 * PARSE_SKB
 *
 * Linearizes the skb, validates all headers, and returns the byte offset
 * of the application payload. All header pointers are re-derived from
 * skb->data AFTER skb_ensure_writable() to avoid use-after-realloc bugs.
 *
 * Returns:
 *   > 0  payload offset
 *     0  unsupported protocol → XT_CONTINUE
 *    -1  invalid/fragment → NF_DROP
 *
 * Outputs:
 *   *old_l4_len  total L4 length (header + payload) BEFORE any expansion
 *   *proto       IP protocol number
 *   *ihl         IP header length in words (for recalc_checksums)
 * ========================================================================= */
static __always_inline int parse_skb(struct sk_buff *skb,
                                      int    *old_l4_len,
                                      uint8_t *proto,
                                      uint8_t *ihl)
{
    struct iphdr *iph;
    int           iph_len;

    /* ── Reject fragments — nonce derivation would be incorrect ── */
    if (unlikely(ip_is_fragment(ip_hdr(skb))))
        return -1;

    /* ── Linearize — all bytes must be contiguous for in-place AEAD ── */
    if (unlikely(skb_is_nonlinear(skb)) && unlikely(skb_linearize(skb)))
        return -1;

    iph = ip_hdr(skb);
    if (unlikely(iph->ihl < 5))
        return -1;

    iph_len = iph->ihl * 4;
    if (unlikely((unsigned int)skb->len < (unsigned int)iph_len))
        return -1;

    /* ── Make writable — COW if shared, refreshes internal pointers ── */
    if (unlikely(skb_ensure_writable(skb, skb->len)))
        return -1;

    /* Re-derive after skb_ensure_writable (may have reallocated) */
    iph = ip_hdr(skb);

    *proto      = iph->protocol;
    *ihl        = iph->ihl;
    *old_l4_len = (int)skb->len - iph_len;

    if (*proto == IPPROTO_TCP) {
        struct tcphdr *tcph;
        int tcph_len;

        if (unlikely(*old_l4_len < (int)sizeof(struct tcphdr)))
            return -1;

        tcph     = (struct tcphdr *)((uint8_t *)iph + iph_len);
        tcph_len = tcph->doff * 4;

        if (unlikely(tcph_len < (int)sizeof(struct tcphdr) ||
                     *old_l4_len < tcph_len))
            return -1;

        return iph_len + tcph_len;

    } else if (*proto == IPPROTO_UDP) {
        if (unlikely(*old_l4_len < (int)sizeof(struct udphdr)))
            return -1;
        return iph_len + (int)sizeof(struct udphdr);

    } else if (*proto == IPPROTO_ICMP) {
        if (unlikely(*old_l4_len < (int)sizeof(struct icmphdr)))
            return -1;
        return iph_len + (int)sizeof(struct icmphdr);

    } else if (*proto == IPPROTO_IGMP) {
        if (unlikely(*old_l4_len < (int)sizeof(struct igmphdr)))
            return -1;
        return iph_len + (int)sizeof(struct igmphdr);

    } else if (*proto == IPPROTO_GRE) {
        struct gre_base_hdr *greh;

        if (unlikely(*old_l4_len < (int)sizeof(struct gre_base_hdr)))
            return -1;

        greh = (struct gre_base_hdr *)((uint8_t *)iph + iph_len);

        /* Only standard GRE — no checksum/key/seq fields */
        if (unlikely(greh->flags != 0))
            return -1;

        return iph_len + (int)sizeof(struct gre_base_hdr);
    }

    return 0; /* Unsupported — pass through */
}

/* =========================================================================
 * RECALC_CHECKSUMS
 *
 * Called AFTER skb->len has been updated (skb_put or pskb_trim).
 * All pointers are re-derived from skb->data to ensure correctness.
 *
 * new_l4_len = current total L4 length (updated by caller)
 * ========================================================================= */
static __always_inline void recalc_checksums(struct sk_buff *skb,
                                              int     new_l4_len,
                                              uint8_t proto,
                                              uint8_t ihl)
{
    struct iphdr *iph;
    uint8_t      *l4_hdr;

    /* Re-derive ALL pointers from skb->data after any length change */
    iph    = ip_hdr(skb);
    l4_hdr = (uint8_t *)iph + ((unsigned int)ihl * 4);

    /* ── IP header ── */
    iph->tot_len   = htons((uint16_t)skb->len);
    iph->check     = 0;
    iph->check     = ip_fast_csum((const unsigned char *)iph, iph->ihl);
    skb->ip_summed = CHECKSUM_NONE;

    /* ── L4 header ── */
    switch (proto) {
    case IPPROTO_TCP: {
        struct tcphdr *tcph = (struct tcphdr *)l4_hdr;
        tcph->check = 0;
        tcph->check = csum_tcpudp_magic(
                          iph->saddr, iph->daddr,
                          (uint16_t)new_l4_len, IPPROTO_TCP,
                          csum_partial(l4_hdr, new_l4_len, 0));
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udph = (struct udphdr *)l4_hdr;
        udph->len   = htons((uint16_t)new_l4_len);
        udph->check = 0;
        udph->check = csum_tcpudp_magic(
                          iph->saddr, iph->daddr,
                          (uint16_t)new_l4_len, IPPROTO_UDP,
                          csum_partial(l4_hdr, new_l4_len, 0));
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr *icmph = (struct icmphdr *)l4_hdr;
        icmph->checksum = 0;
        icmph->checksum = csum_fold(csum_partial(l4_hdr, new_l4_len, 0));
        break;
    }
    case IPPROTO_IGMP: {
        struct igmphdr *igmph = (struct igmphdr *)l4_hdr;
        igmph->csum = 0;
        igmph->csum = csum_fold(csum_partial(l4_hdr, new_l4_len, 0));
        break;
    }
    default:
        break; /* GRE with flags==0: no checksum field */
    }
}

/* =========================================================================
 * ENCRYPT
 *
 * Plaintext  : payload(N) ‖ SEQ(8)  — SEQ appended in-place before call
 * Ciphertext : xchacha20poly1305_encrypt → N+8 bytes + MAC(16)
 * Tail layout: [ ciphertext(N+8) ][ MAC:16 ][ RNONCE:8 ]
 *
 * Memory safety:
 *   - All pointer math uses explicit bounds (offset, payload_len, OVERHEAD)
 *   - skb tail is expanded BEFORE any write
 *   - ip_hdr() / tcp_hdr() re-derived after every skb modification
 *   - All sensitive stack buffers wiped with memzero_explicit
 * ========================================================================= */
static __always_inline unsigned int handle_encrypt(struct sk_buff *skb,
                                                    const struct xt_crypt_info *info)
{
    int      old_l4_len, offset, payload_len, new_l4_len;
    uint8_t  proto, ihl;
    uint64_t seq;
    uint8_t  rnonce[RNONCE_SIZE];
    uint8_t  nonce[XCHACHA20POLY1305_NONCE_SIZE];
    uint8_t *tail;         /* pointer to start of appended area */

    /* ── Parse and validate ── */
    offset = parse_skb(skb, &old_l4_len, &proto, &ihl);
    if (unlikely(offset <= 0))
        return (offset == 0) ? XT_CONTINUE : NF_DROP;

    payload_len = (int)skb->len - offset;
    if (unlikely(payload_len <= 0))
        return XT_CONTINUE;

    /* SEQ is encrypted with payload → actual ciphertext = payload + SEQ_SIZE
     * Total size increase = SEQ_SIZE(encrypted, already in OVERHEAD) + MAC + RNONCE */
    if (unlikely((long)skb->len + OVERHEAD > 65535))
        return NF_DROP;

    /* ── Expand tail BEFORE touching any data ── */
    if (unlikely(skb_tailroom(skb) < OVERHEAD)) {
        if (unlikely(pskb_expand_head(skb, 0, OVERHEAD, GFP_ATOMIC)))
            return NF_DROP;
    }

    /* ── Generate sensitive material ── */
    get_random_bytes(rnonce, RNONCE_SIZE);

    seq = (uint64_t)atomic64_inc_return(&tx_seq);
    if (unlikely(seq == 0))
        seq = (uint64_t)atomic64_inc_return(&tx_seq);

    derive_nonce(nonce, info->nonce_key, rnonce);

    /* ── Grow the skb — re-derive payload pointer AFTER skb_put ── */
    skb_put(skb, OVERHEAD);

    /* All pointers re-derived from skb->data after skb_put */
    tail = skb->data + offset + payload_len;

    /* Write SEQ in little-endian immediately after the original payload.
     * This is within the newly allocated OVERHEAD area. */
    put_unaligned_le64(seq, tail);       /* tail[0..7] = SEQ (plaintext) */

    /*
     * xchacha20poly1305_encrypt encrypts in-place:
     *   input  = skb->data + offset  (payload_len + SEQ_SIZE bytes)
     *   output = same buffer
     *   result = ciphertext(N+8) written at skb->data+offset
     *            MAC(16) written immediately after
     *
     * tail + SEQ_SIZE now points to where MAC will be written.
     * tail + SEQ_SIZE + MAC_SIZE is where we write RNONCE.
     */
    xchacha20poly1305_encrypt(
        skb->data + offset,                   /* dst (in-place)          */
        skb->data + offset,                   /* src                     */
        (size_t)(payload_len + SEQ_SIZE),     /* plaintext length        */
        trans3_sig,   TRANS3_SIG_LEN,         /* AAD — proprietary sig   */
        nonce,
        info->key);

    /* Write RNONCE in clear after the MAC — no memcpy needed, direct write */
    put_unaligned_le64(get_unaligned_le64(rnonce),
                       skb->data + offset + payload_len + SEQ_SIZE + MAC_SIZE);
    /* Note: the above works for 8-byte aligned writes.
     * For safety, use the explicit form: */
    memcpy(skb->data + offset + payload_len + SEQ_SIZE + MAC_SIZE,
           rnonce, RNONCE_SIZE);

    /* ── Update UDP inner length (TCP/IP updated by recalc_checksums) ── */
    if (proto == IPPROTO_UDP) {
        /* Re-derive udph from skb->data after all modifications */
        struct iphdr  *iph  = ip_hdr(skb);
        struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + ihl * 4);
        udph->len = htons(ntohs(udph->len) + (uint16_t)OVERHEAD);
    }

    new_l4_len = old_l4_len + OVERHEAD;
    recalc_checksums(skb, new_l4_len, proto, ihl);

    /* ── Wipe sensitive stack data ── */
    memzero_explicit(nonce,  sizeof(nonce));
    memzero_explicit(rnonce, sizeof(rnonce));
    memzero_explicit(&seq,   sizeof(seq));
    return XT_CONTINUE;
}

/* =========================================================================
 * DECRYPT
 *
 * Memory safety:
 *   - RNONCE read with explicit bounds check before any crypto operation
 *   - Nonce derived before xchacha20poly1305_decrypt
 *   - SEQ read from decrypted buffer, position computed with strict arithmetic
 *   - SEQ wiped in-place after reading (before replay check)
 *   - pskb_trim called with verified new length
 *   - All sensitive stack buffers wiped unconditionally
 * ========================================================================= */
static __always_inline unsigned int handle_decrypt(struct sk_buff *skb,
                                                    const struct xt_crypt_info *info)
{
    int      old_l4_len, offset, payload_len, orig_payload_len, new_l4_len;
    uint8_t  proto, ihl;
    uint64_t seq;
    uint8_t  rnonce[RNONCE_SIZE];
    uint8_t  nonce[XCHACHA20POLY1305_NONCE_SIZE];
    bool     mac_ok;

    /* ── Parse and validate ── */
    offset = parse_skb(skb, &old_l4_len, &proto, &ihl);
    if (unlikely(offset <= 0))
        return (offset == 0) ? XT_CONTINUE : NF_DROP;

    payload_len = (int)skb->len - offset;

    /* Minimum: SEQ(8) in ciphertext + MAC(16) + RNONCE(8) = OVERHEAD(32) */
    if (unlikely(payload_len < OVERHEAD))
        return XT_CONTINUE;

    /* ── Read RNONCE from the last RNONCE_SIZE bytes ──
     * Explicit bounds: skb->data + offset + payload_len - RNONCE_SIZE
     *                = skb->data + skb->len - RNONCE_SIZE
     * Both are within [skb->data, skb->tail). */
    BUILD_BUG_ON(RNONCE_SIZE != 8);
    memcpy(rnonce, skb->data + skb->len - RNONCE_SIZE, RNONCE_SIZE);

    /* ── Derive nonce — must happen before decrypt ── */
    derive_nonce(nonce, info->nonce_key, rnonce);

    /*
     * xchacha20poly1305_decrypt:
     *   src  = skb->data + offset
     *   len  = payload_len - RNONCE_SIZE  = ciphertext(N+8) + MAC(16)
     *   aad  = TRANS3_SIG
     *
     * After success, buffer contains: plaintext(N) ‖ SEQ(8)
     * MAC is verified — any tamper, replay, or wrong AAD → false.
     */
    mac_ok = xchacha20poly1305_decrypt(
                 skb->data + offset,
                 skb->data + offset,
                 (size_t)(payload_len - RNONCE_SIZE),
                 trans3_sig,   TRANS3_SIG_LEN,
                 nonce,
                 info->key);

    /* Wipe nonce immediately — no longer needed */
    memzero_explicit(nonce,  sizeof(nonce));
    memzero_explicit(rnonce, sizeof(rnonce));

    if (unlikely(!mac_ok))
        return NF_DROP;   /* wrong key / tampered / not a TRANS3 packet */

    /*
     * Compute original payload length:
     *   payload_len = orig_N + SEQ_SIZE + MAC_SIZE + RNONCE_SIZE
     *   orig_N      = payload_len - OVERHEAD
     *
     * SEQ is at: skb->data + offset + orig_N
     * This is always within bounds: orig_N >= 0 (checked above: payload_len >= OVERHEAD)
     */
    orig_payload_len = payload_len - OVERHEAD;

    /* ── Read and immediately wipe SEQ from the decrypted buffer ── */
    seq = get_unaligned_le64(skb->data + offset + orig_payload_len);
    memzero_explicit(skb->data + offset + orig_payload_len, SEQ_SIZE);

    if (unlikely(seq == 0)) {
        memzero_explicit(&seq, sizeof(seq));
        return NF_DROP;
    }

    /* ── Replay check AFTER MAC — prevents timing oracle ── */
    if (unlikely(!check_replay(seq))) {
        memzero_explicit(&seq, sizeof(seq));
        return NF_DROP;
    }
    memzero_explicit(&seq, sizeof(seq));

    /* ── Trim tail: remove SEQ(8) + MAC(16) + RNONCE(8) = OVERHEAD ──
     * New skb->len = original skb->len - OVERHEAD.
     * Verified: new_len > offset (orig_payload_len >= 0). */
    if (unlikely(pskb_trim(skb, (unsigned int)(skb->len - OVERHEAD))))
        return NF_DROP;

    /* ── Update UDP inner length ── */
    if (proto == IPPROTO_UDP) {
        struct iphdr  *iph  = ip_hdr(skb);
        struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + ihl * 4);
        udph->len = htons(ntohs(udph->len) - (uint16_t)OVERHEAD);
    }

    new_l4_len = old_l4_len - OVERHEAD;
    recalc_checksums(skb, new_l4_len, proto, ihl);
    return XT_CONTINUE;
}

/* =========================================================================
 * NETFILTER TARGET
 * ========================================================================= */
static unsigned int xt_trans3_target(struct sk_buff *skb,
                                      const struct xt_action_param *par)
{
    const struct xt_crypt_info *info = par->targinfo;
    return (info->mode == 1) ? handle_encrypt(skb, info)
                              : handle_decrypt(skb, info);
}

static int xt_trans3_checkentry(const struct xt_tgchk_param *par)
{
    const struct xt_crypt_info *info = par->targinfo;

    if (info->mode != 1 && info->mode != 2) {
        pr_err("[xt_TRANS3] invalid mode %u — use 1 (encrypt) or 2 (decrypt)\n",
               info->mode);
        return -EINVAL;
    }
    return 0;
}

static void xt_trans3_destroy(const struct xt_tgdtor_param *par)
{
    struct xt_crypt_info *info = (struct xt_crypt_info *)par->targinfo;
    memzero_explicit(info->key,       sizeof(info->key));
    memzero_explicit(info->nonce_key, sizeof(info->nonce_key));
}

static struct xt_target xt_trans3_reg = {
    .name       = "TRANS3",
    .revision   = 0,
    .family     = NFPROTO_IPV4,
    .table      = "mangle",
    .target     = xt_trans3_target,
    .targetsize = sizeof(struct xt_crypt_info),
    .checkentry = xt_trans3_checkentry,
    .destroy    = xt_trans3_destroy,
    .me         = THIS_MODULE,
};

/* =========================================================================
 * MODULE INIT / EXIT
 * ========================================================================= */
static int __init trans3_tg_init(void)
{
    int ret;

    /* Seed tx_seq away from zero — seq=0 is reserved as invalid */
    atomic64_set(&tx_seq, (int64_t)(ktime_get_real_ns() ^ get_random_u64()));
    rx_highest_seq = 0;
    memset(rx_bitmap, 0, sizeof(rx_bitmap));

    ret = xt_register_target(&xt_trans3_reg);
    if (ret < 0) {
        pr_err("[xt_TRANS3] Registration failed: %d\n", ret);
        return ret;
    }
    pr_info("[xt_TRANS3] loaded.\n");
    return 0;
}

static void __exit trans3_tg_exit(void)
{
    xt_unregister_target(&xt_trans3_reg);
    memzero_explicit(rx_bitmap, sizeof(rx_bitmap));
    pr_info("[xt_TRANS3] Unloaded.\n");
}

module_init(trans3_tg_init);
module_exit(trans3_tg_exit);
