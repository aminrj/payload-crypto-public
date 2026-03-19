#ifndef _XT_TRANS3_H
#define _XT_TRANS3_H

#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
#endif

#define KEYFILE_PATH   "/etc/.file/file3"

/*
 * Wire format after encryption:
 *
 *   [ IP hdr ][ L4 hdr ][ ciphertext(payload + SEQ:8) ][ MAC:16 ][ RNONCE:8 ]
 *
 *   RNONCE  (8 bytes) — random, in clear, used to derive nonce
 *   SEQ     (8 bytes) — encrypted with payload (replay protection, hidden)
 *   MAC     (16 bytes)— Poly1305 authentication tag
 *
 * Overhead per packet: SEQ(8) + MAC(16) + RNONCE(8) = +32 bytes
 *
 * Nonce derivation:
 *   nonce[24] = blake2s(nonce_key[32], rnonce[8], outlen=24, inlen=8, keylen=32)
 *
 * AAD (Additional Authenticated Data):
 *   TRANS3_SIGNATURE — proprietary fixed string, authenticated by Poly1305.
 *   Any packet with wrong/missing signature fails MAC → silently dropped.
 */

#define RNONCE_SIZE    8    /* Random nonce, sent in clear            */
#define SEQ_SIZE       8    /* Sequence number, encrypted with payload */
#define MAC_SIZE      16    /* Poly1305 authentication tag             */
#define OVERHEAD      32    /* RNONCE + MAC + hidden SEQ in ciphertext */

/* Proprietary signature authenticated by Poly1305 MAC.
 * Any packet not produced by TRANS3 will fail MAC verification. */
#define TRANS3_SIG     "NEGENCRY.TRANS3.V1"
#define TRANS3_SIG_LEN 18

struct xt_crypt_info {
    uint8_t  key[32];       /* XChaCha20-Poly1305 key         */
    uint8_t  nonce_key[32]; /* Blake2s nonce derivation key   */
    uint8_t  mode;          /* 1 = encrypt   2 = decrypt      */
    uint8_t  __pad[7];
};

#endif /* _XT_TRANS3_H */
