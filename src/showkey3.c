#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <leancrypto/lc_hash.h>
#include <leancrypto/lc_sha256.h>
#include <leancrypto/lc_aead.h>
#include <leancrypto/lc_chacha20_poly1305.h>
#include <leancrypto/lc_memset_secure.h>

#include "libxt_TRANS3.h"

#define RAW_KEY_SIZE   64
#define FILE_SIZE      136

/*
 * Key file layout (136 bytes):
 *   [ 0.. 15]  random prefix       (16 bytes)
 *   [16.. 27]  nonce               (12 bytes → ChaCha20-Poly1305 IV)
 *   [28.. 39]  AAD                 (12 bytes → nonce[12..23])
 *   [40..103]  ciphertext          (64 bytes)
 *   [104..119] Poly1305 MAC        (16 bytes)
 *   [120..135] random suffix       (16 bytes)
 */

static int get_machine_key(uint8_t master_key[32])
{
    FILE  *f;
    char   machine_id[64] = {0};
    size_t len;

    f = fopen("/etc/machine-id", "r");
    if (!f) return -1;
    len = fread(machine_id, 1, sizeof(machine_id) - 1, f);
    fclose(f);
    if (len < 32) return -1;

    lc_hash(lc_sha256, (const uint8_t *)machine_id, len, master_key);
    return 0;
}

int main(void)
{
    uint8_t buffer[FILE_SIZE];
    uint8_t master_key[32];
    uint8_t raw_key[RAW_KEY_SIZE];
    int     ret;

    FILE *f = fopen(KEYFILE_PATH, "rb");
    if (!f) {
        fprintf(stderr, "[-] Key storage not found: %s\n", KEYFILE_PATH);
        return EXIT_FAILURE;
    }
    if (fread(buffer, 1, FILE_SIZE, f) != FILE_SIZE) {
        fclose(f);
        fprintf(stderr, "[-] Key storage is corrupt\n");
        return EXIT_FAILURE;
    }
    fclose(f);

    if (get_machine_key(master_key) != 0) {
        fprintf(stderr, "[-] Machine binding failed\n");
        return EXIT_FAILURE;
    }

    /* Unseal:
     *   buffer+16 → nonce  (12 bytes)
     *   buffer+28 → AAD    (12 bytes)
     *   buffer+40 → ct     (64 bytes)
     *   buffer+104→ MAC    (16 bytes)
     */
    LC_CHACHA20_POLY1305_CTX_ON_STACK(ctx);
    lc_aead_setkey(ctx, master_key, 32, buffer + 16, 12);
    ret = lc_aead_decrypt(ctx, buffer + 40, raw_key, 64,
                          buffer + 28, 12, buffer + 104, 16);
    lc_aead_zero(ctx);
    lc_memset_secure(master_key, 0, 32);

    if (ret != 0) {
        fprintf(stderr, "[-] Key verification failed (wrong machine?)\n");
        lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
        return EXIT_FAILURE;
    }

    printf("[+] Active key:\n");
    for (int i = 0; i < 64; i++) printf("%02x", raw_key[i]);
    printf("\n");

    lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
    return EXIT_SUCCESS;
}
