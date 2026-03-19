#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/random.h>   /* getrandom() */

#include <leancrypto/lc_hash.h>
#include <leancrypto/lc_sha256.h>
#include <leancrypto/lc_aead.h>
#include <leancrypto/lc_chacha20_poly1305.h>
#include <leancrypto/lc_memset_secure.h>

#define HIDDEN_DIR     "/etc/.file"
#define HIDDEN_KEYFILE "/etc/.file/file3"
#define RAW_KEY_SIZE   64
#define FILE_SIZE      136

/*
 * Key file layout (136 bytes):
 *   [ 0.. 15]  random prefix       (16 bytes)
 *   [16.. 39]  nonce               (24 bytes — first 12 used as ChaCha20-Poly1305 nonce,
 *                                              next  12 used as AAD)
 *   [40..103]  ciphertext          (64 bytes — encrypted raw_key)
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

/* Remplir un buffer avec des octets aléatoires via getrandom() (sécurisé) */
static int get_random_bytes_secure(void *buf, size_t len)
{
    size_t offset = 0;
    ssize_t ret;

    while (offset < len) {
        ret = getrandom((uint8_t*)buf + offset, len - offset, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        offset += ret;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <keyfile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Lire la clé brute depuis le fichier source */
    FILE *fin = fopen(argv[1], "rb");
    if (!fin) {
        fprintf(stderr, "[-] Key source not found: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    uint8_t raw_key[RAW_KEY_SIZE];
    if (fread(raw_key, 1, RAW_KEY_SIZE, fin) != RAW_KEY_SIZE) {
        fclose(fin);
        fprintf(stderr, "[-] Key source is invalid (expected %d bytes)\n",
                RAW_KEY_SIZE);
        return EXIT_FAILURE;
    }
    fclose(fin);

    /* Obtenir la clé maîtresse liée à la machine */
    uint8_t master_key[32];
    if (get_machine_key(master_key) != 0) {
        lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
        fprintf(stderr, "[-] Machine binding failed\n");
        return EXIT_FAILURE;
    }

    uint8_t final_buffer[FILE_SIZE];
    uint8_t *prefix     = final_buffer;        /* [0..15]   */
    uint8_t *nonce      = final_buffer + 16;   /* [16..39]  */
    uint8_t *ciphertext = final_buffer + 40;   /* [40..103] */
    uint8_t *mac        = final_buffer + 104;  /* [104..119]*/
    uint8_t *suffix     = final_buffer + 120;  /* [120..135]*/

    /* Générer les parties aléatoires avec getrandom() */
    if (get_random_bytes_secure(prefix, 16) != 0 ||
        get_random_bytes_secure(nonce,  24) != 0 ||
        get_random_bytes_secure(suffix, 16) != 0) {
        lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
        lc_memset_secure(master_key, 0, 32);
        fprintf(stderr, "[-] Failed to generate random data\n");
        return EXIT_FAILURE;
    }

    /* Scellement avec ChaCha20-Poly1305 */
    LC_CHACHA20_POLY1305_CTX_ON_STACK(ctx);
    lc_aead_setkey(ctx, master_key, 32, nonce, 12);  /* nonce[0..11] = IV */
    lc_aead_encrypt(ctx, raw_key, ciphertext, RAW_KEY_SIZE,
                    nonce + 12, 12, mac, 16);        /* AAD = nonce[12..23] */
    lc_aead_zero(ctx);
    lc_memset_secure(master_key, 0, 32);

    /* Créer le répertoire caché s'il n'existe pas */
    struct stat st;
    if (stat(HIDDEN_DIR, &st) == -1) {
        if (mkdir(HIDDEN_DIR, 0700) != 0) {
            lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
            fprintf(stderr, "[-] Cannot create directory %s\n", HIDDEN_DIR);
            return EXIT_FAILURE;
        }
    }

    /* Écrire le fichier scellé */
    FILE *fout = fopen(HIDDEN_KEYFILE, "wb");
    if (!fout) {
        lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
        fprintf(stderr, "[-] Cannot write key storage\n");
        return EXIT_FAILURE;
    }

    /* Permissions strictes : propriétaire seul en lecture/écriture */
    if (fchmod(fileno(fout), S_IRUSR | S_IWUSR) != 0) {
        fclose(fout);
        lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
        fprintf(stderr, "[-] Cannot set file permissions\n");
        return EXIT_FAILURE;
    }

    if (fwrite(final_buffer, 1, FILE_SIZE, fout) != FILE_SIZE) {
        fclose(fout);
        lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
        fprintf(stderr, "[-] Key storage write failed\n");
        return EXIT_FAILURE;
    }
    fclose(fout);

    lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
    printf("[+] Key sealed and locked at %s\n", HIDDEN_KEYFILE);
    return EXIT_SUCCESS;
}
