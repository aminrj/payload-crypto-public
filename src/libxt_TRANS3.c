#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <leancrypto/lc_hash.h>
#include <leancrypto/lc_sha256.h>
#include <leancrypto/lc_aead.h>
#include <leancrypto/lc_chacha20_poly1305.h>
#include <leancrypto/lc_memset_secure.h>

#include "libxt_TRANS3.h"

#define RAW_KEY_SIZE  64
#define FILE_SIZE     136

enum { O_TRANS3_MODE = 0 };
enum { FLAG_MODE     = 1 << 0 };

static const struct option trans3_opts[] = {
    { .name = "mode", .has_arg = true, .val = O_TRANS3_MODE },
    { NULL },
};

/* =========================================================================
 * MACHINE KEY DERIVATION — SHA-256 of /etc/machine-id
 * ========================================================================= */
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

/* =========================================================================
 * XTABLES CALLBACKS
 * ========================================================================= */
static void trans3_help(void)
{
    printf("TRANS3 — XChaCha20-Poly1305 authenticated encryption\n"
           "  +%d bytes overhead per packet (%d SEQ + %d MAC)\n"
           "  Replay protection: 4096-packet sliding window\n"
           "  --mode e    Encrypt (sender)\n"
           "  --mode d    Decrypt (receiver)\n",
           OVERHEAD, SEQ_SIZE, MAC_SIZE);
}

static void trans3_init(struct xt_entry_target *t)
{
    struct xt_crypt_info *info = (struct xt_crypt_info *)t->data;
    uint8_t buffer[FILE_SIZE];
    uint8_t master_key[32];
    uint8_t raw_key[RAW_KEY_SIZE];
    int     ret;

    FILE *f = fopen(KEYFILE_PATH, "rb");
    if (!f)
        xtables_error(PARAMETER_PROBLEM,
                      "TRANS3: key storage not found (%s)", KEYFILE_PATH);

    if (fread(buffer, 1, FILE_SIZE, f) != FILE_SIZE) {
        fclose(f);
        xtables_error(PARAMETER_PROBLEM, "TRANS3: key storage corrupt");
    }
    fclose(f);

    if (get_machine_key(master_key) != 0)
        xtables_error(PARAMETER_PROBLEM, "TRANS3: machine binding failed");

    LC_CHACHA20_POLY1305_CTX_ON_STACK(ctx);
    lc_aead_setkey(ctx, master_key, 32, buffer + 16, 12);
    ret = lc_aead_decrypt(ctx, buffer + 40, raw_key, 64,
                          buffer + 28, 12, buffer + 104, 16);
    lc_aead_zero(ctx);
    lc_memset_secure(master_key, 0, 32);

    if (ret != 0) {
        lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
        xtables_error(PARAMETER_PROBLEM,
                      "TRANS3: key verification failed (wrong machine?)");
    }

    memcpy(info->key,       raw_key,      32);
    memcpy(info->nonce_key, raw_key + 32, 32);
    lc_memset_secure(raw_key, 0, RAW_KEY_SIZE);
}

static int trans3_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
    (void)argv; (void)invert; (void)entry;
    struct xt_crypt_info *info = (struct xt_crypt_info *)(*target)->data;

    if (c == O_TRANS3_MODE) {
        if      (optarg[0] == 'e') info->mode = 1;
        else if (optarg[0] == 'd') info->mode = 2;
        else xtables_error(PARAMETER_PROBLEM,
                           "TRANS3: invalid mode — use 'e' (encrypt) or 'd' (decrypt)");
        *flags |= FLAG_MODE;
        return 1;
    }
    return 0;
}

static void trans3_check(unsigned int flags)
{
    if (!(flags & FLAG_MODE))
        xtables_error(PARAMETER_PROBLEM, "TRANS3: --mode e or --mode d required");
}

static void trans3_save(const void *entry, const struct xt_entry_target *target)
{
    (void)entry;
    const struct xt_crypt_info *info = (const void *)target->data;
    if      (info->mode == 1) printf(" --mode e ");
    else if (info->mode == 2) printf(" --mode d ");
}

/* =========================================================================
 * TARGET REGISTRATION
 * ========================================================================= */
static struct xtables_target trans3_reg = {
    .version       = XTABLES_VERSION,
    .name          = "TRANS3",
    .revision      = 0,
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct xt_crypt_info)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_crypt_info)),
    .help          = trans3_help,
    .final_check   = trans3_check,
    .init          = trans3_init,
    .parse         = trans3_parse,
    .save          = trans3_save,
    .extra_opts    = trans3_opts,
};

static __attribute__((constructor)) void init_xt_trans3(void)
{
    xtables_register_target(&trans3_reg);
}
