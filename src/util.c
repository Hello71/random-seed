// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

static inline signed char hexchr2int(char c) {
    /* No, nobody uses EBCDIC anymore. */
    return (c >= '0' && c <= '9') ? (c - '0') :
           (c >= 'a' && c <= 'f') ? (c - 'a' + 10) :
           (c >= 'A' && c <= 'F') ? (c - 'A' + 10) :
           -1;
}

/**
 * Decode hex.
 *
 * \param dest where to store the decoded data
 * \param size the maximum number of bytes to decode
 * \param src the hex-encoded data
 *
 * \return 0 if an error occurred, otherwise the number of bytes written to
 * dest
 */
size_t hex2mem(unsigned char *dest, size_t size, const char *src) {
#ifdef DEBUG
    fprintf(stderr, "hex decoding %zu bytes\n", size);
#endif
    size_t i;
    for (i = 0; i < size; i++) {
        int n1 = hexchr2int(src[2*i]);
        if (n1 < 0) return 0;
        int n2 = hexchr2int(src[2*i+1]);
        if (n2 < 0) return 0;
        dest[i] = (unsigned char)(n1 << 4 | n2);
    }
    return i;
}

static const char *HEX_CHARS = "0123456789abcdef";

/** Encode hex.
 *
 * \param dest where to store the encoded data (must have at least size*2+1 bytes)
 * \param src the data to encode
 * \param size the number of bytes to encode
 */
void mem2hex(char *dest, const void *src, size_t size) {
    for (size_t i = 0; i < size; i++) {
        unsigned char c = *((const unsigned char *)src + i);
        dest[2*i] = HEX_CHARS[c >> 4];
        dest[2*i+1] = HEX_CHARS[c & 0xf];
    }
    dest[size*2] = '\0';
}

void hash(const unsigned char salt[static SALT_LEN], unsigned char *out, const void *in, size_t size) {
    assert(size < INT_MAX - SALT_LEN - 100);
#ifdef DEBUG
    fprintf(stderr, "hashing %zu bytes starting with 0x%x ending with 0x%x\n", size, (int)((unsigned char*)in)[0], (int)((unsigned char*)in)[size-1]);
#endif
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, salt, SALT_LEN);
    sha256_update(&ctx, in, (unsigned int)size);
    sha256_final(&ctx, out);
}

static void print_hash(const unsigned char digest[static HASH_LEN]) {
#ifdef DEBUG
    char hash[HASH_LEN*2+1];
    mem2hex(hash, digest, HASH_LEN);
    fprintf(stderr, "hash: %s\n", hash);
#else
    (void)digest;
#endif
}

bool hash_match(const unsigned char digest[static HASH_LEN], const char *arg) {
    unsigned char theirdigest[HASH_LEN];
    if (hex2mem(theirdigest, sizeof(theirdigest), arg) == 0) {
        fputs("error decoding hex hash\n", stderr);
        exit(1);
    }
#ifdef DEBUG
    fprintf(stderr, "comparing hash, theirs: %s = 0x%02x..0x%02x, ours: 0x%02x..0x%02x\n", arg, (int)theirdigest[0], (int)theirdigest[HASH_LEN-1], (int)digest[0], (int)theirdigest[HASH_LEN-1]);
    fputs("  our ", stderr);
    print_hash(digest);
    fputs("their ", stderr);
    print_hash(theirdigest);
#endif
    return !memcmp(digest, theirdigest, HASH_LEN);
}

ssize_t random_get(void *buf, size_t buflen, unsigned int flags) {
    memset(buf, 0, buflen);

    long rv = syscall(SYS_getrandom, buf, buflen, flags);
    if (rv == -1) {
        if (errno == ENOSYS) {
            fputs("getrandom returned ENOSYS. random-seed requires Linux 3.17\n", stderr);
            exit(1);
        }
    } else {
        bool all_zero = true;
        if (buflen > 32) {
            for (size_t i = 0; i < buflen; i++) {
                if (((unsigned char *)buf)[i] != 0) {
                    all_zero = false;
                    break;
                }
            }
        }
        if (all_zero) {
            fputs("getrandom returned all zeros, probably broken\n", stderr);
            exit(1);
        }
    }

    return rv;
}
