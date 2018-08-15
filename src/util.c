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
    size_t i;
    for (i = 0; i < size; i++) {
        unsigned char c = *((const unsigned char *)src + i);
        dest[2*i] = HEX_CHARS[c >> 4];
        dest[2*i+1] = HEX_CHARS[c & 0xf];
    }
    dest[2*i] = '\0';
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
