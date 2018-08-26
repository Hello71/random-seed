// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <sys/types.h>
#include <stdbool.h>
#include <string.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#ifdef HAVE_FUNC_ATTRIBUTE_FALLTHROUGH
#define FALLS_THROUGH __attribute__((fallthrough))
#else
#define FALLS_THROUGH (void)0
#endif

/* The pool size is fixed at 4096 bits since Linux 2.6. */
#define RAND_POOL_SIZE 512
/* SHA-256 */
#define HASH_LEN 32
#define HASH_STR_LEN 65
/* The salt is the random data */
#define SALT_LEN RAND_POOL_SIZE

#define GRND_NONBLOCK 0x01
#define GRND_RANDOM 0x02

static inline bool streq(const char *s1, const char *s2) {
    return !strcmp(s1, s2);
}

ssize_t random_get(void *buf, size_t buflen, unsigned int flags);
