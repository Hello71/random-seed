#ifndef UTIL_H
#define UTIL_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "sha2.h"

#define GRND_NONBLOCK 0x01
#define GRND_RANDOM 0x02

/* The pool size is fixed at 4096 bits since Linux 2.6. */
#define RAND_POOL_SIZE 512
/* SHA-256 */
#define HASH_LEN 32
#define HASH_STR_LEN 65
/* The salt is the random data */
#define SALT_LEN RAND_POOL_SIZE

static inline bool streq(const char *s1, const char *s2) {
    return !strcmp(s1, s2);
}

ssize_t random_get(void *buf, size_t buflen, unsigned int flags);
size_t hex2mem(unsigned char *dest, size_t size, const char *src);
void mem2hex(char *dest, const void *src, size_t size);
void hash(const unsigned char salt[static SALT_LEN], unsigned char *out, const void *in, size_t size);
bool hash_match(const unsigned char digest[static HASH_LEN], const char *arg);

#endif
