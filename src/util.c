#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

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
