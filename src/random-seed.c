// SPDX-License-Identifier: BSD-3-Clause

#include "config.h"

#include "random-seed.h"
#include "util.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* 3 hours */
#define DAEMONIZE_SLEEP_TIME (3*60*60)

static sig_atomic_t sigint = 0;
static sig_atomic_t sigterm = 0;

static void sighandler(int signum) {
    switch (signum) {
        case SIGHUP: /* do nothing; we just needed to interrupt sleep */ break;
        case SIGINT: sigint = 1; break;
        case SIGTERM: sigterm = 1; break;
        default: abort();
    }
}

void run(const char *mode, const char *seed_path) {
    int exit_status = 0;

    if (streq(mode, "load")) {
        if (!load(seed_path)) {
            if (noperms)
                exit_status = 15;
            else
                exit_status = 1;
        }
        if (streq(seed_path, "-")) {
            fputs("warning: cannot refresh stdin seed\n", stderr);
        } else {
            unsigned char random_buf[RAND_POOL_SIZE];
            unsigned char *random_ptr = random_buf;
            switch (random_get(random_buf, RAND_POOL_SIZE, GRND_NONBLOCK)) {
                case RAND_POOL_SIZE:
                    break;
                case -1:
                    if (errno != EAGAIN) {
                        perror("getrandom");
                        exit(1);
                    }
                    FALLS_THROUGH;
                default:
                    if (daemon(0, 1) == -1) {
                        perror("error daemonizing, continuing without");
                    }
                    close(0);
                    close(1);
                    random_ptr = NULL;
            }
            if (!save(seed_path, random_ptr))
                exit_status = 1;
        }
        exit(exit_status);
    } else if (streq(mode, "save")) {
        exit(!save(seed_path, NULL));
    } else if (streq(mode, "daemonize")) {
        if (streq(seed_path, "-")) {
            fputs("error: seed_path cannot be - for daemonize\n", stderr);
            exit(2);
        }
        if (!load(seed_path))
            fputs("warning: failed to load initial entropy\n", stderr);

        struct sigaction sa;
        sa.sa_handler = sighandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);

        if (daemon(seed_path[0] != '/', 1) == -1) {
            perror("error daemonizing");
            exit(1);
        }
        close(0);
        close(1);
        // don't close stderr because we log there

        while (true) {
            if (sigint)
                exit(exit_status);
            if (!save(seed_path, NULL)) {
                exit_status = 1;
                fputs("an error occurred while saving, trying again later\n", stderr);
            }
            if (sigterm)
                exit(exit_status);
            sleep(DAEMONIZE_SLEEP_TIME);
        }
    } else if (streq(mode, "daemonise")) {
        fputs("invalid mode (did you mean `daemonize'?)\n", stderr);
        exit(2);
    } else {
        fputs("invalid mode, expected load, save, or daemonize\n", stderr);
        exit(2);
    }
}
