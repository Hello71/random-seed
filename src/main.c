#include "config.h"

#include "random-seed.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>

static inline void usage() {
    puts("usage: random-seed MODE FILE");
    puts("see random-seed(8) for more information.");
}

static inline void caprlimit(int resource, rlim_t rlimit) {
    struct rlimit rlim;
    if (getrlimit(resource, &rlim) == -1) {
        perror("warning: couldn't get resource limit");
        return;
    }
    if (rlim.rlim_cur > rlimit) {
        rlim.rlim_cur = rlimit;
        if (setrlimit(resource, &rlim) == -1) {
            perror("warning: couldn't set resource limit");
            return;
        }
    }
}

int main(int argc, char *argv[]) {
    char *mode, *seed_path;

    switch (argc) {
        case 2:
            if (streq(argv[1], "-h") || streq(argv[1], "--help")) {
                usage();
                exit(0);
            }
            if (streq(argv[1], "-V") || streq(argv[1], "--version")) {
                printf("random-seed %s\n", PACKAGE_VERSION);
                exit(0);
            }
            mode = argv[1];
            seed_path = DEFAULT_SEED_PATH;
            break;
        case 3:
            mode = argv[1];
            seed_path = argv[2];
            break;
        default:
            fprintf(stderr, "error: invalid arguments\n");
            usage();
            exit(2);
    }

    umask(0);
    caprlimit(RLIMIT_DATA, 32*1024*1024);
    caprlimit(RLIMIT_FSIZE, 1*1024*1024);
    run(mode, seed_path);
}
