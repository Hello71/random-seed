// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "config.h"

#include "id.h"
#include "musl-libgen-c.h"
#include "util.h"

// musl forbids include/linux
#define RNDADDENTROPY	_IOW( 'R', 0x03, int [2] )

/* 3 hours */
#define DAEMONIZE_SLEEP_TIME (3*60*60)

/* random pool is always the same size, so use a fixed size array */
struct rand_pool_info_ {
        int entropy_count;
        int buf_size;
        uint32_t buf[RAND_POOL_SIZE / sizeof(uint32_t)];
};

static const char MAGIC[] = "RANDOM SEED FILE VERSION 1\n";

static sig_atomic_t sigint = 0;
static sig_atomic_t sigterm = 0;

static bool noperms = false;

static inline void usage() {
    puts("usage: random-seed MODE FILE");
    puts("see random-seed(8) for more information.");
}

static bool run_seed_file_cmd(const char *cmd, const unsigned char *salt, FILE *seed_file) {
#define HASH_ID_CMD(my_cmd, type, fn, data_accessor, ...) \
    do { \
        if (!streq(cmd, my_cmd)) \
            break; \
        char *arg = strtok(NULL, " \t"); \
        if (!arg) { \
            fputs("error parsing seed file: expected argument " \
                  "to '" my_cmd "'\n", stderr); \
            return false; \
        } \
        type fn ## _buf; \
        unsigned char fn ## _hash[HASH_LEN]; \
        size_t sz = fn(&fn ## _buf, ##__VA_ARGS__); \
        if (sz == 0) { \
            fputs("error getting " my_cmd " hash\n", stderr); \
            return false; \
        } \
        hash(salt, fn ## _hash, data_accessor fn ## _buf, sz); \
        unsigned char theirdigest[HASH_LEN]; \
        if (hex2mem(theirdigest, HASH_LEN, arg) == 0) { \
            fputs("error decoding hex hash\n", stderr); \
            exit(1); \
        } \
        if (memcmp(fn ## _hash, theirdigest, HASH_LEN)) { \
            fputs(my_cmd " hash does not match\n", stderr); \
            return false; \
        } \
        return true; \
    } while (0)

    HASH_ID_CMD("machine-id", char *, get_machine_id, );
    HASH_ID_CMD("fs-id", fsid_t, get_fs_id, &, fileno(seed_file));
#if defined(HAVE_LIBUDEV) || defined(HAVE_UTIL_LINUX)
    HASH_ID_CMD("fs-uuid", char *, get_fs_uuid, fileno(seed_file));
#else
    if (streq(cmd, "fs-uuid")) {
        fputs("error: fs-uuid not supported by this random-seed\n", stderr);
        return false;
    }
#endif
#ifdef HAVE_LIBUDEV
    HASH_ID_CMD("drive-id", char *, get_drive_id, fileno(seed_file));
#else
    if (streq(cmd, "drive-id")) {
        fputs("error: drive-id not supported by this random-seed\n", stderr);
        return false;
    }
#endif
    fprintf(stderr, "error parsing seed file: unsupported command: %s\n", cmd);
    return false;
}

static bool load(FILE *seed_file) {
    bool credit_entropy = true;

    struct rand_pool_info_ rpi = {
        .entropy_count = RAND_POOL_SIZE * CHAR_BIT,
        .buf_size = RAND_POOL_SIZE,
        .buf = { 0 }
    };

    uint64_t linenum = 0;
    char *line = NULL;
    size_t n = 0;
    bool done = false;

    if (fread(&rpi.buf, 1, RAND_POOL_SIZE, seed_file) != RAND_POOL_SIZE) {
        if (feof(seed_file)) {
            fputs("premature EOF on seed file\n", stderr);
        } else if (ferror(seed_file)) {
            fputs("error reading from seed file\n", stderr);
        }
        // else: we got signalled, so return to main loop to quit or whatever
        return false;
    }

    unsigned char *salt = (unsigned char *)rpi.buf;

    while (1) {
        errno = 0;
        ssize_t line_length = getline(&line, &n, seed_file);
        if (line_length == -1) {
            if (errno) {
                perror("error reading from seed file");
                credit_entropy = false;
            }
            break;
        }

        linenum++;

        if (linenum == 1) {
            if (streq(line, MAGIC)) {
                continue;
            } else {
                fputs("error parsing seed file: invalid magic\n", stderr);
                credit_entropy = false;
                break;
            }
        }

        char *nul = memchr(line, '\0', (size_t)line_length);
        if (nul) {
            fprintf(stderr, "error parsing seed file: encountered NUL byte in commands line %zu char %zu\n", linenum, nul - line + 1);
            credit_entropy = false;
            break;
        }

        char *cmd = strtok(line, " \t\n");
        if (!cmd)
            continue;

#ifdef DEBUG
        fprintf(stderr, "executing command: %s\n", cmd);
#endif

        if (streq(cmd, "done")) {
            done = true;
            continue;
        }

        if (!run_seed_file_cmd(cmd, salt, seed_file)) {
            credit_entropy = false;
            break;
        }
    }

    if (!linenum) {
        fputs("seed file has no commands, assuming legacy format. disabling entropy credit\n", stderr);
        credit_entropy = false;
    }

    if (credit_entropy && !done) {
        fputs("missing done command, random seed file probably truncated. disabling entropy credit\n", stderr);
        credit_entropy = false;
    }

    int random_fd = open("/dev/random", O_RDWR, 0);
    if (random_fd == -1) {
        perror("error opening /dev/random");
        exit(1);
    }

    if (credit_entropy) {
        if (ioctl(random_fd, RNDADDENTROPY, &rpi) == -1) {
            perror("ioctl(RNDADDENTROPY)");
            if (errno == EPERM) {
                fputs("Continuing without crediting entropy.\n", stderr);
                noperms = true;
            }
            credit_entropy = false;
        }
    }

    if (!credit_entropy) {
        if (write(random_fd, &rpi.buf, RAND_POOL_SIZE) != RAND_POOL_SIZE) {
            fputs("error writing entropy to /dev/random\n", stderr);
            exit(1);
        }
    }

    return credit_entropy;
}

static bool get_rand_pool(unsigned char *buf) {
    size_t rand_bytes_gotten = 0;

    do {
        long this_rand_bytes_gotten = random_get(buf + rand_bytes_gotten, RAND_POOL_SIZE - rand_bytes_gotten, 0);
        if (this_rand_bytes_gotten == -1) {
            switch (errno) {
                case EAGAIN: continue;
                case EINTR: return false;
                default:
                    perror("getrandom");
                    exit(1);
            }
        } else {
            rand_bytes_gotten += (size_t)this_rand_bytes_gotten;
        }
    } while (rand_bytes_gotten < RAND_POOL_SIZE);

    return true;
}

/**
 * Save entropy to disk.
 *
 * \param seed_path the seed file path
 * \param random_buf the random buffer. if NULL, get our own entropy.
 * \return true means saved successfully, false means received EINTR
 */
static bool save(const char *seed_path, unsigned char *random_buf) {
    assert(seed_path);

    bool rv = false;

    unsigned char *random_ptr;
    if (random_buf) {
        random_ptr = random_buf;
    } else {
        random_ptr = alloca(RAND_POOL_SIZE);
        if (!get_rand_pool(random_ptr))
            return false;
    }

#define GET_HASH_STR(type, hash_access, name, ...) \
    char name ## _hash[HASH_STR_LEN]; \
    do { \
        type name ## _buf; \
        size_t name ## _len = get_ ## name(&name ## _buf, ##__VA_ARGS__); \
        if (!name ## _len) { \
            fputs("error obtaining " #name " \n", stderr); \
            return false; \
        } \
        unsigned char name ## _digest[HASH_LEN]; \
        hash(random_ptr, name ## _digest, hash_access name ## _buf, name ## _len); \
        mem2hex(name ## _hash, name ## _digest, HASH_LEN); \
    } while (0)

    GET_HASH_STR(char *, , machine_id);

    int seed_dir_fd = -1;
    int seed_fd = -1;
    FILE *seed_file = NULL;

    char *seed_path_tmp = strdup(seed_path);
    const char *seed_dir, *seed_name;
    char *seed_path_last_slash = strrchr(seed_path_tmp, '/');
    if (seed_path_last_slash) {
        *seed_path_last_slash = '\0';
        seed_dir = seed_path_tmp;
        seed_name = seed_path_last_slash + 1;
    } else {
        free(seed_path_tmp);
        seed_path_tmp = NULL;
        seed_dir = ".";
        seed_name = seed_path;
    }
    char *seed_name_new = NULL;

    if (asprintf(&seed_name_new, ".%s.new", seed_name) == -1) {
        fputs("out of memory\n", stderr);
        goto out;
    }

    seed_dir_fd = open(seed_dir, O_RDONLY | O_DIRECTORY);
    if (seed_dir_fd == -1) {
        perror("error opening seed directory");
        goto out;
    }

    GET_HASH_STR(fsid_t, &, fs_id, seed_dir_fd);
#ifdef HAVE_LIBUDEV
    GET_HASH_STR(char *, , drive_id, seed_dir_fd);
#endif
#if defined(HAVE_LIBUDEV) || defined(HAVE_UTIL_LINUX)
    GET_HASH_STR(char *, , fs_uuid, seed_dir_fd);
#endif

    seed_fd = openat(seed_dir_fd, seed_name_new, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (seed_fd == -1) {
        perror("error opening new seed file");
        goto err;
    }
    seed_file = fdopen(seed_fd, "w");
    if (!seed_file) {
        perror("error converting seed file fd to stream");
        goto err;
    }

    if (fwrite(random_ptr, 1, RAND_POOL_SIZE, seed_file) != RAND_POOL_SIZE
            || fputs(MAGIC, seed_file) == EOF
            || fputs("machine-id ", seed_file) == EOF
            || fputs(machine_id_hash, seed_file) == EOF
            || fputs("\nfs-id ", seed_file) == EOF
            || fputs(fs_id_hash, seed_file) == EOF
            || fputs("\ndone\n", seed_file) == EOF) {
        fputs("error writing new seed file\n", stderr);
        goto err;
    }

    if (fflush(seed_file) == EOF) {
        perror("error flushing new seed file");
        goto err;
    }
    if (fsync(seed_fd) == -1) {
        perror("error syncing new seed file");
        goto err;
    }
    if (renameat(seed_dir_fd, seed_name_new, seed_dir_fd, seed_name) == -1) {
        perror("error installing new seed file");
        goto err;
    }
    if (fclose(seed_file) == EOF) {
        perror("error closing new seed file");
        goto err;
    }
    if (fsync(seed_dir_fd) == -1) {
        perror("error syncing seed directory");
        goto out;
    }

    rv = true;
    goto out;

err:
    if (seed_file) {
        fclose(seed_file);
        if (unlinkat(seed_dir_fd, seed_name_new, 0) == -1) {
            perror("error removing temporary seed file");
            rv = false;
        }
    }

out:
    if (seed_dir_fd != -1) {
        if (close(seed_dir_fd) == -1) {
            perror("error closing seed directory");
            rv = false;
        }
    }

    free(seed_path_tmp);
    free(seed_name_new);

    return rv;
}

static void sighandler(int signum) {
    switch (signum) {
        case SIGHUP:
            // do nothing; we just needed to interrupt sleep
            break;
        case SIGINT:
            sigint = 1;
            break;
        case SIGTERM:
            sigterm = 1;
            break;
        default:
            abort();
    }
}

noreturn static void run(const char *mode, const char *seed_path) {
    FILE *seed_file;
    int exit_status = 0;

    if (streq(mode, "load")) {
        bool refresh_seed = true;

        if (streq(seed_path, "-")) {
            fputs("warning: cannot refresh stdin seed\n", stderr);
            seed_file = stdin;
            refresh_seed = false;
        } else {
            seed_file = fopen(seed_path, "r");
        }
        if (!seed_file) {
            perror("error opening seed file");
            exit(1);
        }
        if (!load(seed_file)) {
            if (noperms)
                exit_status = 15;
            else
                exit_status = 1;
        }
        if (refresh_seed) {
            unsigned char random_buf[RAND_POOL_SIZE];
            unsigned char *random_ptr = random_buf;
            switch (random_get(random_buf, RAND_POOL_SIZE, GRND_NONBLOCK)) {
                case RAND_POOL_SIZE:
                    goto save;
                case -1:
                    if (errno != EAGAIN) {
                        perror("getrandom");
                        exit(1);
                    }
            }
            if (daemon(0, 1) == -1) {
                perror("error daemonizing, continuing without");
            }
            close(0);
            close(1);
            random_ptr = NULL;
save:       if (!save(seed_path, random_ptr))
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
        seed_file = fopen(seed_path, "r");
        if (!seed_file) {
            perror("error opening seed file");
            exit(3);
        }
        if (!load(seed_file))
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
    run(mode, seed_path);
}
