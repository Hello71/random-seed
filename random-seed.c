/* Copyright 2018 Alex Xu (aka Hello71, alxu)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

static bool get_machine_id(unsigned char **machine_id) {
#ifdef MACHINE_ID_PATH
    FILE *machine_id_file = fopen(MACHINE_ID_PATH, "r");
#else
    const char *etc_machine_id = "/etc/machine-id";
    const char *var_lib_dbus_machine_id = "/var/lib/dbus/machine-id";
    FILE *machine_id_file = fopen(etc_machine_id, "r");
    if (!machine_id_file) {
        if (errno != ENOENT)
            fprintf(stderr, "error opening %s: %s, trying %s\n",
                    etc_machine_id, strerror(errno), var_lib_dbus_machine_id);
        machine_id_file = fopen(var_lib_dbus_machine_id, "r");
    }
#endif

    if (!machine_id_file) {
        perror("couldn't open any machine-id file, last error");
        *machine_id = NULL;
        return false;
    }

    size_t machine_id_len = 0;
    if (getdelim((char **)machine_id, &machine_id_len, '\0', machine_id_file) == -1) {
        fputs("error reading machine id file\n", stderr);
        *machine_id = NULL;
        return false;
    }

    return true;
}

static bool get_machine_id_hash(const unsigned char salt[static SALT_LEN], unsigned char machine_id_digest[static HASH_LEN]) {
    static unsigned char *c_machine_id;
    static size_t c_machine_id_len;
    if (!c_machine_id)
        c_machine_id_len = get_machine_id(&c_machine_id);
    if (!c_machine_id_len) {
        free(c_machine_id);
        c_machine_id = NULL;
        return false;
    }
    unsigned char c_machine_id_digest[HASH_LEN];
    hash(salt, c_machine_id_digest, c_machine_id, c_machine_id_len);
    memcpy(machine_id_digest, c_machine_id_digest, HASH_LEN);
    return true;
}

static inline bool get_fs_id_hash(const unsigned char salt[static SALT_LEN], unsigned char fsid_digest[static HASH_LEN], int seed_fd) {
    struct statfs statfs_buf;
    if (fstatfs(seed_fd, &statfs_buf) == -1) {
        fprintf(stderr, "error statfs seed file: %s, "
                "disabling entropy credit\n", strerror(errno));
        return false;
    }
    hash(salt, fsid_digest, &statfs_buf.f_fsid, sizeof(statfs_buf.f_fsid));
    return true;
}

static bool run_seed_file_cmd(const char *cmd, const unsigned char *salt, FILE *seed_file) {
    char *arg;
    if (streq(cmd, "machine-id")) {
        arg = strtok(NULL, " \t");
        if (!arg) {
            fputs("error parsing seed file: expected argument "
                  "to 'machine-id'\n", stderr);
            return false;
        }
        unsigned char machine_id_hash[HASH_LEN];
        if (!get_machine_id_hash(salt, machine_id_hash)) {
            fputs("error getting machine id hash, disabling entropy credit\n",
                  stderr);
            return false;
        }

        if (!hash_match(machine_id_hash, arg)) {
            fputs("machine-id does not match, disabling entropy credit\n",
                  stderr);
            return false;
        }
        return true;
    }

    if (streq(cmd, "fs-id")) {
        arg = strtok(NULL, " \t");
        if (!arg) {
            fputs("error parsing seed file: expected argument to 'fs-id'\n", stderr);
            return false;
        }
        unsigned char fs_id_hash[HASH_LEN];
        if (!get_fs_id_hash(salt, fs_id_hash, fileno(seed_file))) {
            fputs("error getting fs id hash, disabling entropy credit\n", stderr);
            return false;
        }

        if (!hash_match(fs_id_hash, arg)) {
            fputs("fs id does not match, disabling entropy credit\n", stderr);
            return false;
        }
        return true;
    }

    fprintf(stderr, "error parsing seed file: unsupported command: %s\n", cmd);
    return false;
}

static bool load(FILE *seed_file) {
    bool credit_entropy = true;

    struct rand_pool_info_ rpi = {
        .entropy_count = RAND_POOL_SIZE * 8,
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
        } else {
            fputs("short read from seed file\n", stderr);
        }
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

        char *nul = memchr(line, '\0', line_length);
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
    size_t rand_bits_gotten = 0;
    while (rand_bits_gotten < RAND_POOL_SIZE) {
        long this_rand_bits_gotten = random_get(buf + rand_bits_gotten, RAND_POOL_SIZE - rand_bits_gotten, 0);
        if (this_rand_bits_gotten < 0) {
            switch (errno) {
                case EAGAIN: continue;
                case EINTR: return false;
                default:
                    perror("getrandom");
                    exit(1);
            }
        } else {
            rand_bits_gotten += (size_t)this_rand_bits_gotten;
        }
    }
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
    char *seed_path_tmp = NULL;
    char *seed_name_new = NULL;

    unsigned char my_random_buf[RAND_POOL_SIZE];
    if (!random_buf) {
        if (!get_rand_pool(my_random_buf))
            return false;
        random_buf = my_random_buf;
    }

    unsigned char machine_id_digest[HASH_LEN];
    if (!get_machine_id_hash(random_buf, machine_id_digest)) {
        fputs("cannot obtain machine id, aborting save\n", stderr);
        return false;
    }
    char machine_id_hash[HASH_LEN*2+1];
    memset(machine_id_hash, 0, HASH_LEN*2);
    mem2hex(machine_id_hash, machine_id_digest, HASH_LEN);
    machine_id_hash[sizeof(machine_id_hash)-1] = '\0';

    int seed_dir_fd = -1;
    int seed_fd = -1;
    FILE *seed_file = NULL;

    seed_path_tmp = strdup(seed_path);

    seed_dir_fd = open(mydirname(seed_path_tmp), O_RDONLY | O_DIRECTORY);
    if (seed_dir_fd == -1) {
        perror("error opening seed directory");
        goto out;
    }

    unsigned char fs_id_digest[HASH_LEN];
    if (!get_fs_id_hash(random_buf, fs_id_digest, seed_dir_fd)) {
        fputs("cannot obtain machine id, aborting save\n", stderr);
        free(seed_path_tmp);
        return false;
    }
    char fs_id_hash[HASH_LEN*2+1];
    mem2hex(fs_id_hash, fs_id_digest, HASH_LEN);
    fs_id_hash[sizeof(fs_id_hash)-1] = '\0';

    strcpy(seed_path_tmp, seed_path);
    char *seed_name = mybasename(seed_path_tmp);
    size_t seed_name_new_len = strlen(seed_name) + 6;
    seed_name_new = malloc(seed_name_new_len);
    if (!seed_name_new) {
        fputs("out of memory\n", stderr);
        free(seed_path_tmp);
        return false;
    }
    assert(seed_name_new_len < INT_MAX);
    if ((size_t)snprintf(seed_name_new, seed_name_new_len, ".%s.new", seed_name) >= seed_name_new_len)
        abort();

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

    if (fwrite(random_buf, 1, RAND_POOL_SIZE, seed_file) != RAND_POOL_SIZE
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
            if (random_get(random_buf, sizeof(random_buf), GRND_NONBLOCK) == -1) {
                if (errno != EAGAIN) {
                    perror("getrandom");
                    exit(1);
                }
                daemon(0, 1);
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

        daemon(seed_path[0] != '/', 1);
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
