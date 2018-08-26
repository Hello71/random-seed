#include "config.h"

#include "id.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define RNDADDENTROPY   _IOW( 'R', 0x03, int [2] )

/* random pool is always the same size, so use a fixed size array */
struct rand_pool_info_ {
    int entropy_count;
    int buf_size;
    uint32_t buf[RAND_POOL_SIZE / sizeof(uint32_t)];
};

bool noperms;

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
 * \return 0 if an error occurred, otherwise size
 */
static size_t hex2mem(unsigned char *dest, size_t size, const char *src) {
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

static bool match_cmd_with_arg(const char *cmd, const char *my_cmd, char **arg) {
    if (!streq(cmd, my_cmd))
        return false;

    *arg = strtok(NULL, " \t");
    if (!arg) {
        fprintf(stderr, "error parsing seed file: expected argument to '%s'\n", my_cmd);
        return false;
    }

    return true;
}

static bool hash_match(const unsigned char salt[static SALT_LEN], const void *buf, size_t buflen, const char theirhash[static HASH_STR_LEN]) {
    if (streq(theirhash, "none")) {
        return buf == NULL;
    }
    if (!buf)
        return false;
    unsigned char mydigest[HASH_LEN];
    hash(salt, mydigest, buf, buflen);
    unsigned char theirdigest[HASH_LEN];
    if (hex2mem(theirdigest, HASH_LEN, theirhash) != HASH_LEN) {
        fputs("error decoding hex hash\n", stderr);
        return false;
    }
    if (memcmp(mydigest, theirdigest, HASH_LEN)) {
        fputs("hash does not match\n", stderr);
        return false;
    }
    return true;
}

bool load(const char *seed_path) {
    struct random_seed rs = {0};

    if (streq(seed_path, "-")) {
        rs.file = stdin;
    } else {
        rs.file = fopen(seed_path, "r");
        if (!rs.file) {
            perror("error opening seed file");
            exit(1);
        }
    }

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

    if (fread(&rpi.buf, 1, RAND_POOL_SIZE, rs.file) != RAND_POOL_SIZE) {
        if (feof(rs.file)) {
            fputs("premature EOF on seed file\n", stderr);
        } else if (ferror(rs.file)) {
            fputs("error reading from seed file\n", stderr);
        }
        // else: we got signalled, so return to main loop to quit or whatever
        return false;
    }

    unsigned char *salt = (unsigned char *)rpi.buf;

    while (1) {
        errno = 0;
        ssize_t line_length = getline(&line, &n, rs.file);
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
            /* empty line */
            continue;

        if (streq(cmd, "done")) {
            done = true;
            break;
        }

        char *arg;

        if (match_cmd_with_arg(cmd, "machine-id", &arg)) {
            const char *machine_id = get_machine_id(&machine_id);
            if (!machine_id) {
                credit_entropy = false;
                break;
            }
            return hash_match(salt, machine_id, strlen(machine_id), arg);
        }

        if (match_cmd_with_arg(cmd, "fs-id", &arg)) {
            fsid_t fs_id;
            credit_entropy = hash_match(
                salt,
                get_fs_id(&fs_id, fileno(rs.file)) ? &fs_id : NULL,
                sizeof(fs_id),
                arg
            );
            break;
        }

#if defined(HAVE_LIBUDEV) || defined(HAVE_UTIL_LINUX)
        if (match_cmd_with_arg(cmd, "fs-uuid", &arg)) {
            const char *fs_uuid = get_fs_uuid(&rs);
            credit_entropy = hash_match(salt, fs_uuid, fs_uuid ? strlen(fs_uuid) : 0, arg);
            break;
        }
#else
        if (streq(cmd, "fs-uuid")) {
            fputs("error: fs-uuid disabled at compile time\n", stderr);
            credit_entropy = false;
            break;
        }
#endif

#ifdef HAVE_LIBUDEV
        if (match_cmd_with_arg(cmd, "drive-id", &arg)) {
            const char *drive_id = get_drive_id(&rs);
            credit_entropy = hash_match(salt, drive_id, drive_id ? strlen(drive_id) : 0, arg);
            break;
        }
#else
        if (streq(cmd, "drive-id")) {
            fputs("error: drive-id disabled at compile time\n", stderr);
            credit_entropy = false;
            break;
        }
#endif

        fprintf(stderr, "error parsing seed file: unsupported command: %s\n", cmd);
        credit_entropy = false;
        break;
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

