#include "id.h"
#include "musl-libgen-c.h"
#include "random-seed.h"
#include "util.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static const char *HEX_CHARS = "0123456789abcdef";

/** Encode hex.
 *
 * \param dest where to store the encoded data (must have at least size*2+1 bytes)
 * \param src the data to encode
 * \param size the number of bytes to encode
 */
static void mem2hex(char *dest, const void *src, size_t size) {
    size_t i;
    for (i = 0; i < size; i++) {
        unsigned char c = *((const unsigned char *)src + i);
        dest[2*i] = HEX_CHARS[c >> 4];
        dest[2*i+1] = HEX_CHARS[c & 0xf];
    }
    dest[2*i] = '\0';
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

static void hash_str(const unsigned char salt[static SALT_LEN], char hash_out[static HASH_STR_LEN], const void *buf, size_t buflen) {
    unsigned char digest[HASH_LEN];
    hash(salt, digest, buf, buflen);
    mem2hex(hash_out, digest, HASH_LEN);
}

/**
 * Save entropy to disk.
 *
 * \param seed_path the seed file path
 * \param random_buf the random buffer. if NULL, get our own entropy.
 * \return true means saved successfully, false means received EINTR
 */
bool save(const char *seed_path, const unsigned char *random_ptr) {
    assert(seed_path);

    bool rv = false;

    unsigned char random_buf[RAND_POOL_SIZE];
    if (!random_ptr) {
        if (!get_rand_pool(random_buf))
            return false;
        random_ptr = random_buf;
    }

    const char *machine_id = get_machine_id(&machine_id);
    if (!machine_id)
        return false;
    char machine_id_hash[HASH_STR_LEN];
    hash_str(random_ptr, machine_id_hash, machine_id, strlen(machine_id));

    struct random_seed rs = {0};

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

    int seed_dir_fd = open(seed_dir, O_RDONLY | O_DIRECTORY);
    if (seed_dir_fd == -1) {
        perror("error opening seed directory");
        goto out;
    }

    fsid_t fs_id;
    bool have_fs_id = get_fs_id(&fs_id, seed_dir_fd);
#ifdef HAVE_FS_UUID
    (void)have_fs_id;
#else
    if (!have_fs_id) {
        fputs("error getting fs id\n", stderr);
        return false;
    }
#endif
    char fs_id_hash[HASH_STR_LEN];
    hash_str(random_ptr, fs_id_hash, &fs_id, sizeof(fs_id));

#ifdef HAVE_FS_UUID
    ensure_rs_device(&rs, seed_dir_fd);
    char fs_uuid_hash[HASH_STR_LEN];
    {
        const char *fs_uuid = get_fs_uuid(&rs);
        if (!fs_uuid) {
            fputs("error getting fs uuid\n", stderr);
            return false;
        }
        hash_str(random_ptr, fs_uuid_hash, fs_uuid, strlen(fs_uuid));
    }
#endif

#ifdef HAVE_LIBUDEV
    bool have_drive_id = false;
    char drive_id_hash[HASH_STR_LEN];
    {
        const char *drive_id = get_drive_id(&rs);
        if (drive_id) {
            have_drive_id = true;
            hash_str(random_ptr, drive_id_hash, drive_id, strlen(drive_id));
        }
    }
#endif

    {
        int seed_fd = openat(seed_dir_fd, seed_name_new, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (seed_fd == -1) {
            perror("error opening new seed file");
            goto err;
        }
        rs.file = fdopen(seed_fd, "w");
        if (!rs.file) {
            perror("error converting seed file fd to stream");
            goto err;
        }
    }

    if (fwrite(random_ptr, 1, RAND_POOL_SIZE, rs.file) != RAND_POOL_SIZE
            || fputs(MAGIC, rs.file) == EOF
            || fputs("machine-id ", rs.file) == EOF
            || fputs(machine_id_hash, rs.file) == EOF
#ifdef HAVE_FS_UUID
            || fputs("\nfs-uuid ", rs.file) == EOF
            || fputs(fs_uuid_hash, rs.file) == EOF
            || fputs("\nfs-id ", rs.file) == EOF
            || fputs(fs_id_hash, rs.file) == EOF
#else
            || (have_fs_id ? fputs("\nfs-id ", rs.file) == EOF : 0)
            || (have_fs_id ? fputs(fs_id_hash, rs.file) == EOF : 0)
#endif
#ifdef HAVE_LIBUDEV
            || (have_drive_id ? fputs("\ndrive-id ", rs.file) == EOF : 0)
            || (have_drive_id ? fputs(drive_id_hash, rs.file) == EOF : 0)
#endif
            || fputs("\ndone\n", rs.file) == EOF) {
        fputs("error writing new seed file\n", stderr);
        goto err;
    }

    if (fflush(rs.file) == EOF) {
        perror("error flushing new seed file");
        goto err;
    }
    if (fsync(fileno(rs.file)) == -1) {
        perror("error syncing new seed file");
        goto err;
    }
    if (renameat(seed_dir_fd, seed_name_new, seed_dir_fd, seed_name) == -1) {
        perror("error installing new seed file");
        goto err;
    }
    if (fclose(rs.file) == EOF) {
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
    if (rs.file) {
        fclose(rs.file);
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

