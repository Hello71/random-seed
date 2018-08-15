// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "id.h"
#include "util.h"

#ifdef HAVE_UDEV

#endif

#ifdef HAVE_UTIL_LINUX

#endif

static char *really_get_machine_id() {
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
        return NULL;
    }

    char *machine_id = NULL;
    size_t machine_id_len = 0;
    if (getdelim(&machine_id, &machine_id_len, '\0', machine_id_file) == -1) {
        fputs("error reading machine id file\n", stderr);
        free(machine_id);
        return NULL;
    }

    return machine_id;
}

size_t get_machine_id(char **machine_id) {
    static char *c_machine_id;
    if (!c_machine_id)
        c_machine_id = really_get_machine_id();
    *machine_id = c_machine_id;
    return strlen(*machine_id);
}

size_t get_fs_id(fsid_t *fs_id, int seed_fd) {
    struct statfs statfs_buf;
    if (fstatfs(seed_fd, &statfs_buf) == -1) {
        perror("error: statfs seed file: %s");
        return false;
    }

    switch (statfs_buf.f_type) {
        case 0x9123683e: // BTRFS_SUPER_MAGIC
        case 0xef53: // EXT2_SUPER_MAGIC == EXT3_SUPER_MAGIC == EXT4_SUPER_MAGIC
        case 0x3153464a: // JFS_SUPER_MAGIC
        case 0x5346544e: // NTFS_SB_MAGIC
        case 0x52654973: // REISERFS_SUPER_MAGIC
        case 0x24051905: // UBIFS_SUPER_MAGIC
            memcpy(fs_id, &statfs_buf.f_fsid, sizeof(fsid_t));
            return sizeof(fsid_t);
        default:
            fprintf(stderr, "error: filesystem type 0x%08x does not have consistent f_fsid\n", (unsigned int)statfs_buf.f_type);
            return 0;
    }
}

void hash(const unsigned char salt[static SALT_LEN], unsigned char out[static HASH_LEN], const void *in, size_t size) {
    assert(size < INT_MAX - SALT_LEN - 100);
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, salt, SALT_LEN);
    sha256_update(&ctx, in, (unsigned int)size);
    sha256_final(&ctx, out);
}
