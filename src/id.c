// SPDX-License-Identifier: BSD-3-Clause

#include "config.h"

#include "id.h"
#include "random-seed.h"
#include "sha2.h"
#include "util.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifdef HAVE_LIBUDEV
#include <libudev.h>
#endif

#ifdef HAVE_UTIL_LINUX
#include <blkid.h>
#include <libmount.h>
#endif

static const char *MACHINE_ID_PATHS[] = THE_MACHINE_ID_PATHS;

bool ensure_rs_device(struct random_seed *rs, int fd) {
    assert(!major(rs->dev));
    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1) {
        perror("warning: failed getting seed device");
        return false;
    }
    memcpy(&rs->dev, &statbuf.st_dev, sizeof(dev_t));
    return true;
}

#ifdef HAVE_LIBUDEV
static struct udev *udev;

bool ensure_udev_device(struct random_seed *rs) {
    if (!udev)
        udev = udev_new();
    if (!udev) {
        fputs("error initializing libudev\n", stderr);
        return false;
    }
    if (!major(rs->dev)) {
        assert(rs->file);
        if (!ensure_rs_device(rs, fileno(rs->file)))
            return false;
    }
    if (!rs->udev_dev)
        rs->udev_dev = udev_device_new_from_devnum(udev, 'b', rs->dev);
    return !!rs->udev_dev;
}

const char *get_fs_uuid_udev(struct random_seed *rs) {
    if (!ensure_udev_device(rs))
        return NULL;
    return udev_device_get_property_value(rs->udev_dev, "ID_FS_UUID_ENC");
}

const char *get_drive_id(struct random_seed *rs) {
    if (!ensure_udev_device(rs))
        return NULL;
    return udev_device_get_property_value(rs->udev_dev, "ID_SERIAL");
}
#endif

#ifdef HAVE_UTIL_LINUX
const char *get_fs_uuid_util_linux(struct random_seed *rs) {
    (void)rs;
    fputs("error: util linux not implemented\n", stderr);
    return NULL;
}
#endif

#if defined(HAVE_LIBUDEV) && defined(HAVE_UTIL_LINUX)
const char *get_fs_uuid(struct random_seed *rs) {
    const char *rv = get_fs_uuid_udev(rs);
    if (!rv)
        rv = get_fs_uuid_util_linux(rs);
    return rv;
}
#elif defined(HAVE_LIBUDEV)
const char *get_fs_uuid(struct random_seed *rs) {
    return get_fs_uuid_udev(rs);
}
#elif defined(HAVE_UTIL_LINUX)
const char *get_fs_uuid(struct random_seed *rs) {
    return get_fs_uuid_util_linux(rs);
}
#endif

static char *really_get_machine_id() {
    FILE *machine_id_file;
    for (size_t i = 0; i < ARRAY_SIZE(MACHINE_ID_PATHS); i++) {
        machine_id_file = fopen(MACHINE_ID_PATHS[i], "r");
        if (!machine_id_file)
            fprintf(stderr, "warning: failed to open machine id %s: %s\n", MACHINE_ID_PATHS[i], strerror(errno));
    }
    if (!machine_id_file) {
        fputs("error: failed to open all machine id files\n", stderr);
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

const char *get_machine_id() {
    static char *c_machine_id;
    if (!c_machine_id)
        c_machine_id = really_get_machine_id();
    return c_machine_id;
}

bool get_fs_id(fsid_t *fs_id, int seed_fd) {
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
            return true;
        default:
            fprintf(stderr, "error: filesystem type 0x%08x does not have consistent f_fsid\n", (unsigned int)statfs_buf.f_type);
            return false;
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
