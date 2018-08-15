// SPDX-License-Identifier: BSD-3-Clause

#ifndef FSID_H
#define FSID_H

#include <sys/types.h>

#include "util.h"

#if defined(HAVE_UDEV) || defined(HAVE_UTIL_LINUX)
size_t get_fs_uuid(char **fs_uuid, int seed_fd);
#endif
#ifdef HAVE_UDEV
size_t get_drive_id(char **drive_id, int seed_fd);
#endif
size_t get_machine_id(char **machine_id);
size_t get_fs_id(fsid_t *fs_id, int seed_fd);
void hash(const unsigned char salt[static SALT_LEN], unsigned char *out, const void *in, size_t size);

#endif
