// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <sys/types.h>

#include "random-seed.h"
#include "util.h"

#if defined(HAVE_LIBUDEV) || defined(HAVE_UTIL_LINUX)
#define HAVE_FS_UUID
bool set_rs_device(struct random_seed *rs, int fd);
const char *get_fs_uuid(struct random_seed *rs);
#endif

#ifdef HAVE_LIBUDEV
const char *get_drive_id(struct random_seed *rs);
#endif

const char *get_machine_id();
bool get_fs_id(fsid_t *fs_id, int fd);
void hash(const unsigned char salt[static SALT_LEN], unsigned char *out, const void *in, size_t size);
