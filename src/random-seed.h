#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#define MAGIC "RANDOM SEED FILE VERSION 1\n"

extern bool noperms;

struct random_seed {
    FILE *file;
#ifdef HAVE_UTIL_LINUX
    dev_t dev;
#endif
#ifdef HAVE_LIBUDEV
    struct udev_device *udev_dev;
#endif
};

bool load(const char *seed_path);
bool save(const char *seed_path, const unsigned char *random_buf);

/* defining noreturn in C99 is too hard */
void run(const char *mode, const char *seed_path);
