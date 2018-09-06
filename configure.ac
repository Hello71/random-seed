# SPDX-License-Identifier: BSD-3-Clause

AC_INIT(random-seed, 0.1)
AC_CONFIG_MACRO_DIRS([m4])

AC_LANG(C)
AC_PROG_CC
AC_PROG_CC_C99
AS_IF([test "$ac_cv_prog_cc_c99" = no], [
    AC_MSG_ERROR([a C99 compatible compiler is required])
])

AX_GCC_FUNC_ATTRIBUTE(fallthrough)

AC_ARG_ENABLE(unity,
    AC_HELP_STRING(--enable-unity, [enable unity build (similar to sqlite amalgamation, increases performance) [yes]]),
    [enable_unity=$enableval],
    [enable_unity=yes]
)
AS_CASE([$enable_unity],
    [no], [UNITY=],
    [yes], [UNITY=1],
    [AC_MSG_ERROR([invalid argument to --enable-unity])]
)
AC_SUBST(UNITY)

AC_ARG_WITH(udev,
    AC_HELP_STRING(--with-udev, [enable libudev support [auto]]),
    [with_udev=$withval],
    [with_udev=auto]
)
AS_CASE([$with_udev],
    [no], [],
    [yes], [
        PKG_CHECK_MODULES(LIBUDEV, libudev)
    ],
    [auto], [
        PKG_CHECK_MODULES(LIBUDEV, libudev, [with_udev=yes], [with_udev=no])
    ],
    [AC_MSG_ERROR([invalid argument to --with-udev])]
)
AS_IF([test "$with_udev" = yes], [
    AC_DEFINE(HAVE_LIBUDEV, [], [enable libudev support])
    AX_APPEND_FLAG($LIBUDEV_CFLAGS, CFLAGS)
    AX_APPEND_FLAG($LIBUDEV_LIBS, LIBS)
])

AC_ARG_WITH(util-linux,
    AC_HELP_STRING(--with-util-linux, [enable util-linux support (libmount, libblkid) [yes]]),
    [with_util_linux=$withval],
    [with_util_linux=yes]
)
AS_CASE([$with_util_linux],
    [no], [],
    [yes], [
        PKG_CHECK_MODULES(LIBBLKID, blkid)
        PKG_CHECK_MODULES(LIBMOUNT, mount)
    ],
    [auto], [
        with_util_linux=yes
        PKG_CHECK_MODULES(LIBBLKID, blkid, [], [with_util_linux=no])
        PKG_CHECK_MODULES(LIBMOUNT, mount, [], [with_util_linux=no])
    ],
    [AC_MSG_ERROR([invalid argument to --with-util-linux])]
)
AS_IF([test "$with_util_linux" = yes], [
    AC_DEFINE(HAVE_UTIL_LINUX, [], [enable util-linux support])
    AX_APPEND_FLAG($LIBBLKID_CFLAGS $LIBMOUNT_CFLAGS, CFLAGS)
    AX_APPEND_FLAG($LIBBLKID_LIBS $LIBMOUNT_LIBS, LIBS)
])

PKG_CHECK_VAR(SYSTEMDSYSTEMUNITDIR, systemd, systemdsystemunitdir)

AC_ARG_VAR([MACHINE_ID_PATHS],
    [manually specify machine-id location (colon separated list, values must not contain backslashes or quotes) [/etc/machine-id:/var/lib/dbus/machine-id]]
)
machine_id_paths_c=`
    printf '%s\n' "${MACHINE_ID_PATHS-/etc/machine-id:/var/lib/dbus/machine-id}" |
    sed -e '
        s/^/{"/
        s/:/", "/g
        s/$/"}/
    '
`
AC_DEFINE_UNQUOTED(THE_MACHINE_ID_PATHS, $machine_id_paths_c, [machine id location])

AC_ARG_VAR([DEFAULT_RANDOM_SEED_PATH], [default seed path if no command line argument [/var/lib/random-seed]])
AS_IF([test -z "$DEFAULT_RANDOM_SEED_PATH"], [
    DEFAULT_RANDOM_SEED_PATH=/var/lib/random-seed
])
AC_DEFINE_UNQUOTED(DEFAULT_SEED_PATH, "$DEFAULT_RANDOM_SEED_PATH", [default seed path])
# everybody has POSIX shell now.
DEFAULT_SEED_DIR=${DEFAULT_RANDOM_SEED_PATH%/*}
AC_SUBST(DEFAULT_SEED_DIR)

AX_APPEND_FLAG(-D_GNU_SOURCE, CPPFLAGS)
AX_APPEND_FLAG(-D_DEFAULT_SOURCE, CPPFLAGS)
AX_APPEND_FLAG(-D_POSIX_C_SOURCE=200809L, CPPFLAGS)
AX_APPEND_COMPILE_FLAGS(-Wall -Wextra -pedantic)
AX_CHECK_PREPROC_FLAG(-MMD, [AX_APPEND_FLAG(-MMD, CPPFLAGS)])
AX_CHECK_PREPROC_FLAG(-MP, [AX_APPEND_FLAG(-MP, CPPFLAGS)])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT

AS_IF([test "$with_udev" != yes && test "$with_util_linux" != yes], [
    AC_MSG_WARN([without udev or util-linux, functionality is severely limited and may be insecure. please read the README before continuing.])
])
