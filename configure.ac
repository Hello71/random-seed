# SPDX-License-Identifier: BSD-3-Clause

AC_INIT(random-seed, 0.1)
AC_CONFIG_MACRO_DIRS([m4])

AC_LANG(C)

AC_CONFIG_HEADERS(config.h)
AC_PROG_CC

AC_PROG_CC_C99
AS_IF([test "$ac_cv_prog_cc_c99" = no],
      [AC_MSG_ERROR([a C99 compatible compiler is required])])

CPPFLAGS="${CPPFLAGS+$CPPFLAGS }-D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L"

AC_ARG_ENABLE(debug,
    AC_HELP_STRING(--enable-debug, [enable debug output [no]]),
    [enable_debug=$enableval],
    [enable_debug=no]
)
AS_CASE([$enable_debug],
    [yes], [AC_DEFINE(DEBUG, [], [enable debug output])],
    [no], [],
    [AC_MSG_ERROR([invalid argument to --enable-debug])]
)

AC_ARG_WITH(udev,
    AC_HELP_STRING(--with-udev, [enable libudev support [auto]]),
    [with_udev=$withval],
    [with_udev=auto]
)
AS_CASE([$with_udev],
    [no], [],
    [yes], [ PKG_CHECK_MODULES(LIBUDEV, libudev, [WITH_UDEV=1]) ],
    [auto], [ PKG_CHECK_MODULES(LIBUDEV, libudev, [WITH_UDEV=1], []) ],
    [AC_MSG_ERROR([invalid argument to --with-udev])]
)
AS_IF([test "$WITH_UDEV" = 1], [
    AC_DEFINE(HAVE_LIBUDEV, [], [enable libudev support])
    CFLAGS="${CFLAGS:+$CFLAGS }$LIBUDEV_CFLAGS"
    LIBS="${LIBS:+$LIBS }$LIBUDEV_LIBS"
])

AC_ARG_WITH(util-linux,
    AC_HELP_STRING(--with-util-linux, [enable util-linux support (libmount, libblkid) [auto]]),
    [with_util_linux=$withval],
    [with_util_linux=auto]
)
AS_CASE([$with_util_linux],
    [no], [],
    [yes], [
        PKG_CHECK_MODULES(LIBBLKID, blkid)
        PKG_CHECK_MODULES(LIBMOUNT, mount)
        WITH_UTIL_LINUX=1
    ],
    [auto], [
        WITH_UTIL_LINUX=1
        PKG_CHECK_MODULES(LIBBLKID, blkid, [], [WITH_UTIL_LINUX=0])
        PKG_CHECK_MODULES(LIBMOUNT, mount, [], [WITH_UTIL_LINUX=0])
    ],
    [AC_MSG_ERROR([invalid argument to --with-udev])]
)
AS_IF([test "$WITH_UTIL_LINUX" = 1], [
    AC_DEFINE(HAVE_UTIL_LINUX, [], [enable util-linux support])
    CFLAGS="${CFLAGS:+$CFLAGS }$LIBBLKID_CFLAGS $LIBMOUNT_CFLAGS"
    LIBS="${LIBS:+$LIBS }$LIBBLKID_LIBS $LIBMOUNT_LIBS"
])

AC_ARG_WITH([machine-id-path],
            AC_HELP_STRING(--with-machine-id-path, [manually specify machine-id location [/etc/machine-id, /var/lib/dbus/machine-id]]),
            [machine_id_path=$withval]
)
AS_IF([test -n "$machine_id_path"],
      [
       AS_CASE($machine_id_path,
               [/*], [],
               [AC_MSG_ERROR([relative machine id path is invalid])]
              )
       AC_DEFINE_UNQUOTED(MACHINE_ID_PATH, "$machine_id_path", [machine id location])
      ]
)

AC_ARG_WITH([default-seed-path],
    AC_HELP_STRING(--with-default-seed-path, [default seed path if no command line argument [/var/lib/random-seed]]),
    [default_seed_path=$withval],
    [default_seed_path=/var/lib/random-seed]
)
AC_DEFINE_UNQUOTED(DEFAULT_SEED_PATH, "$default_seed_path", [default seed path])
default_seed_path_dir=${default_seed_path%/*}
AC_SUBST(default_seed_path_dir)

EXTRA_CFLAGS=
AX_CHECK_COMPILE_FLAG(-Wall, [EXTRA_CFLAGS="-Wall${EXTRA_CFLAGS+ $EXTRA_CFLAGS}"])
AX_CHECK_COMPILE_FLAG(-Wextra, [EXTRA_CFLAGS="-Wextra${EXTRA_CFLAGS+ $EXTRA_CFLAGS}"])
AX_CHECK_COMPILE_FLAG(-pedantic, [EXTRA_CFLAGS="-pedantic${EXTRA_CFLAGS+ $EXTRA_CFLAGS}"])
AC_SUBST(EXTRA_CFLAGS)

AC_OUTPUT(Makefile)
