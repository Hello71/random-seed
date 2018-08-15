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
            [default_seed_path=/var/lib/random-seed])
AC_DEFINE_UNQUOTED(DEFAULT_SEED_PATH, "$default_seed_path", [default seed path])
default_seed_path_dir=${default_seed_path%/*}
AC_SUBST(default_seed_path_dir)

EXTRA_CFLAGS=
AX_CHECK_COMPILE_FLAG(-Wall, [EXTRA_CFLAGS="-Wall${EXTRA_CFLAGS+ $EXTRA_CFLAGS}"])
AX_CHECK_COMPILE_FLAG(-Wextra, [EXTRA_CFLAGS="-Wextra${EXTRA_CFLAGS+ $EXTRA_CFLAGS}"])
AX_CHECK_COMPILE_FLAG(-pedantic, [EXTRA_CFLAGS="-pedantic${EXTRA_CFLAGS+ $EXTRA_CFLAGS}"])
AC_SUBST(EXTRA_CFLAGS)

AC_OUTPUT(Makefile)
