AC_INIT(random-seed, 0.1)
AC_LANG(C)
AC_CONFIG_HEADERS(config.h)
AC_PROG_CC

CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L"
CFLAGS="$CFLAGS -std=c99"

PKG_HAVE_DEFINE_WITH_MODULES(SYSTEMD, libsystemd, , , [use libsystemd to get machine id])
AS_IF([test "$with_systemd" = yes],
      [PKG_CHECK_VAR(systemdsystemunitdir, systemd, systemdsystemunitdir)])

AC_ARG_ENABLE(debug,
              AC_HELP_STRING(--enable-debug, [enable debug output [default=no]]),
              [enable_debug=$enableval],
              [enable_debug=no]
             )
AS_CASE([$enable_debug],
    [yes], [AC_DEFINE(DEBUG, [], [enable debug output])],
    [no], [],
    [AC_MSG_ERROR([invalid argument to --enable-debug])]
)

AC_OUTPUT(Makefile)
