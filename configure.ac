AC_INIT([AccountsService],[0.6.7])
AM_INIT_AUTOMAKE(dist-bzip2 no-dist-gzip foreign)

GETTEXT_PACKAGE=accounts-service
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE",
                   [the gettext translation domain])

# Support silent build rules, requires at least automake-1.11. Enable
# by either passing --enable-silent-rules to configure or passing V=0
# to make
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([no])])

AC_PROG_CC
PKG_PROG_PKG_CONFIG
AM_GLIB_GNU_GETTEXT
IT_PROG_INTLTOOL([0.40.0])
AC_USE_SYSTEM_EXTENSIONS

LT_INIT
LT_CURRENT=0
LT_REVISION=0
LT_AGE=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

PKG_CHECK_MODULES(GLIB, glib-2.0)
PKG_CHECK_MODULES(GIO, gio-2.0 gio-unix-2.0)
PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1)
PKG_CHECK_MODULES(POLKIT, polkit-gobject-1)

AM_MAINTAINER_MODE([enable])

# client library dependencies
LIBACCOUNTSSERVICE_LIBS="$GLIB_LIBS $DBUS_GLIB_LIBS"
AC_SUBST(LIBACCOUNTSSERVICE_LIBS)
LIBACCOUNTSSERVICE_CFLAGS="$GLIB_CFLAGS $DBUS_GLIB_CFLAGS"
AC_SUBST(LIBACCOUNTSSERVICE_CFLAGS)

GOBJECT_INTROSPECTION_CHECK([0.9.12])
LIBACCOUNTSSERVICE_GIR_INCLUDES="GLib-2.0 GObject-2.0 DBusGLib-1.0"
AC_SUBST(LIBACCOUNTSSERVICE_GIR_INCLUDES)


AC_ARG_ENABLE(more-warnings,
              AS_HELP_STRING([--enable-more-warnings],
                             [Maximum compiler warnings]),
              set_more_warnings="$enableval",[
              if test -d $srcdir/.git; then
                set_more_warnings=yes
              else
                set_more_warnings=no
              fi])

AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
  AC_MSG_RESULT(yes)
  MAYBE_WARN="\
   -Wall -Wextra  \
   -Wchar-subscripts -Wmissing-declarations -Wmissing-prototypes \
   -Wwrite-strings -Wnested-externs -Wpointer-arith \
   -Wswitch-enum -Wstrict-aliasing=2 -Winit-self -Wunsafe-loop-optimizations \
   -Wno-missing-field-initializers -Wno-unused-parameter \
   -Wcast-align -Wsign-compare -Wp,-D_FORTIFY_SOURCE=2"
elif test "$GCC" = "yes"; then
  AC_MSG_RESULT(no)
  MAYBE_WARN="-Wall -Wno-sign-compare -Wno-deprecated-declarations"
else
  AC_MSG_RESULT(no)
fi

# invalidate cached value if MAYBE_WARN has changed
if test "x$accountsservice_cv_warn_maybe" != "x$MAYBE_WARN"; then
  unset accountsservice_cv_warn_cflags
fi

AC_DEFUN([ACCOUNTSSERVICE_CC_TRY_FLAG], [
  AC_MSG_CHECKING([whether $CC supports $1])

  accountsservice_save_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $1"

  AC_COMPILE_IFELSE([ ], [accountsservice_cc_flag=yes], [accountsservice_cc_flag=no])
  CFLAGS="$accountsservice_save_CFLAGS"

  if test "x$accountsservice_cc_flag" = "xyes"; then
    ifelse([$2], , :, [$2])
  else
    ifelse([$3], , :, [$3])
  fi
  AC_MSG_RESULT([$accountsservice_cc_flag])
])

AC_CACHE_CHECK([for supported warning flags], accountsservice_cv_warn_cflags, [
  echo
  WARN_CFLAGS=""

  # Some warning options are not supported by all versions of
  # gcc, so test all desired options against the current
  # compiler.
  #
  # Note that there are some order dependencies
  # here. Specifically, an option that disables a warning will
  # have no net effect if a later option then enables that
  # warnings, (perhaps implicitly). So we put some grouped
  # options (-Wall and -Wextra) up front and the -Wno options
  # last.

  for W in $MAYBE_WARN; do
    ACCOUNTSSERVICE_CC_TRY_FLAG([$W], [WARN_CFLAGS="$WARN_CFLAGS $W"])
  done

  accountsservice_cv_warn_cflags=$WARN_CFLAGS
  accountsservice_cv_warn_maybe=$MAYBE_WARN

  AC_MSG_CHECKING([which warning flags were supported])
])

WARN_CFLAGS="$accountsservice_cv_warn_cflags"
AC_SUBST(WARN_CFLAGS)

dnl ---------------------------------------------------------------------------
dnl - DocBook Documentation
dnl ---------------------------------------------------------------------------

AC_ARG_ENABLE(docbook-docs,
        [AS_HELP_STRING([--enable-docbook-docs],[build documentation (requires xmlto)])],
        enable_docbook_docs=$enableval,enable_docbook_docs=no)
AC_PATH_PROG(XMLTO, xmlto, no)
AC_MSG_CHECKING([whether to build DocBook documentation])
if test x$XMLTO = xno ; then
        have_docbook=no
else
        have_docbook=yes
fi
if test x$enable_docbook_docs = xauto ; then
        if test x$have_docbook = xno ; then
                enable_docbook_docs=no
        else
                enable_docbook_docs=yes
        fi
fi
if test x$enable_docbook_docs = xyes; then
        if test x$have_docbook = xno; then
                AC_MSG_ERROR([Building DocBook docs explicitly required, but DocBook not found])
        fi
fi
AM_CONDITIONAL(DOCBOOK_DOCS_ENABLED, test x$enable_docbook_docs = xyes)
AC_MSG_RESULT(yes)
AC_ARG_VAR([XMLTO],[Define/override the 'xmlto' location.])
AC_ARG_VAR([XMLTO_FLAGS],[Define/override 'xmlto' options, like '--skip-validation'.])

dnl ---------------------------------------------------------------------------
dnl Check for xsltproc
dnl ---------------------------------------------------------------------------
AC_PATH_PROG([XSLTPROC], [xsltproc])

# systemd

AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        [],
        [with_systemdsystemunitdir=yes])
if test "x$with_systemdsystemunitdir" = "xyes"; then
    with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
fi
if test "x$with_systemdsystemunitdir" != "xno"; then
    AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != "xno" ])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
Makefile
po/Makefile.in
data/Makefile
src/Makefile
src/libaccountsservice/Makefile
src/libaccountsservice/accountsservice.pc
doc/Makefile
doc/dbus/Makefile
doc/dbus/AccountsService.xml
])
AC_OUTPUT

echo
AC_MSG_NOTICE([accountsservice was configured with the following options:])
if test "x$enable_docbook_docs" = "xyes"; then
        AC_MSG_NOTICE([** DocBook documentation build enabled])
else
        AC_MSG_NOTICE([** DocBook documentation build disabled])
fi
echo


