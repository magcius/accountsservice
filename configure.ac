AC_INIT(AccountsService, 0.6.2)
AM_INIT_AUTOMAKE(dist-bzip2 foreign)

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

PKG_CHECK_MODULES(GLIB, glib-2.0)
PKG_CHECK_MODULES(GIO, gio-2.0 gio-unix-2.0)
PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1)
PKG_CHECK_MODULES(POLKIT, polkit-gobject-1)

GNOME_COMMON_INIT
GNOME_DEBUG_CHECK
GNOME_COMPILE_WARNINGS([maximum])
GNOME_CXX_WARNINGS
GNOME_MAINTAINER_MODE_DEFINES

nl ---------------------------------------------------------------------------
dnl - DocBook Documentation
dnl ---------------------------------------------------------------------------

AC_ARG_ENABLE(docbook-docs,
        [AC_HELP_STRING([--enable-docbook-docs],
                        [build documentation (requires xmlto)])],
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
        [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir"])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
Makefile
po/Makefile.in
data/Makefile
src/Makefile
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


