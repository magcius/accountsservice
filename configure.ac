AC_INIT(AccountsService, 0.3)
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
PKG_CHECK_MODULES(GIO, gio-2.0)
PKG_CHECK_MODULES(GDK_PIXBUF, gdk-pixbuf-2.0)
PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1)
PKG_CHECK_MODULES(POLKIT, polkit-gobject-1)

GNOME_COMMON_INIT
GNOME_DEBUG_CHECK
GNOME_COMPILE_WARNINGS([maximum])
GNOME_CXX_WARNINGS
GNOME_MAINTAINER_MODE_DEFINES

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
Makefile
po/Makefile.in
data/Makefile
src/Makefile
])
AC_OUTPUT
