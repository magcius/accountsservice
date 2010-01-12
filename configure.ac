AC_INIT(AccountsService, 0.2)
AM_INIT_AUTOMAKE(dist-bzip2 foreign)

GETTEXT_PACKAGE=accounts-service
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE",
                   [the gettext translation domain])

AC_PROG_CC
PKG_PROG_PKG_CONFIG
AM_GNU_GETTEXT(external)
IT_PROG_INTLTOOL([0.40.0])

PKG_CHECK_MODULES(GLIB, glib-2.0)
PKG_CHECK_MODULES(GIO, gio-2.0)
PKG_CHECK_MODULES(GDK_PIXBUF, gdk-pixbuf-2.0)
PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1)
PKG_CHECK_MODULES(POLKIT, polkit-gobject-1)

AC_CONFIG_FILES([
Makefile
po/Makefile.in
data/Makefile
src/Makefile
])
AC_OUTPUT
