INCLUDES = 			\
	-DLOCALSTATE_DIR=\""$(localstatedir)"\" \
	$(DBUS_GLIB_CFLAGS) 	\
	$(GIO_CFLAGS)	 	\
	$(GLIB_CFLAGS)		\
	$(GDK_PIXBUF_CFLAGS)	\
	$(POLKIT_CFLAGS)	\
	$(WARN_CFLAGS)

BUILT_SOURCES = 		\
	daemon-glue.h		\
	user-glue.h

daemon-glue.h: $(top_srcdir)/data/org.freedesktop.Accounts.xml Makefile
	dbus-binding-tool --prefix=daemon --mode=glib-server --output=daemon-glue.h $(top_srcdir)/data/org.freedesktop.Accounts.xml

user-glue.h: $(top_srcdir)/data/org.freedesktop.Accounts.User.xml Makefile
	dbus-binding-tool --prefix=user --mode=glib-server --output=user-glue.h $(top_srcdir)/data/org.freedesktop.Accounts.User.xml

libexec_PROGRAMS = accounts-daemon

accounts_daemon_SOURCES = 	\
	$(enums_h_sources)	\
	$(BUILT_SOURCES)	\
	types.h			\
	daemon.h		\
	daemon.c		\
	user.h			\
	user.c			\
	main.c

accounts_daemon_LDADD = 	\
	$(DBUS_GLIB_LIBS) 	\
	$(GIO_LIBS)		\
	$(GLIB_LIBS)		\
	$(GDK_PIXBUF_LIBS)	\
	$(POLKIT_LIBS)

CLEANFILES = $(BUILT_SOURCES)

install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/users"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/icons"
