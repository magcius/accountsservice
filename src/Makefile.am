SUBDIRS = . libaccountsservice
INCLUDES = 			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\""$(datadir)"\" \
	-DICONDIR=\"$(localstatedir)/lib/AccountsService/icons\" \
	-DUSERDIR=\"$(localstatedir)/lib/AccountsService/users\" \
	$(DBUS_GLIB_CFLAGS) 	\
	$(GIO_CFLAGS)	 	\
	$(GLIB_CFLAGS)		\
	$(POLKIT_CFLAGS)	\
	$(WARN_CFLAGS)

BUILT_SOURCES = 			\
	accounts-generated.c			\
	accounts-generated.h			\
	accounts-user-generated.c	\
	accounts-user-generated.h

accounts-generated.c accounts-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.xml Makefile
	$(AM_VGEN)gdbus-codegen --generate-c-code accounts-generated --c-namespace Accounts --interface-prefix=org.freedesktop. $(top_srcdir)/data/org.freedesktop.Accounts.xml

accounts-user-generated.c accounts-user-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.User.xml Makefile
	$(AM_VGEN)gdbus-codegen --generate-c-code accounts-user-generated --c-namespace Accounts --interface-prefix=org.freedesktop.Accounts. $(top_srcdir)/data/org.freedesktop.Accounts.User.xml

libexec_PROGRAMS = accounts-daemon

accounts_daemon_SOURCES = 	\
	$(enums_h_sources)	\
	$(BUILT_SOURCES)	\
	types.h			\
	daemon.h		\
	daemon.c		\
	user.h			\
	user.c			\
	util.h			\
	util.c			\
	main.c

accounts_daemon_LDADD = 	\
	$(DBUS_GLIB_LIBS) 	\
	$(GIO_LIBS)		\
	$(GLIB_LIBS)		\
	$(POLKIT_LIBS)

CLEANFILES = $(BUILT_SOURCES)

install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/users"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/icons"
