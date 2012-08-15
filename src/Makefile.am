END_OF_LIST =

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

BUILT_SOURCES =					\
	act-user-manager-generated.c		\
	act-user-manager-generated.h		\
	act-user-generated.c			\
	act-user-generated.h			\
	$(END_OF_LIST)

act-user-manager-generated.c act-user-manager-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.xml Makefile
	$(AM_V_GEN)gdbus-codegen			\
	 --generate-c-code act-user-manager-generated	\
	--c-namespace Act				\
	--interface-prefix=org.freedesktop.		\
	$(top_srcdir)/data/org.freedesktop.Accounts.xml

act-user-generated.c act-user-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.User.xml Makefile
	$(AM_V_GEN) gdbus-codegen			\
	--generate-c-code act-user-generated		\
	--c-generate-object-manager			\
	--c-namespace Act				\
	--interface-prefix=org.freedesktop.Accounts.	\
	$(top_srcdir)/data/org.freedesktop.Accounts.User.xml

libexec_PROGRAMS = accounts-daemon

accounts_daemon_SOURCES = 	\
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
