END_OF_LIST =

CLEANFILES = $(END_OF_LIST)
AM_CPPFLAGS = \
        -I.                                                                   \
        -I..                                                                  \
        $(END_OF_LIST)

lib_LTLIBRARIES =                                                             \
        libaccountsservice.la                                                 \
        $(END_OF_LIST)

libaccountsservicedir = $(includedir)/accountsservice-1.0/act
libaccountsservice_HEADERS =                                                  \
        act-user.h                                                            \
        act-user-manager.h                                                    \
        $(END_OF_LIST)

libaccountsservice_la_CFLAGS = $(LIBACCOUNTSSERVICE_CFLAGS)
libaccountsservice_la_LDFLAGS =                                               \
        -export-symbols-regex '^[^_].*'                                       \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)                  \
        -no-undefined                                                         \
        $(END_OF_LIST)

libaccountsservice_la_LIBADD =                                                \
        $(LIBACCOUNTSSERVICE_LIBS)                                            \
        $(END_OF_LIST)

libaccountsservice_la_SOURCES =                                               \
        $(libaccountsservice_HEADERS)                                         \
        act-user-private.h                                                    \
        act-user.c                                                            \
        act-user-manager.c                                                    \
        $(END_OF_LIST)

pkgconfigdir = $(libdir)/pkgconfig
dist_pkgconfig_DATA = accountsservice.pc

-include $(INTROSPECTION_MAKEFILE)

if HAVE_INTROSPECTION
girdir = $(datadir)/gir-1.0
gir_DATA = AccountsService-1.0.gir
typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = $(gir_DATA:.gir=.typelib)
INTROSPECTION_GIRS = $(gir_DATA)

AccountsService-1.0.gir:                                                      \
        $(INTROSPECTION_SCANNER)                                              \
        libaccountsservice.la                                                 \
        Makefile                                                              \
        $(END_OF_LIST)

AccountsService_1_0_gir_SCANNERFLAGS =                                        \
        --warn-all                                                            \
        --namespace=AccountsService                                           \
        --identifier-prefix Act                                               \
        $(libaccountsservice_la_CFLAGS)                                       \
        $(END_OF_LIST)

AccountsService_1_0_gir_INCLUDES = $(LIBACCOUNTSSERVICE_GIR_INCLUDES)
AccountsService_1_0_gir_LIBS = libaccountsservice.la
AccountsService_1_0_gir_FILES =                                               \
        $(filter-out %-private.h, $(libaccountsservice_la_SOURCES))
        $(END_OF_LIST)

CLEANFILES += $(gir_DATA) $(typelibs_DATA)
endif

MAINTAINERCLEANFILES = Makefile.in
