END_OF_LIST =

BUILT_SOURCES = $(END_OF_LIST)
CLEANFILES = $(END_OF_LIST)

AM_CPPFLAGS = \
        -I.                                                                   \
        -I..                                                                  \
        -DG_LOG_DOMAIN=\"AccountsService\"                                    \
        $(END_OF_LIST)

lib_LTLIBRARIES =                                                             \
        libaccountsservice.la                                                 \
        $(END_OF_LIST)

act-enum-types.h: act-types.h
	$(AM_V_GEN) (cd $(srcdir) && \
	         glib-mkenums \
	          --fhead "#ifndef __ACT_ENUM_TYPES_H__\n#define __ACT_ENUM_TYPES_H__\n\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n" \
	          --fprod "/* enumerations from \"@filename@\" */\n" \
	          --vhead "GType @enum_name@_get_type (void);\n#define ACT_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n"    \
	          --ftail "G_END_DECLS\n\n#endif /* __ACT_ENUM_TYPES_H__ */" \
	          $^ ) > $@

act-enum-types.c: act-types.h act-enum-types.h
	$(AM_V_GEN) (cd $(srcdir) && \
	         glib-mkenums \
	          --fhead "#include \"act-types.h\"\n" \
	          --fhead "#include \"act-enum-types.h\"\n" \
	          --fhead "#include <glib-object.h>" \
	          --fprod "\n/* enumerations from \"@filename@\" */" \
	          --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {"    \
	          --vprod "      { @VALUENAME@, \"@VALUENAME@\", \"@valuenick@\" }," \
	          --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (\"@EnumName@\", values);\n  }\n  return etype;\n}\n" \
	         $^ ) > $@

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

BUILT_SOURCES += \
	act-user-manager-generated.c		\
	act-user-manager-generated.h		\
	act-user-generated.c			\
	act-user-generated.h			\
	$(END_OF_LIST)

CLEANFILES += $(BUILT_SOURCES)

libaccountsservicedir = $(includedir)/accountsservice-1.0/act
libaccountsservice_headers =                                                  \
        act-user-generated.h                                                  \
        act-user-manager-generated.h                                          \
        act-user-manager.h                                                    \
	act-user-utils.h                                                      \
	act-types.h                                                           \
        $(END_OF_LIST)

libaccountsservice_HEADERS =                                                  \
        act.h                                                                 \
        $(libaccountsservice_headers)                                         \
        $(END_OF_LIST)


libaccountsservice_la_CFLAGS = $(LIBACCOUNTSSERVICE_CFLAGS)
libaccountsservice_la_LDFLAGS =                                               \
        -export-symbols-regex '^[^_].*'                                       \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)                  \
        -no-undefined                                                         \
        $(END_OF_LIST)

libaccountsservice_la_LIBADD =                                                \
        $(LIBACCOUNTSSERVICE_LIBS)                                            \
        -lcrypt                                                               \
        $(END_OF_LIST)

libaccountsservice_la_sources =                                               \
        $(libaccountsservice_headers)                                         \
        act-user-manager.c                                                    \
	act-user-utils.c                                                      \
        $(END_OF_LIST)

libaccountsservice_la_SOURCES =                                               \
        $(libaccountsservice_la_sources)                                      \
        $(BUILT_SOURCES)                                                      \
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
        --c-include=act/act.h                                                 \
        $(libaccountsservice_la_CFLAGS)                                       \
        $(END_OF_LIST)

AccountsService_1_0_gir_INCLUDES = Gio-2.0
AccountsService_1_0_gir_LIBS = libaccountsservice.la
AccountsService_1_0_gir_FILES =                                               \
        $(libaccountsservice_la_SOURCES)                                      \
        $(END_OF_LIST)

CLEANFILES += $(gir_DATA) $(typelibs_DATA)
endif

MAINTAINERCLEANFILES = Makefile.in
EXTRA_DIST =

if ENABLE_VAPIGEN
-include $(VAPIGEN_MAKEFILE)

accountsservice.vapi: AccountsService-1.0.gir accountsservice.deps

VAPIGEN_VAPIS = accountsservice.vapi

accountsservice_vapi_METADATADIRS = $(srcdir)
accountsservice_vapi_FILES = AccountsService-1.0.gir

vapidir = $(VAPIGEN_VAPIDIR)
vapi_DATA = $(VAPIGEN_VAPIS) $(VAPIGEN_VAPIS:.vapi=.deps)

EXTRA_DIST += accountsservice.deps accountsservice.vapi
CLEANFILES += accountsservice.vapi

endif
