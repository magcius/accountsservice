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

act-user-enum-types.h: act-user.h act-user-manager.h
	$(AM_V_GEN) (cd $(srcdir) && \
	         glib-mkenums \
	          --fhead "#ifndef __ACT_USER_ENUM_TYPES_H__\n#define __ACT_USER_ENUM_TYPES_H__\n\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n" \
	          --fprod "/* enumerations from \"@filename@\" */\n" \
	          --vhead "GType @enum_name@_get_type (void);\n#define ACT_USER_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n"    \
	          --ftail "G_END_DECLS\n\n#endif /* __ACT_USER_ENUM_TYPES_H__ */" \
	          $^ ) > $@

act-user-enum-types.c: act-user.h act-user-manager.h act-user-enum-types.h
	$(AM_V_GEN) (cd $(srcdir) && \
	         glib-mkenums \
	          --fhead "#include \"act-user.h\"\n" \
	          --fhead "#include \"act-user-manager.h\"\n" \
	          --fhead "#include \"act-user-enum-types.h\"\n" \
	          --fhead "#include <glib-object.h>" \
	          --fprod "\n/* enumerations from \"@filename@\" */" \
	          --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {"    \
	          --vprod "      { @VALUENAME@, \"@VALUENAME@\", \"@valuenick@\" }," \
	          --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (\"@EnumName@\", values);\n  }\n  return etype;\n}\n" \
	         $^ ) > $@

accounts-generated.c accounts-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.xml Makefile
	gdbus-codegen --generate-c-code accounts-generated --c-namespace Accounts --interface-prefix=org.freedesktop. $(top_srcdir)/data/org.freedesktop.Accounts.xml

accounts-user-generated.c accounts-user-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.User.xml Makefile
	gdbus-codegen --generate-c-code accounts-user-generated --c-namespace Accounts --interface-prefix=org.freedesktop.Accounts. $(top_srcdir)/data/org.freedesktop.Accounts.User.xml

ck-manager-generated.c ck-manager-generated.h: org.freedesktop.ConsoleKit.Manager.xml Makefile
	gdbus-codegen --generate-c-code ck-manager-generated --c-namespace ConsoleKit --interface-prefix=org.freedesktop.ConsoleKit org.freedesktop.ConsoleKit.Manager.xml

ck-seat-generated.c ck-seat-generated.h: org.freedesktop.ConsoleKit.Seat.xml Makefile
	gdbus-codegen --generate-c-code ck-seat-generated --c-namespace ConsoleKit --interface-prefix=org.freedesktop.ConsoleKit org.freedesktop.ConsoleKit.Seat.xml

ck-session-generated.c ck-session-generated.h: org.freedesktop.ConsoleKit.Session.xml Makefile
	gdbus-codegen --generate-c-code ck-session-generated --c-namespace ConsoleKit --interface-prefix=org.freedesktop.ConsoleKit org.freedesktop.ConsoleKit.Session.xml

BUILT_SOURCES += \
	accounts-generated.c			\
	accounts-generated.h			\
	accounts-user-generated.c	\
	accounts-user-generated.h	\
	act-user-enum-types.c	\
	act-user-enum-types.h	\
	ck-manager-generated.c		\
	ck-manager-generated.h		\
	ck-seat-generated.c			\
	ck-seat-generated.h			\
	ck-session-generated.c		\
	ck-session-generated.h

CLEANFILES += $(BUILT_SOURCES)

libaccountsservicedir = $(includedir)/accountsservice-1.0/act
libaccountsservice_headers =                                                  \
        act-user.h                                                            \
        act-user-manager.h                                                    \
        act-user-enum-types.h                                                 \
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

libaccountsservice_la_SOURCES =                                               \
        $(libaccountsservice_headers)                                         \
        act-user-private.h                                                    \
        act-user.c                                                            \
        act-user-manager.c                                                    \
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

AccountsService_1_0_gir_INCLUDES = $(LIBACCOUNTSSERVICE_GIR_INCLUDES)
AccountsService_1_0_gir_LIBS = libaccountsservice.la
AccountsService_1_0_gir_FILES =                                               \
        $(filter-out %-private.h, $(libaccountsservice_la_SOURCES))           \
        $(BUILT_SOURCES)                                                      \
        $(END_OF_LIST)

CLEANFILES += $(gir_DATA) $(typelibs_DATA)
endif

MAINTAINERCLEANFILES = Makefile.in
