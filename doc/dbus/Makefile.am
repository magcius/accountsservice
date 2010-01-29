NULL =

SPEC_XML_FILES =			\
	AccountsService.xml		\
	org.freedesktop.Accounts.ref.xml	\
	org.freedesktop.Accounts.User.ref.xml		\
	$(NULL)

if DOCBOOK_DOCS_ENABLED

htmldocdir = $(docdir)/spec
htmldoc_DATA = AccountsService.html

AccountsService.html : $(SPEC_XML_FILES)
	$(XMLTO) $(XMLTO_FLAGS) xhtml-nochunks -m $(top_srcdir)/doc/dbus/config.xsl AccountsService.xml

endif # DOCBOOK_DOCS_ENABLED

org.freedesktop.Accounts.ref.xml : $(top_srcdir)/data/org.freedesktop.Accounts.xml spec-to-docbook.xsl
	$(XSLTPROC) $(top_srcdir)/doc/dbus/spec-to-docbook.xsl $< | tail -n +2 > $@
org.freedesktop.Accounts.User.ref.xml : $(top_srcdir)/data/org.freedesktop.Accounts.User.xml spec-to-docbook.xsl
	$(XSLTPROC) $(top_srcdir)/doc/dbus/spec-to-docbook.xsl $< | tail -n +2 > $@

EXTRA_DIST =				\
	spec-to-docbook.xsl		\
	AccountsService.xml.in		\
	config.xsl			\
	docbook.css			\
	dbus-introspect-docs.dtd	\
	$(SPEC_XML_FILES)
	$(NULL)

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in		\
	$(NULL)

clean-local:
	rm -f *~ *.ref.xml
	rm -f AccountsService.html

check-local:
	xmllint --noout --noent --valid AccountsService.xml
