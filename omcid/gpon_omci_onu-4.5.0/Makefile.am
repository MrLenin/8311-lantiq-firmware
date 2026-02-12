## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign 1.9 nostdinc

SUBDIRS = src tools

DISTCHECK_CONFIGURE_FLAGS=@CONFIGURE_OPTIONS@

omci_docdir = ${prefix}/doc/${PACKAGE}

omci_doc_DATA = \
	LICENSE \
	README \
	AUTHORS \
	ChangeLog \
	NEWS \
	TODO \
	doc/doxyconfig \
	doc/doxyconfig_me \
	doc/footer.html \
	doc/header.html \
	doc/logo.gif \
	doc/stylesheet.css \
	doc/howto/add_me/omci_foo.c \
	doc/howto/add_me/omci_foo.h \
	scripts/bootscript.hush \
	scripts/omci_pipe.sh

EXTRA_DIST = $(omci_doc_DATA)

clean-local:
	rm -Rf .built .built_check .version* .prepared*  ipkg/

dist-hook:
	for specfile in *.spec; do \
		if test -f $$specfile; then \
			cp -p $$specfile $(distdir); \
		fi \
	done

# Create self extracting linux distribution
distcheck-hook:
	chmod a+w $(distdir)
	echo "Checking line ends ..."; \
	find $(distdir) -type f -exec file {} \; | grep CRLF && exit -1; \
	echo "Create installation package ..."; \
	makeself.sh --gzip --notemp $(distdir) \
		gpon_omci_onu-$(PACKAGE_VERSION).sh "$(PACKAGE_NAME)"

generate-doc:
	(cd @srcdir@/doc; \
	doxygen doxyconfig; )

lint:
	@target=lint; \
	list='$(SUBDIRS)'; \
	for subdir in $$list; do \
		echo "Making $$target in $$subdir"; \
		if test "$$subdir" = "."; then \
		dot_seen=yes; \
		local_target="$$target-am"; \
		else \
		local_target="$$target"; \
		fi; \
		(cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$local_target) \
		|| eval $$failcom; \
	done;

