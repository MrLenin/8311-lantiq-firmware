## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign 1.7 nostdinc

if ENABLE_LINUX
LINUXDIRS = tools/optic tools/otop
endif ENABLE_LINUX

SUBDIRS = src $(LINUXDIRS)

DISTCHECK_CONFIGURE_FLAGS=@CONFIGURE_OPTIONS@

drv_optic_docdir = ${prefix}/doc/drv_optic

drv_optic_doc_DATA = \
	LICENSE \
	README \
	AUTHORS \
	ChangeLog \
	NEWS \
	TODO \
	doc/doxyconfig \
	doc/footer.html \
	doc/header.html \
	doc/logo.gif \
	doc/stylesheet.css

EXTRA_DIST = $(drv_optic_doc_DATA)

clean-local:
	rm -Rf .built .built_check .version* .prepared*  ipkg/

# Copy all the spec files. Of cource, only one is actually used.
dist-hook:
	for specfile in *.spec; do \
		if test -f $$specfile; then \
			cp -p $$specfile $(distdir); \
		fi \
	done

# Create self extracting linux distribution
distcheck-hook:
	chmod a+w $(distdir)
	echo "Checking line ends ...!!!"; \
	find $(distdir) -type f -exec file {} \; | grep -e "CRLF" -e "Non-ISO" && exit 1; \
	echo "Create installation package ..."; \
	makeself.sh --gzip --notemp $(distdir) \
		gpon_optic_drv-$(PACKAGE_VERSION).sh "$(PACKAGE_NAME)" 
      
doc:
	( cd @top_srcdir@/doc; \
	doxygen doxyconfig; )

doc_cli:
	( cd @top_srcdir@/doc; \
	python @top_srcdir@/scripts/cli_parser.py; \
	doxygen @top_srcdir@/doc/doxyconfig_cli; )

.PHONY: doc doc_cli
