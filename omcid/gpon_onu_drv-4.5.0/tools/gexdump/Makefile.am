## Process this file with automake to produce Makefile.in

gexdump_SOURCES = \
	gexdump.c

EXTRA_DIST = \
	gexdump.h

bin_PROGRAMS = gexdump

AM_CPPFLAGS =  \
	-I@srcdir@/../../src \
	@IFXOS_INCLUDE_PATH@

AM_CFLAGS= -DLINUX -Wall -Wextra -Wno-unused-parameter

gexdump_CFLAGS=$(AM_CFLAGS)
gexdump_LDFLAGS=
