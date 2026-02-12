## Process this file with automake to produce Makefile.in

if !OPTIC_LIBRARY
optic_top_SOURCES = \
	tui.c \
	optic_top.c \
	dump.c
else
optic_top_SOURCES =
endif

EXTRA_DIST = \
	tui.h \
	optic_top.h \
	dump.h

bin_PROGRAMS = optic_top

AM_CPPFLAGS = \
	-I@top_srcdir@/../src \
	-I@top_srcdir@/src/include \
	@IFXOS_INCLUDE_PATH@ \
	-I@KERNEL_INCL_PATH@

##if WITH_CURSES
#AM_CPPFLAGS += \
#	-DWITH_CURSES
##endif

AM_CFLAGS= -DLINUX -Wall -Wextra -Wno-unused-parameter

optic_top_CFLAGS=$(AM_CFLAGS)

##if WITH_CURSES
#optic_top_LDFLAGS=-lncurses
##else
optic_top_LDFLAGS=
##endif

