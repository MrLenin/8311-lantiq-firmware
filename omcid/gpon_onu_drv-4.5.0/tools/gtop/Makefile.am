## Process this file with automake to produce Makefile.in

gtop_SOURCES = \
	../onu/onu_control_rpc.c \
	tui.c \
	gtop.c \
	gpe_counter.c \
	gtc_counter.c \
	sce_counter.c \
	dump.c \
	common.c

EXTRA_DIST = \
	pe_abort_reasons.h \
	tui.h \
	gtop.h \
	gtc_counter.h \
	gpe_counter.h \
	sce_counter.h \
	dump.h \
	common.h

bin_PROGRAMS = gtop

AM_CPPFLAGS =  \
	-I@top_srcdir@/src/include \
	-I@top_srcdir@/src \
	-I@top_srcdir@/tools/onu \
	-I@srcdir@ \
	@IFXOS_INCLUDE_PATH@

##if WITH_CURSES
#AM_CPPFLAGS += \
#	-DWITH_CURSES
##endif

AM_CFLAGS= -DLINUX -Wall -Wextra -Wno-unused-parameter

gtop_CFLAGS=$(AM_CFLAGS)
##if WITH_CURSES
#gtop_LDFLAGS=-lncurses -lpthread
##else
gtop_LDFLAGS=-lpthread
##endif

gtop_LDADD =

if INCLUDE_REMOTE_ONU
gtop_LDADD += -lgponrpc
endif
