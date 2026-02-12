## Process this file with automake to produce Makefile.in

if OPTIC_LIBRARY
optic_apps =
else !OPTIC_LIBRARY
optic_SOURCES = 

optic_apps = optic
endif !OPTIC_LIBRARY
bin_PROGRAMS = $(optic_apps)

liboptic_control_a = liboptic_control.a

liboptic_control_a_SOURCES = \
	optic_control_rpc.c \
	optic_control_rpc.h \
	optic_control_cli.c \
	optic_control.c \
	optic_control.h

lib_LIBRARIES = $(liboptic_control_a)

AM_CFLAGS = -Wall -Wextra
if !OPTIC_LIBRARY
AM_CFLAGS += -DLINUX -D_ISOC99_SOURCE
endif

AM_LDFLAGS = -L@builddir@

AM_CPPFLAGS = \
	-I@srcdir@ \
	-I@srcdir@/../include \
	-I@top_srcdir@/src/include \
	@IFXOS_INCLUDE_PATH@

optic_LDADD = -loptic_control -lm

if INCLUDE_REMOTE_ONU
optic_LDADD += -lgponrpc
endif

liboptic_control_a_CFLAGS=$(AM_CFLAGS)

optic_CFLAGS=$(AM_CFLAGS)
optic_pp_CXXFLAGS=$(AM_CFLAGS)

optic_DEPENDENCIES = liboptic_control.a
optic_LDFLAGS = $(AM_LDFLAGS)
