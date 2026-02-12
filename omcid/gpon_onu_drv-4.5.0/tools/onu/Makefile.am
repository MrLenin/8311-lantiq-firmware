## Process this file with automake to produce Makefile.in

if ONU_LIBRARY
onu_apps =
else !ONU_LIBRARY
onu_SOURCES = 

onu_pp_SOURCES = \
	onu_control_pp.cpp

onu_apps = onu onu_pp
endif !ONU_LIBRARY
bin_PROGRAMS = $(onu_apps)

libonu_control_a = libonu_control.a

libonu_control_a_SOURCES = \
	onu_control_rpc.c \
	onu_control_cli.c \
	onu_control.c \
	onu_control.h

if ONU_SCE_TABLES_WRAPPERS
libscewrappers_a = libscewrappers.a

libscewrappers_a_SOURCES = \
	include/onu_sce_xml_wrappers.h \
	include/onu_sce_json_wrappers.h \
	include/onu_sce_wrappers_misc.h \
	onu_sce_wrappers_common.h \
	onu_sce_xml_wrappers.c \
	onu_sce_json_wrappers.c \
	onu_sce_wrappers_misc.c \
	onu_sce_wrappers_common.c
else
libscewrappers_a =
endif

lib_LIBRARIES = $(libscewrappers_a) $(libonu_control_a)

AM_CFLAGS = -Wall -Wextra
if !ONU_LIBRARY
AM_CFLAGS += -DLINUX
endif

AM_LDFLAGS = -L@builddir@

AM_CPPFLAGS = \
	-I@srcdir@ \
	-I@srcdir@/include \
	-I@top_srcdir@/src/include \
	@IFXOS_INCLUDE_PATH@

onu_LDADD = -lonu_control

if ONU_SCE_TABLES_WRAPPERS
libscewrappers_a_CFLAGS=$(AM_CFLAGS)
onu_LDADD += -lscewrappers
endif

if INCLUDE_REMOTE_ONU
onu_LDADD += -lgponrpc
endif

libonu_control_a_CFLAGS=$(AM_CFLAGS)

onu_CFLAGS=$(AM_CFLAGS)
onu_pp_CXXFLAGS=$(AM_CFLAGS)

onu_DEPENDENCIES = libonu_control.a $(libscewrappers_a)
onu_LDFLAGS = $(AM_LDFLAGS)
