## Process this file with automake to produce Makefile.in

bin_PROGRAMS =

EXTRA_DIST = \
	include/gpon_rpc_interface.h \
	include/gpon_client_rpc_interface.h \
	gpon_client.c \
	gpon_client_rpc.c \
	gpon_server.c


AM_CPPFLAGS =  \
	-I@srcdir@ \
	-I@srcdir@/include \
	-I@top_srcdir@/src/include

AM_CFLAGS =

AM_LDFLAGS = -L@builddir@

libgponrpc_a_CFLAGS = $(AM_CFLAGS)

if ENABLE_LINUX

AM_CFLAGS += -DLINUX

endif ENABLE_LINUX

if INCLUDE_REMOTE_ONU
## if RPC_CLIENT

bin_PROGRAMS += grpc_client

grpc_client_SOURCES = \
	include/gpon_client_rpc_interface.h \
	gpon_client.c \
	gpon_client_rpc.c

grpc_client_CFLAGS = $(AM_CFLAGS)

grpc_client_LDFLAGS = $(AM_LDFLAGS)

grpc_client_LDADD = -lgponrpc -lpthread -lrt

## endif RPC_CLIENT


## if RPC_SERVER

bin_PROGRAMS += grpc_server

grpc_server_SOURCES = \
	gpon_server.c

grpc_server_CFLAGS = $(AM_CFLAGS)

grpc_server_LDFLAGS = $(AM_LDFLAGS)

grpc_server_LDADD = -lgponrpc -lpthread -lrt

## endif RPC_SERVER
endif
