/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_ubus.c

   ubus/uloop integration for OMCI network interface state monitoring.
   Matches stock v7.5.1 omcid behavior: connects to ubusd, listens for
   "network.interface" events, and triggers ME 134 (IP Host Config Data)
   attribute refresh on ifup.

   All external library dependencies (libubus, libubox) are resolved at
   runtime via dlopen/dlsym. If libraries are unavailable (e.g. early boot
   before ubusd starts, or rootfs without ubus), ubus integration is
   silently disabled.

   Stock architecture (from Ghidra decompilation):
     - omci_ubus_init: ubus_connect + ubus_register_event_handler
     - omci_ubus_start: uloop_init + uloop_fd_add + IFXOS thread
     - omci_ubus_thread: polls uloop_run_events(100ms), drains event queue
     - Event callback: parses blobmsg for "interface"/"action" fields
     - On "ifup": maps iface name to ME instance, calls state callback
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_ubus.h"
#include "omci_net.h"

#ifdef LINUX
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <arpa/inet.h>

/* ========================================================================
 * Minimal type definitions for ubus/uloop/blobmsg.
 *
 * We use dlopen so we don't need full headers. Only define what we need
 * to call the functions and parse results. Struct layouts derived from
 * stock v7.5.1 decompilation and OpenWRT BB 14.07 headers.
 * ======================================================================== */

/* blob_attr: libubox blob attribute (from blob.h) */
struct ubus_blob_attr {
	uint32_t id_len;  /* upper 1 bit: extended, next 7 bits: id, lower 24 bits: len */
	char data[];
};

/* blobmsg_policy: field descriptor for blobmsg_parse */
struct ubus_blobmsg_policy {
	const char *name;
	int type;
};

#define UBUS_BLOBMSG_TYPE_STRING 3

/* Extract blob data pointer (skip id_len header) */
static inline void *ubus_blob_data(const struct ubus_blob_attr *attr)
{
	return (void *)(attr + 1);
}

/* Extract blob total length including header */
static inline unsigned int ubus_blob_pad_len(const struct ubus_blob_attr *attr)
{
	unsigned int len = attr->id_len & 0x00FFFFFF;  /* big-endian on MIPS */
	/* Actually on MIPS BE, id_len is stored big-endian already */
	len = ntohl(attr->id_len) & 0x00FFFFFF;
	return (len + 3) & ~3;  /* 4-byte aligned */
}

/* Extract blob data length (total - header) */
static inline unsigned int ubus_blob_len(const struct ubus_blob_attr *attr)
{
	return (ntohl(attr->id_len) & 0x00FFFFFF) - sizeof(struct ubus_blob_attr);
}

/* Check if blob is extended (has blobmsg header) */
static inline int ubus_blob_is_extended(const struct ubus_blob_attr *attr)
{
	return !!(ntohl(attr->id_len) & 0x80000000);
}

/* blobmsg_hdr: name header inside extended blob attrs */
struct ubus_blobmsg_hdr {
	uint16_t namelen;
	uint8_t name[];
} __attribute__((packed));

/* Extract blobmsg string data */
static inline char *ubus_blobmsg_get_string(struct ubus_blob_attr *attr)
{
	struct ubus_blobmsg_hdr *hdr;
	char *data;
	uint16_t namelen;

	if (!attr)
		return NULL;

	data = (char *)ubus_blob_data(attr);

	if (ubus_blob_is_extended(attr)) {
		hdr = (struct ubus_blobmsg_hdr *)data;
		namelen = ntohs(hdr->namelen);
		/* blobmsg header: 2 bytes namelen + name + NUL, padded to 4 bytes */
		data += ((sizeof(struct ubus_blobmsg_hdr) + namelen + 1 + 3) & ~3);
	}

	return data;
}

/* blobmsg data length */
static inline unsigned int ubus_blobmsg_data_len(const struct ubus_blob_attr *attr)
{
	char *start, *end;
	struct ubus_blobmsg_hdr *hdr;
	uint16_t namelen;

	start = (char *)ubus_blob_data(attr);
	end = start;

	if (ubus_blob_is_extended(attr)) {
		hdr = (struct ubus_blobmsg_hdr *)start;
		namelen = ntohs(hdr->namelen);
		end += ((sizeof(struct ubus_blobmsg_hdr) + namelen + 1 + 3) & ~3);
	}

	return ubus_blob_len(attr) - (end - start);
}

/* Stock struct offsets (from decompilation):
 *   ubus_context + 0x2c = struct uloop_fd (for uloop_fd_add)
 *   ubus_event_handler: 0x40 bytes total, callback at offset 0x3c
 */
#define UBUS_CTX_FD_OFFSET      0x2c
#define UBUS_EVH_SIZE           0x40
#define UBUS_EVH_CB_OFFSET      0x3c

/* ========================================================================
 * Function pointer types for dlsym'd symbols
 * ======================================================================== */

typedef void *(*fn_ubus_connect)(const char *path);
typedef int   (*fn_ubus_register_event_handler)(void *ctx, void *ev, const char *pattern);
typedef void  (*fn_ubus_free)(void *ctx);

typedef int   (*fn_uloop_init)(void);
typedef int   (*fn_uloop_fd_add)(void *sock, unsigned int flags);
typedef int   (*fn_uloop_run_events)(int timeout);
typedef void  (*fn_uloop_done)(void);

typedef int   (*fn_blobmsg_parse)(const struct ubus_blobmsg_policy *policy, int policy_len,
                                  struct ubus_blob_attr **tb, void *data, unsigned int len);

/* ========================================================================
 * Event queue node (matches stock: 0x20 bytes)
 * ======================================================================== */

struct ubus_event_node {
	struct ubus_event_node *next;
	struct ubus_event_node *prev;
	/* payload: */
	uint32_t action;
	char iface_name[16];
	uint8_t is_ifup;
	uint8_t pad[3];
};

/* ========================================================================
 * ubus subsystem context
 * ======================================================================== */

struct omci_ubus_ctx {
	struct omci_context *omci_ctx;

	/* dlopen handles */
	void *h_ubus;
	void *h_ubox;

	/* resolved function pointers */
	fn_ubus_connect          dl_ubus_connect;
	fn_ubus_register_event_handler dl_ubus_register_event_handler;
	fn_ubus_free             dl_ubus_free;
	fn_uloop_init            dl_uloop_init;
	fn_uloop_fd_add          dl_uloop_fd_add;
	fn_uloop_run_events      dl_uloop_run_events;
	fn_uloop_done            dl_uloop_done;
	fn_blobmsg_parse         dl_blobmsg_parse;

	/* ubus state */
	void *ubus_ctx;                       /* from ubus_connect */
	uint8_t event_handler[UBUS_EVH_SIZE]; /* ubus_event_handler struct */

	/* event queue (doubly-linked circular list) */
	struct ubus_event_node queue_head;    /* sentinel node */
	IFXOS_lock_t lock;

	/* thread control */
	IFXOS_ThreadCtrl_t thread;
	volatile int running;
};

/* Single global instance (stock uses global pointer too) */
static struct omci_ubus_ctx *g_ubus = NULL;

/* ========================================================================
 * Event callback — called by libubus from uloop context
 * ======================================================================== */

static void ubus_event_cb(void *uctx, void *handler,
                           const char *type, struct ubus_blob_attr *msg)
{
	struct omci_ubus_ctx *u = g_ubus;
	struct ubus_blobmsg_policy policy[2];
	struct ubus_blob_attr *tb[2];
	struct ubus_event_node *node;
	char *iface_str, *action_str;

	if (!u || !msg)
		return;

	if (strcmp(type, "network.interface") != 0)
		return;

	/* Parse blobmsg: [0]=interface, [1]=action */
	policy[0].name = "interface";
	policy[0].type = UBUS_BLOBMSG_TYPE_STRING;
	policy[1].name = "action";
	policy[1].type = UBUS_BLOBMSG_TYPE_STRING;

	tb[0] = NULL;
	tb[1] = NULL;

	u->dl_blobmsg_parse(policy, 2, tb,
	                     (char *)msg + sizeof(struct ubus_blob_attr),
	                     ubus_blobmsg_data_len(msg));

	if (!tb[0] || !tb[1])
		return;

	iface_str = ubus_blobmsg_get_string(tb[0]);
	action_str = ubus_blobmsg_get_string(tb[1]);

	if (!iface_str || !action_str)
		return;

	/* Allocate and queue event node */
	node = (struct ubus_event_node *)IFXOS_MemAlloc(sizeof(*node));
	if (!node)
		return;

	memset(node, 0, sizeof(*node));
	node->action = 0;
	strncpy(node->iface_name, iface_str, sizeof(node->iface_name) - 1);
	node->is_ifup = (strcmp(action_str, "ifup") == 0) ? 1 : 0;

	/* Insert at tail (before sentinel) */
	IFXOS_LockGet(&u->lock);
	node->prev = u->queue_head.prev;
	node->next = &u->queue_head;
	u->queue_head.prev->next = node;
	u->queue_head.prev = node;
	IFXOS_LockRelease(&u->lock);
}

/* ========================================================================
 * Polling thread — matches stock "omciubus" thread
 * ======================================================================== */

static int ubus_thread_func(IFXOS_ThreadParams_t *params)
{
	struct omci_ubus_ctx *u = (struct omci_ubus_ctx *)params->nArg1;
	struct ubus_event_node *node;

	while (u->running && !params->bShutDown) {
		/* Poll uloop with 100ms timeout (matches stock) */
		IFXOS_LockGet(&u->lock);
		u->dl_uloop_run_events(100);
		IFXOS_LockRelease(&u->lock);

		/* Drain event queue */
		while (1) {
			IFXOS_LockGet(&u->lock);
			node = u->queue_head.next;
			if (node == &u->queue_head) {
				IFXOS_LockRelease(&u->lock);
				break;
			}
			/* Unlink from list */
			node->prev->next = node->next;
			node->next->prev = node->prev;
			IFXOS_LockRelease(&u->lock);

			/* Process ifup events */
			if (node->action == 0 && node->is_ifup) {
				omci_net_iface_state_cb(u->omci_ctx,
				                        node->iface_name,
				                        true);
			}

			IFXOS_MemFree(node);
		}

		IFXOS_MSecSleep(10);
	}

	return 0;
}

/* ========================================================================
 * Resolve all dlsym symbols. Returns 0 on success, -1 on failure.
 * ======================================================================== */

static int ubus_resolve_symbols(struct omci_ubus_ctx *u)
{
	/* Load libubox first (libubus may depend on it) */
	u->h_ubox = dlopen("libubox.so", RTLD_LAZY | RTLD_GLOBAL);
	if (!u->h_ubox) {
		dbg_wrn("ubus: dlopen(libubox.so) failed: %s", dlerror());
		return -1;
	}

	u->h_ubus = dlopen("libubus.so", RTLD_LAZY);
	if (!u->h_ubus) {
		dbg_wrn("ubus: dlopen(libubus.so) failed: %s", dlerror());
		return -1;
	}

	/* Resolve ubus functions */
	u->dl_ubus_connect = (fn_ubus_connect)
		dlsym(u->h_ubus, "ubus_connect");
	u->dl_ubus_register_event_handler = (fn_ubus_register_event_handler)
		dlsym(u->h_ubus, "ubus_register_event_handler");
	u->dl_ubus_free = (fn_ubus_free)
		dlsym(u->h_ubus, "ubus_free");

	if (!u->dl_ubus_connect || !u->dl_ubus_register_event_handler ||
	    !u->dl_ubus_free) {
		dbg_wrn("ubus: missing ubus symbols: %s", dlerror());
		return -1;
	}

	/* Resolve uloop functions */
	u->dl_uloop_init = (fn_uloop_init)
		dlsym(u->h_ubox, "uloop_init");
	u->dl_uloop_fd_add = (fn_uloop_fd_add)
		dlsym(u->h_ubox, "uloop_fd_add");
	u->dl_uloop_run_events = (fn_uloop_run_events)
		dlsym(u->h_ubox, "uloop_run_events");
	u->dl_uloop_done = (fn_uloop_done)
		dlsym(u->h_ubox, "uloop_done");

	if (!u->dl_uloop_init || !u->dl_uloop_fd_add ||
	    !u->dl_uloop_run_events || !u->dl_uloop_done) {
		dbg_wrn("ubus: missing uloop symbols: %s", dlerror());
		return -1;
	}

	/* Resolve blobmsg_parse */
	u->dl_blobmsg_parse = (fn_blobmsg_parse)
		dlsym(u->h_ubox, "blobmsg_parse");
	if (!u->dl_blobmsg_parse) {
		dbg_wrn("ubus: missing blobmsg_parse: %s", dlerror());
		return -1;
	}

	return 0;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

enum omci_error omci_ubus_init(struct omci_context *context)
{
	struct omci_ubus_ctx *u;
	int ret;

	if (!context)
		return OMCI_SUCCESS;

	u = (struct omci_ubus_ctx *)IFXOS_MemAlloc(sizeof(*u));
	if (!u) {
		dbg_wrn("ubus: alloc failed, ubus disabled");
		return OMCI_SUCCESS;
	}

	memset(u, 0, sizeof(*u));
	u->omci_ctx = context;

	/* Initialize circular queue sentinel */
	u->queue_head.next = &u->queue_head;
	u->queue_head.prev = &u->queue_head;

	/* Resolve library symbols via dlopen */
	if (ubus_resolve_symbols(u) != 0) {
		dbg_prn("ubus: libraries not available, ubus disabled");
		goto cleanup;
	}

	/* Connect to ubusd (stock: ubus_connect(NULL)) */
	u->ubus_ctx = u->dl_ubus_connect(NULL);
	if (!u->ubus_ctx) {
		dbg_wrn("ubus: failed to connect to ubus");
		goto cleanup;
	}

	/* Set up event handler struct: zero 0x40 bytes, callback at +0x3c */
	memset(u->event_handler, 0, UBUS_EVH_SIZE);
	*(void **)(u->event_handler + UBUS_EVH_CB_OFFSET) = (void *)ubus_event_cb;

	/* Register for "network.interface" events */
	ret = u->dl_ubus_register_event_handler(
		u->ubus_ctx, u->event_handler, "network.interface");
	if (ret != 0) {
		dbg_wrn("ubus: failed to register event handler (%d)", ret);
		u->dl_ubus_free(u->ubus_ctx);
		u->ubus_ctx = NULL;
		goto cleanup;
	}

	/* Initialize lock */
	IFXOS_LockInit(&u->lock);

	/* Initialize uloop and add ubus fd */
	u->dl_uloop_init();
	u->dl_uloop_fd_add((char *)u->ubus_ctx + UBUS_CTX_FD_OFFSET,
	                    9);  /* ULOOP_READ | ULOOP_BLOCKING */

	/* Set global before starting thread (event callback needs it) */
	u->running = 1;
	g_ubus = u;

	/* Spawn polling thread */
	memset(&u->thread, 0, sizeof(u->thread));
	ret = IFXOS_ThreadInit(&u->thread, "omciubus",
	                       ubus_thread_func, 0, 0,
	                       (unsigned long)u, 0);
	if (ret != IFX_SUCCESS) {
		dbg_wrn("ubus: failed to start thread");
		g_ubus = NULL;
		u->running = 0;
		u->dl_ubus_free(u->ubus_ctx);
		u->ubus_ctx = NULL;
		IFXOS_LockDelete(&u->lock);
		u->dl_uloop_done();
		goto cleanup;
	}

	dbg_prn("OMCI ubus started");
	return OMCI_SUCCESS;

cleanup:
	if (u->h_ubus)
		dlclose(u->h_ubus);
	if (u->h_ubox)
		dlclose(u->h_ubox);
	IFXOS_MemFree(u);
	return OMCI_SUCCESS;  /* non-fatal */
}

void omci_ubus_exit(struct omci_context *context)
{
	struct omci_ubus_ctx *u = g_ubus;
	struct ubus_event_node *node;

	if (!u)
		return;

	/* Stop thread */
	u->running = 0;
	IFXOS_ThreadDelete(&u->thread, 100);
	g_ubus = NULL;

	/* Drain event queue */
	while (u->queue_head.next != &u->queue_head) {
		node = u->queue_head.next;
		node->prev->next = node->next;
		node->next->prev = node->prev;
		IFXOS_MemFree(node);
	}

	/* Disconnect from ubus */
	if (u->ubus_ctx) {
		u->dl_ubus_free(u->ubus_ctx);
		u->ubus_ctx = NULL;
	}

	/* Cleanup lock and uloop */
	IFXOS_LockDelete(&u->lock);
	u->dl_uloop_done();

	/* Unload libraries */
	if (u->h_ubus)
		dlclose(u->h_ubus);
	if (u->h_ubox)
		dlclose(u->h_ubox);

	IFXOS_MemFree(u);
	dbg_prn("OMCI ubus stopped");
}

#else /* !LINUX */

enum omci_error omci_ubus_init(struct omci_context *context)
{
	return OMCI_SUCCESS;
}

void omci_ubus_exit(struct omci_context *context)
{
}

#endif /* LINUX */
