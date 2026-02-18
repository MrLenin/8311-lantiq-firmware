/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu_loop_detection.c
   ME 65528: ONU Loop Detection — real ME handler with timers, alarms, and
   per-port state management.

   Replaces the default_me_init/shutdown/update stubs in omci_stub_mes.c.

   Stock v7.5.1 reference: ghidra/output/phase13_stock.c lines 15-620
   Decompiled functions:
     loop_detect_func_4     = me_init          @ 0x00427ebc (221B)
     loop_detect_func_3     = me_shutdown       @ 0x00427dd4 (219B)
     loop_detect_func_2     = me_tbl_copy       @ 0x00427cf4 (139B)
     loop_detect_control_and_pkt_rate_set = me_update @ 0x00428068 (633B)
     loop_detect_send_timeout_handler     @ 0x00427fac (175B)
     loop_detect_recovery_to_handler      @ 0x00427ba8 (313B)
     omci_onu_loop_detect_action          @ 0x00428318 (384B)
*/
#include "ifxos_memory_alloc.h"
#include "ifxos_lock.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "omci_mib.h"
#include "omci_timeout.h"
#include "me/omci_stub_mes.h"
#include "me/omci_onu_loop_detection.h"
#include "me/omci_api_onu_loop_detection.h"
#include "me/omci_api_pptp_ethernet_uni.h"

/** \addtogroup OMCI_ME_ONU_LOOP_DETECTION
   @{
*/

/* ---- Internal data structures ---- */

/** Per-port loop detection entry.
    Stock allocates 0x34 bytes per entry; managed as circular doubly-linked
    list with IFXOS_lock per entry for timer synchronization. */
struct ld_port {
	uint8_t  port_index;	   /**< LAN port index (0-3) */
	uint16_t uni_me_id;	   /**< PPTP ETH UNI ME ID */
	uint16_t svlan;		   /**< S-VLAN for loop detection frames */
	uint16_t cvlan;		   /**< C-VLAN for loop detection frames */
	unsigned long send_tid;	   /**< Send timer ID (0 = inactive) */
	unsigned long recovery_tid;/**< Recovery timer ID (0 = inactive) */
	uint16_t pkt_rate;	   /**< Packets per second */
	IFXOS_lock_t lock;	   /**< Per-port lock */
	struct ld_port *next;	   /**< Circular list next */
	struct ld_port *prev;	   /**< Circular list prev */
};

/** List head stored in me->internal_data.
    Stock allocates 0x38 bytes: sentinel list pointers at 0x2c/0x30,
    count at 0x34. */
struct ld_data {
	struct ld_port sentinel;   /**< Circular list sentinel (not a real entry) */
	uint32_t count;		   /**< Number of port entries */
};

/* Minimum send timer interval in ms (stock enforces 50ms floor at 0x32) */
#define LD_MIN_SEND_INTERVAL_MS   50

/* ---- List helpers ---- */

static void ld_list_init(struct ld_data *d)
{
	d->sentinel.next = &d->sentinel;
	d->sentinel.prev = &d->sentinel;
	d->count = 0;
}

static void ld_list_add(struct ld_data *d, struct ld_port *entry)
{
	entry->next = &d->sentinel;
	entry->prev = d->sentinel.prev;
	d->sentinel.prev->next = entry;
	d->sentinel.prev = entry;
	d->count++;
}

static void ld_list_remove(struct ld_data *d, struct ld_port *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	d->count--;
}

static struct ld_port *ld_find_by_port(struct ld_data *d, uint8_t port_index)
{
	struct ld_port *p;

	for (p = d->sentinel.next; p != &d->sentinel; p = p->next)
		if (p->port_index == port_index)
			return p;
	return NULL;
}

static struct ld_port *ld_find_by_uni(struct ld_data *d, uint16_t uni_me_id)
{
	struct ld_port *p;

	for (p = d->sentinel.next; p != &d->sentinel; p = p->next)
		if (p->uni_me_id == uni_me_id)
			return p;
	return NULL;
}

/** Calculate send timer interval from pkt_rate.
    Stock: 1000/pkt_rate ms, minimum 50ms, default 1000ms if rate==0. */
static uint32_t ld_send_interval(uint16_t pkt_rate)
{
	uint32_t ms;

	if (pkt_rate == 0)
		return 1000;
	ms = 1000 / pkt_rate;
	if (ms < LD_MIN_SEND_INTERVAL_MS)
		ms = LD_MIN_SEND_INTERVAL_MS;
	return ms;
}

/* ---- Timer handlers (forward declarations) ---- */

static enum omci_error ld_send_timeout(struct omci_context *context,
				       struct timeout *timeout);
static enum omci_error ld_recovery_timeout(struct omci_context *context,
					   struct timeout *timeout);

/* ---- ME Handlers ---- */

/**
   ME init — allocate internal data, init list, write initial data, call API
   create.  Stock: loop_detect_func_4 @ 0x00427ebc.

   Stock only allows instance_id == 0 (singleton ME).
*/
enum omci_error
omci_onu_loop_detection_me_init(struct omci_context *context,
				struct me *me,
				void *init_data,
				uint16_t suppress_avc)
{
	enum omci_error error;
	enum omci_api_return ret;
	struct ld_data *d;
	struct omci_onu_loop_detection init_buf;
	uint16_t all_writable;

	me_dbg_msg(me, "me_init");

	/* Stock: only allows instance_id == 0 */
	if (me->instance_id != 0) {
		me_dbg_err(me, "ERROR(-12) instance_id must be 0");
		return OMCI_ERROR_INVALID_ME_ID;
	}

	d = IFXOS_MemAlloc(sizeof(*d));
	if (d == NULL) {
		me_dbg_err(me, "ERROR(-4) Memory allocation error");
		return OMCI_ERROR_MEMORY;
	}
	memset(d, 0, sizeof(*d));
	ld_list_init(d);
	me->internal_data = d;

	/* Stock copies min(data, 0x13=19) bytes covering attrs 1-5.
	   attr_mask = 0xF800 (attrs 1-5 writable). */
	if (init_data == NULL) {
		memset(&init_buf, 0, sizeof(init_buf));
		init_data = &init_buf;
	}
	all_writable = omci_attr2mask(1) | omci_attr2mask(2) |
		       omci_attr2mask(3) | omci_attr2mask(4) |
		       omci_attr2mask(5);
	error = me_data_write(context, me, init_data, 19,
			      all_writable, suppress_avc);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) me_data_write failed", error);
		return error;
	}

	/* Call API create (sets up GPE exception for ethertype 0xFFFA) */
	ret = omci_api_onu_loop_detection_create(context->api,
						 me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't create Managed Entity", ret);
		return OMCI_ERROR_DRV;
	}

	return OMCI_SUCCESS;
}

/**
   ME shutdown — cancel all timers, free all port entries, call API destroy.
   Stock: loop_detect_func_3 @ 0x00427dd4.
*/
enum omci_error
omci_onu_loop_detection_me_shutdown(struct omci_context *context,
				    struct me *me)
{
	struct ld_data *d = (struct ld_data *)me->internal_data;
	struct ld_port *p, *next;
	enum omci_error error;

	me_dbg_msg(me, "me_shutdown");

	if (d == NULL)
		return OMCI_SUCCESS;

	/* Walk list: cancel timers, delete locks, free entries.
	   Stock iterates list, checks send_tid and recovery_tid under lock. */
	for (p = d->sentinel.next; p != &d->sentinel; p = next) {
		next = p->next;

		if (p->send_tid != 0) {
			IFXOS_LockGet(&p->lock);
			error = timeout_event_remove(context, p->send_tid);
			IFXOS_LockRelease(&p->lock);
			if (error != OMCI_SUCCESS) {
				me_dbg_err(me, "ERROR(%d) send timer remove",
					   error);
				return error;
			}
		}

		if (p->recovery_tid != 0) {
			IFXOS_LockGet(&p->lock);
			error = timeout_event_remove(context, p->recovery_tid);
			IFXOS_LockRelease(&p->lock);
			if (error != OMCI_SUCCESS) {
				me_dbg_err(me, "ERROR(%d) recovery timer remove",
					   error);
				return error;
			}
		}

		IFXOS_LockDelete(&p->lock);
		ld_list_remove(d, p);
		IFXOS_MemFree(p);
	}

	IFXOS_MemFree(d);
	me->internal_data = NULL;

	/* Call API destroy (logging only in stock, no hardware cleanup) */
	if (omci_api_onu_loop_detection_destroy(context->api,
						me->instance_id)
	    != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR Can't destroy Managed Entity");
		return OMCI_ERROR_DRV;
	}

	return OMCI_SUCCESS;
}

/**
   ME table copy — serialize port entries for MIB upload.
   Stock: loop_detect_func_2 @ 0x00427cf4.
   Each entry is 7 bytes: port_index(1) + uni_me_id(2) + svlan(2) + cvlan(2).
*/
enum omci_error
omci_onu_loop_detection_me_tbl_copy(struct omci_context *context,
				    struct me *me,
				    unsigned int attr,
				    struct tbl_copy_entry *tbl_copy)
{
	struct ld_data *d = (struct ld_data *)me->internal_data;
	struct ld_port *p;
	uint8_t *buf;
	size_t total;

	me_dbg_msg(me, "me_tbl_copy attr=%u", attr);

	if (attr != omci_me_onu_loop_detection_port_vlan_table)
		return OMCI_ERROR_INVALID_VAL;

	total = d->count * 7;
	tbl_copy->data_size = total;

	if (total == 0) {
		tbl_copy->data = NULL;
		return OMCI_SUCCESS;
	}

	buf = IFXOS_MemAlloc(total);
	if (buf == NULL) {
		me_dbg_err(me, "ERROR(-4) Memory allocation error");
		return OMCI_ERROR_MEMORY;
	}

	tbl_copy->data = buf;

	for (p = d->sentinel.next; p != &d->sentinel; p = p->next) {
		buf[0] = p->port_index;
		buf[1] = (p->uni_me_id >> 8) & 0xFF;
		buf[2] = p->uni_me_id & 0xFF;
		buf[3] = (p->svlan >> 8) & 0xFF;
		buf[4] = p->svlan & 0xFF;
		buf[5] = (p->cvlan >> 8) & 0xFF;
		buf[6] = p->cvlan & 0xFF;
		buf += 7;
	}

	return OMCI_SUCCESS;
}

/**
   Parse a 7-byte port VLAN table entry from raw OMCI data.
   Layout: port_index(1) + uni_me_id(2 BE) + svlan(2 BE) + cvlan(2 BE).
*/
static void ld_parse_vlan_entry(const uint8_t *raw, uint8_t *port_index,
				uint16_t *uni_me_id, uint16_t *svlan,
				uint16_t *cvlan)
{
	*port_index = raw[0];
	*uni_me_id = (raw[1] << 8) | raw[2];
	*svlan = (raw[3] << 8) | raw[4];
	*cvlan = (raw[5] << 8) | raw[6];
}

/**
   ME update — handle port VLAN table entries, update pkt_rate, manage timers
   and call API update ioctl.
   Stock: loop_detect_control_and_pkt_rate_set @ 0x00428068 (633B).

   Three phases:
   1. If attr 6 (port_vlan_table) set: insert or update port entry
   2. Update pkt_rate on all entries (from attr 4)
   3. For each entry: call _update ioctl, manage send timers
*/
enum omci_error
omci_onu_loop_detection_me_update(struct omci_context *context,
				  struct me *me,
				  void *data,
				  uint16_t attr_mask)
{
	struct omci_onu_loop_detection *upd =
		(struct omci_onu_loop_detection *)data;
	struct ld_data *d = (struct ld_data *)me->internal_data;
	struct ld_port *p;
	enum omci_api_return ret;
	enum omci_error error;
	uint8_t port_index;
	uint16_t uni_me_id, svlan, cvlan;
	bool enable;
	bool port_shutdown;

	me_dbg_msg(me, "me_update attr_mask=0x%04x", attr_mask);

	/*
	 * Phase 1: Port VLAN table entry (attr 6, mask 0x0400)
	 */
	if (attr_mask & omci_attr2mask(
		    omci_me_onu_loop_detection_port_vlan_table)) {

		ld_parse_vlan_entry(upd->port_vlan_table,
				    &port_index, &uni_me_id, &svlan, &cvlan);

		me_dbg_msg(me, "port_vlan_tbl_entry: idx=%u uni=0x%04x "
			   "svlan=%u cvlan=%u",
			   port_index, uni_me_id, svlan, cvlan);

		/* Stock: port_index must be < 4 */
		if (port_index >= 4) {
			me_dbg_err(me, "ERROR(-7) port_index %u >= 4",
				   port_index);
			return OMCI_ERROR_INVALID_VAL;
		}

		/* Validate UNI exists (stock uses mib_me_find for ME 11) */
		{
			struct me *uni_me = NULL;
			error = mib_me_find(context,
					    OMCI_ME_PPTP_ETHERNET_UNI,
					    uni_me_id, &uni_me);
			if (error != OMCI_SUCCESS) {
				me_dbg_err(me, "ERROR(%d) Can't find UNI "
					   "me_id=0x%04x", error, uni_me_id);
				return error;
			}
		}

		/* Search for existing entry with same port_index */
		p = ld_find_by_port(d, port_index);
		if (p != NULL) {
			/* Update existing entry under lock */
			IFXOS_LockGet(&p->lock);
			p->port_index = port_index;
			p->uni_me_id = uni_me_id;
			p->svlan = svlan;
			p->cvlan = cvlan;
			IFXOS_LockRelease(&p->lock);
			me_dbg_msg(me, "table entry at idx %u overwritten",
				   port_index);
		} else {
			/* Allocate new entry */
			p = IFXOS_MemAlloc(sizeof(*p));
			if (p == NULL) {
				me_dbg_err(me, "ERROR(-4) Memory allocation "
					   "error");
				return OMCI_ERROR_MEMORY;
			}
			memset(p, 0, sizeof(*p));
			IFXOS_LockInit(&p->lock);
			p->port_index = port_index;
			p->uni_me_id = uni_me_id;
			p->svlan = svlan;
			p->cvlan = cvlan;

			ld_list_add(d, p);
			me_dbg_msg(me, "Added table entry, entries_num=%u",
				   d->count);
		}
	}

	/*
	 * Phase 2: Update pkt_rate on all entries (from attr 4 = freq)
	 */
	{
		uint16_t freq = upd->loop_detect_freq;

		me_dbg_msg(me, "pkt_rate_set: freq=%u", freq);

		for (p = d->sentinel.next; p != &d->sentinel; p = p->next) {
			IFXOS_LockGet(&p->lock);
			p->pkt_rate = freq;
			IFXOS_LockRelease(&p->lock);
		}
	}

	/*
	 * Phase 3: Control — call _update ioctl, manage send timers.
	 * Stock: enable = (loop_detect_mgmt == 2),
	 *        port_shutdown = (loop_port_down == 1)
	 */
	enable = (upd->loop_detect_mgmt == 2);
	port_shutdown = (upd->loop_port_down == 1);

	me_dbg_msg(me, "control: enable=%u", enable);

	for (p = d->sentinel.next; p != &d->sentinel; p = p->next) {
		/* Call ioctl for this port */
		ret = omci_api_onu_loop_detection_update(
			context->api, me->instance_id,
			p->uni_me_id, enable, port_shutdown);
		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't update Managed "
				   "Entity", ret);
			return OMCI_ERROR_DRV;
		}

		if (!enable || p->pkt_rate == 0) {
			/* Disable: cancel send timer */
			if (p->send_tid != 0) {
				IFXOS_LockGet(&p->lock);
				error = timeout_event_remove(context,
							     p->send_tid);
				if (error == OMCI_SUCCESS)
					p->send_tid = 0;
				IFXOS_LockRelease(&p->lock);
			}
		} else if (p->send_tid == 0) {
			/* Enable with pkt_rate>0 and no timer: start one */
			error = timeout_event_add(
				context, &p->send_tid,
				ld_send_interval(p->pkt_rate),
				ld_send_timeout,
				OMCI_ME_ONU_LOOP_DETECTION,
				me->instance_id,
				(unsigned long)p, 0, 0);
			if (error != OMCI_SUCCESS) {
				me_dbg_err(me, "ERROR(%d) send timer add",
					   error);
				return error;
			}
		}
		/* else: enable, timer already running — pkt_rate updated
		   above, handler will use new rate on next reschedule */
	}

	return OMCI_SUCCESS;
}

/* ---- Timer handlers ---- */

/**
   Send timer — transmit loop detection frame and reschedule.
   Stock: loop_detect_send_timeout_handler @ 0x00427fac.
   timeout->arg1 = port entry pointer.
*/
static enum omci_error ld_send_timeout(struct omci_context *context,
				       struct timeout *timeout)
{
	struct ld_port *p = (struct ld_port *)timeout->arg1;
	enum omci_api_return ret;
	enum omci_error error = OMCI_SUCCESS;

	IFXOS_LockGet(&p->lock);

	ret = omci_api_onu_loop_detection_packet_send(
		context->api, timeout->instance_id,
		p->svlan, p->cvlan, p->uni_me_id);

	if (ret != OMCI_API_SUCCESS) {
		IFXOS_LockRelease(&p->lock);
		dbg_err("Loop Detection send failed, ret=%d", ret);
		return OMCI_ERROR_DRV;
	}

	/* Reschedule if send_tid is still active (not cleared by control) */
	if (p->send_tid != 0 && p->pkt_rate != 0) {
		error = timeout_event_add(
			context, &p->send_tid,
			ld_send_interval(p->pkt_rate),
			ld_send_timeout,
			OMCI_ME_ONU_LOOP_DETECTION,
			timeout->instance_id,
			(unsigned long)p, 0, 0);
	}

	IFXOS_LockRelease(&p->lock);
	return error;
}

/**
   Recovery timer — re-enable port, clear alarm, restart send if still enabled.
   Stock: loop_detect_recovery_to_handler @ 0x00427ba8.
   timeout->arg1 = port entry pointer.
*/
static enum omci_error ld_recovery_timeout(struct omci_context *context,
					   struct timeout *timeout)
{
	struct ld_port *p = (struct ld_port *)timeout->arg1;
	struct me *uni_me = NULL;
	struct me *loop_me = NULL;
	enum omci_error error;
	uint16_t detect_mgmt;

	dbg_msg("loop_detect_recovery_to_handler");

	mib_lock_read(context);
	IFXOS_LockGet(&p->lock);
	p->recovery_tid = 0;

	/* Find and re-enable the PPTP ETH UNI port.
	   Stock calls FUN_0040b6a0 (ME refresh); we directly call _enabled
	   which is the functional equivalent for port re-enablement. */
	error = mib_me_find(context, OMCI_ME_PPTP_ETHERNET_UNI,
			    p->uni_me_id, &uni_me);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't find UNI 0x%04x", error,
			p->uni_me_id);
		goto out;
	}

	me_lock(context, uni_me);
	omci_api_pptp_ethernet_uni_enabled(context->api, p->uni_me_id);
	me_unlock(context, uni_me);

	/* Find loop detection ME and clear alarm */
	error = mib_me_find(context, OMCI_ME_ONU_LOOP_DETECTION,
			    timeout->instance_id, &loop_me);
	if (error != OMCI_SUCCESS)
		goto out;

	me_lock(context, loop_me);

	/* Read attr 2 (loop_detect_mgmt) to check if detection still on */
	error = me_attr_read(context, loop_me,
			     omci_me_onu_loop_detection_loop_detect_mgmt,
			     &detect_mgmt, sizeof(detect_mgmt));
	me_unlock(context, loop_me);

	if (error != OMCI_SUCCESS)
		goto out;

	/* Clear alarm for this port */
	me_lock(context, loop_me);
	me_alarm_set(context, loop_me, p->port_index, false);
	me_unlock(context, loop_me);

	/* If detection still enabled and pkt_rate > 0, restart send timer */
	if (detect_mgmt != 0 && p->pkt_rate != 0) {
		error = timeout_event_add(
			context, &p->send_tid,
			ld_send_interval(p->pkt_rate),
			ld_send_timeout,
			OMCI_ME_ONU_LOOP_DETECTION,
			timeout->instance_id,
			(unsigned long)p, 0, 0);
	}

out:
	IFXOS_LockRelease(&p->lock);
	mib_unlock(context);
	return error;
}

/* ---- External action function ---- */

/**
   Loop detection event action — called when kernel reports loop on a port.
   Stock: omci_onu_loop_detect_action @ 0x00428318 (384B).
   Caller: event handler dispatcher @ 0x00408b5a.

   Actions:
   1. Find loop detection ME
   2. Find port entry by uni_me_id
   3. Check loop_port_down attr — if enabled, shut down port
   4. Set alarm for the port
   5. Cancel send timer
   6. Start recovery timer if recovery interval > 0
*/
enum omci_error
omci_onu_loop_detect_action(struct omci_context *context,
			    uint16_t instance_id,
			    uint16_t uni_me_id)
{
	struct me *loop_me = NULL;
	struct ld_data *d;
	struct ld_port *p;
	enum omci_error error;
	uint16_t port_down;
	uint16_t recovery_int;

	dbg_msg("omci_onu_loop_detect_action: inst=%u uni=0x%04x",
		instance_id, uni_me_id);

	if (context == NULL) {
		dbg_err("ERROR(-3) context is NULL");
		return OMCI_ERROR_INVALID_VAL;
	}

	mib_lock_read(context);

	error = mib_me_find(context, OMCI_ME_ONU_LOOP_DETECTION,
			    instance_id, &loop_me);
	if (error != OMCI_SUCCESS) {
		mib_unlock(context);
		/* Stock: ME not found → return success (not an error) */
		if (error == OMCI_ERROR_ME_NOT_FOUND)
			return OMCI_SUCCESS;
		return error;
	}

	me_lock(context, loop_me);

	d = (struct ld_data *)loop_me->internal_data;
	p = ld_find_by_uni(d, uni_me_id);
	if (p == NULL) {
		/* No port entry for this UNI — nothing to do */
		me_unlock(context, loop_me);
		mib_unlock(context);
		return OMCI_SUCCESS;
	}

	/* Read attr 3 (loop_port_down): 1 = shut down port on loop */
	error = me_attr_read(context, loop_me,
			     omci_me_onu_loop_detection_loop_port_down,
			     &port_down, sizeof(port_down));
	if (error != OMCI_SUCCESS || port_down != 1) {
		me_unlock(context, loop_me);
		mib_unlock(context);
		return OMCI_SUCCESS;
	}

	/* Set alarm for this port */
	me_alarm_set(context, loop_me, p->port_index, true);

	/* Read attr 5 (loop_recovery_int) for recovery timer */
	me_attr_read(context, loop_me,
		     omci_me_onu_loop_detection_loop_recovery_int,
		     &recovery_int, sizeof(recovery_int));

	IFXOS_LockGet(&p->lock);

	/* Cancel send timer */
	if (p->send_tid != 0) {
		timeout_event_remove(context, p->send_tid);
		p->send_tid = 0;
	}

	/* Disable port */
	omci_api_pptp_ethernet_uni_disabled(context->api, p->uni_me_id);

	/* Start recovery timer if recovery interval > 0 */
	if (recovery_int != 0) {
		if (p->recovery_tid != 0) {
			timeout_event_remove(context, p->recovery_tid);
			p->recovery_tid = 0;
		}
		timeout_event_add(context, &p->recovery_tid,
				  (uint32_t)recovery_int * 1000,
				  ld_recovery_timeout,
				  OMCI_ME_ONU_LOOP_DETECTION,
				  instance_id,
				  (unsigned long)p, 0, 0);
	}

	IFXOS_LockRelease(&p->lock);
	me_unlock(context, loop_me);
	mib_unlock(context);

	return OMCI_SUCCESS;
}

/** @} */
