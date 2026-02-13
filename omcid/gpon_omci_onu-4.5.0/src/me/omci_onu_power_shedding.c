/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu_power_shedding.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_onu_power_shedding.h"
#include "me/omci_pptp_ethernet_uni.h"
#include "me/omci_pptp_pots_uni.h"
#include "me/omci_circuit_pack.h"

/** \addtogroup OMCI_ME_ONU_POWER_SHEDDING
   @{
*/

/** Data shared between multiple calls to \ref shed_walker */
struct shed_walker_data {
	/** Whether to lock admin state or not */
	bool lock;
	/** Circuit pack type for overriding */
	uint8_t circuit_pack_type;
};

static enum omci_error shed_walker(struct omci_context *context,
				   struct me *me,
				   void *shared_data)
{
	enum omci_error error;
	struct shed_walker_data *data = (struct shed_walker_data *)shared_data;
	uint8_t state = data->lock ?
		OMCI_ADMINISTRATIVE_STATE_LOCKED :
		OMCI_ADMINISTRATIVE_STATE_UNLOCKED;
	uint8_t type = data->circuit_pack_type;
	struct me *circuit_pack;
	size_t circuit_pack_num;
	uint8_t port = me->instance_id & 0xFF;
	uint32_t power_shed_override;
	unsigned int attr;

	switch (data->circuit_pack_type) {
	case OMCI_CIRCUIT_PACK_TYPE_101001000BASET:
		attr = omci_me_pptp_ethernet_uni_admin_state;
		break;

	case OMCI_CIRCUIT_PACK_POTS:
		attr = omci_me_pptp_pots_uni_admin_state;
		break;

	default:
		me_dbg_err(me, "ERROR(%d) Unsupported shedding circuit pack");
		return OMCI_ERROR;
	}

	error = mib_me_find_where(context, OMCI_ME_CIRCUIT_PACK,
				  omci_me_circuit_pack_type,
				  &type, sizeof(type),
				  &circuit_pack, sizeof(circuit_pack),
				  &circuit_pack_num);
	if (error != OMCI_SUCCESS || circuit_pack_num != 1) {
		me_dbg_err(me, "ERROR(%d) Can't find related circuit pack "
			   "for shedding override");
		return error;
	}

	error = me_attr_read(context, circuit_pack,
			     omci_me_circuit_pack_power_shed_override,
			     &power_shed_override,
			     sizeof(power_shed_override));
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't read shedding override");
		return error;
	}

	if ((1 << (31 - port + 1)) & power_shed_override) {
		me_dbg_msg(me, "Shedding overridden");
		return OMCI_SUCCESS;
	}

	me_dbg_msg(me, "Shed admin state (#%u) to %s",
		   attr,
		   data->lock ? "locked" : "unlocked");

	error = me_attr_write(context, me,
			      attr,
			      &state, sizeof(state),
			      false);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't %s admin state for shedding",
			   error, (data->lock ? "lock" : "unlock"));
		return error;
	}

	return OMCI_SUCCESS;
}

static enum omci_error data_shed_enable_timeout_handle(struct omci_context
						       *context,
						       struct timeout *timeout)
{
	uint16_t status;
	enum omci_error error;
	struct me *me;
	struct shed_walker_data shared_data;

	dbg_msg("Enable data shedding...");

	mib_lock_read(context);

	error = mib_me_find(context, OMCI_ME_ONU_POWER_SHEDDING, 0, &me);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't find Power Shedding ME", error);
		mib_unlock(context);
		return error;
	}

	me_lock(context, me);

	error = me_attr_read(context, me,
			     omci_me_onu_power_shedding_power_shed_status,
			     &status,
			     sizeof(status));
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't get shedding status", error);
		goto exit;
	}

	shared_data.lock = true;
	shared_data.circuit_pack_type = OMCI_CIRCUIT_PACK_TYPE_101001000BASET;
	error = mib_walk_by_class(context,
				  OMCI_ME_PPTP_ETHERNET_UNI,
				  shed_walker,
				  &shared_data);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't disable data shedding", error);
		goto exit;
	}

	status |= 0x8000;

	error = me_attr_write(context, me,
			      omci_me_onu_power_shedding_power_shed_status,
			      &status, sizeof(status),
			      false);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't update shedding status",
			   error);
		goto exit;
	}

	me_unlock(context, me);
	mib_unlock(context);

	return OMCI_SUCCESS;
exit:
	me_unlock(context, me);
	mib_unlock(context);

	return error;
}

#ifdef INCLUDE_OMCI_ONU_VOIP
static enum omci_error voice_shed_enable_timeout_handle(struct omci_context
							*context,
							struct timeout *timeout)
{
	uint16_t status;
	enum omci_error error;
	struct me *me;
	struct shed_walker_data shared_data;

	dbg_msg("Enable voice shedding...");

	mib_lock_read(context);

	error = mib_me_find(context, OMCI_ME_ONU_POWER_SHEDDING, 0, &me);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't find Power Shedding ME", error);
		mib_unlock(context);
		return error;
	}

	me_lock(context, me);

	error = me_attr_read(context, me,
			      omci_me_onu_power_shedding_power_shed_status,
			      &status,
			      sizeof(status));
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't get shedding status",
			   error);
		goto exit;
	}

	shared_data.lock = true;
	shared_data.circuit_pack_type = OMCI_CIRCUIT_PACK_POTS;
	error = mib_walk_by_class(context,
				  OMCI_ME_PPTP_POTS_UNI,
				  shed_walker,
				  &shared_data);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't enable voice shedding", error);
		goto exit;
	}

	status |= 0x4000;

	error = me_attr_write(context, me,
			      omci_me_onu_power_shedding_power_shed_status,
			      &status, sizeof(status),
			      false);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't update shedding status",
			   error);
		goto exit;
	}

	me_unlock(context, me);
	mib_unlock(context);

	return OMCI_SUCCESS;
exit:
	me_unlock(context, me);
	mib_unlock(context);

	return error;
}
#endif

static enum omci_error shed_disable_timeout_handle(struct omci_context *context,
						   struct timeout *timeout)
{
	uint16_t status = 0;
	enum omci_error error;
	struct me *me;
	struct shed_walker_data shared_data;

	dbg_msg("Disable shedding...");

	mib_lock_read(context);
	error = mib_me_find(context, OMCI_ME_ONU_POWER_SHEDDING, 0, &me);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't find Power Shedding ME", error);
		mib_unlock(context);
		return error;
	}

	shared_data.lock = false;
	shared_data.circuit_pack_type = OMCI_CIRCUIT_PACK_TYPE_101001000BASET;
	error = mib_walk_by_class(context,
				  OMCI_ME_PPTP_ETHERNET_UNI,
				  shed_walker,
				  &shared_data);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't disable data shedding", error);
		goto exit;
	}

#ifdef INCLUDE_OMCI_ONU_VOIP
	shared_data.lock = false;
	shared_data.circuit_pack_type = OMCI_CIRCUIT_PACK_POTS;
	error = mib_walk_by_class(context,
				  OMCI_ME_PPTP_POTS_UNI,
				  shed_walker,
				  &shared_data);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't disable voice shedding", error);
		goto exit;
	}
#endif

	me_lock(context, me);
	error = me_attr_write(context, me,
			      omci_me_onu_power_shedding_power_shed_status,
			      &status, sizeof(status),
			      false);
	me_unlock(context, me);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't update shedding status", error);
		goto exit;
	}

	mib_unlock(context);

	return OMCI_SUCCESS;
exit:
	mib_unlock(context);

	return error;
}

void ac_power_on_cb(struct omci_context *context)
{
	uint16_t restore_interval;
	enum omci_error error;
	struct me *me;

	mib_lock_read(context);

	error = mib_me_find(context, OMCI_ME_ONU_POWER_SHEDDING, 0, &me);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't find Power Shedding ME", error);
		mib_unlock(context);
		return;
	}

	me_lock(context, me);

	error = me_attr_read(context, me,
			     omci_me_onu_power_shedding_restore_power_timer_interval,
			     &restore_interval,
			     sizeof(restore_interval));
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't read restore timeout", error);
		goto exit;
	}

	error = timeout_event_add(context,
				  NULL,
				  restore_interval * 1000,
				  shed_disable_timeout_handle,
				  OMCI_ME_ONU_POWER_SHEDDING,
				  0,
				  0, 0, 0);
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me,
			   "ERROR(%d) Can't create timeout event for power off",
			   error);
		goto exit;
	}

exit:
	me_unlock(context, me);
	mib_unlock(context);
}

void ac_power_off_cb(struct omci_context *context)
{
	enum omci_error error;
	struct me *me;
	uint16_t interval;

	mib_lock_read(context);

	error = mib_me_find(context, OMCI_ME_ONU_POWER_SHEDDING, 0, &me);
	if (error != OMCI_SUCCESS) {
		dbg_wrn("WARNING Can't find Power Shedding ME");
		mib_unlock(context);
		return;
	}

	me_lock(context, me);

	error = me_attr_read(context, me,
			     omci_me_onu_power_shedding_data_power_shed_interval,
			     &interval,
			     sizeof(interval));
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't read data interval", error);
		goto exit;
	}

	if (interval) {
		error = timeout_event_add(context,
					  NULL,
					  (interval == OMCI_PM_INTERVAL_HIST ?
					   0 : interval * 1000),
					  data_shed_enable_timeout_handle,
					  OMCI_ME_ONU_POWER_SHEDDING,
					  0,
					  0, 0, 0);
		if (error != OMCI_SUCCESS) {
			me_dbg_err(me, "ERROR(%d) "
				   "Can't create timeout event for data shed",
				   error);
			goto exit;
		}
	}

#ifdef INCLUDE_OMCI_ONU_VOIP
	error = me_attr_read(context, me,
			     omci_me_onu_power_shedding_voice_power_shed_interval,
			     &interval,
			     sizeof(interval));
	if (error != OMCI_SUCCESS) {
		me_dbg_err(me, "ERROR(%d) Can't read data interval", error);
		goto exit;
	}

	if (interval) {
		error = timeout_event_add(context,
					  NULL,
					  (interval == OMCI_PM_INTERVAL_HIST ?
					   0 : interval * 1000),
					  voice_shed_enable_timeout_handle,
					  OMCI_ME_ONU_POWER_SHEDDING,
					  0,
					  0, 0, 0);
		if (error != OMCI_SUCCESS) {
			me_dbg_err(me, "ERROR(%d) "
				   "Can't create timeout event for voice shed",
				   error);
			goto exit;
		}
	}
#endif

exit:
	me_unlock(context, me);
	mib_unlock(context);
}

/** Managed Entity class */
struct me_class me_onu_power_shedding_class = {
	/* Class ID */
	OMCI_ME_ONU_POWER_SHEDDING,
	/* Attributes */
	{
		/* 1. Restore Power Timer Reset Interval */
		ATTR_UINT("Restore power timer reset",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   restore_power_timer_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 2. Data Power Shedding Interval */
		ATTR_UINT("Data shedding interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   data_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 3. Voice Power Shedding Interval */
		ATTR_UINT("Voice shedding interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   voice_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 4. Video Overlay Power Shedding Interval */
		ATTR_UINT("Video overlay shedding",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   video_overlay_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 5. Video Return Power Shedding Interval */
		ATTR_UINT("Video return shedding",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   video_return_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. DSL Power Shedding Interval */
		ATTR_UINT("DSL shedding interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   dsl_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. ATM Power Shedding Interval */
		ATTR_UINT("ATM shedding interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   atm_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. CES Power Shedding Interval */
		ATTR_UINT("CES shedding interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   ces_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9. Frame Power Shedding Interval */
		ATTR_UINT("Frame shedding interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   frame_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 10. SONET Power Shedding Interval */
		ATTR_UINT("Sonet shedding interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_power_shedding,
				   sonet_power_shed_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 11. Power Shedding Status */
		ATTR_BF("Shedding status",
			ATTR_SUPPORTED,
			0xff80,
			offsetof(struct omci_me_onu_power_shedding,
				 power_shed_status),
			2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_AVC | OMCI_ATTR_PROP_OPTIONAL,
			NULL),
		/* 12-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		NULL,
		NULL,
		/* Delete */
		NULL,
		NULL,
		/* Set */
		set_action_handle,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		NULL,
		/* Download section */
		NULL,
		/* End SW download */
		NULL,
		/* Activate software */
		NULL,
		/* Commit software */
		NULL,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		NULL,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	default_me_init,
	/* Shutdown Handler */
	default_me_shutdown,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	default_me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_onu_power_shedding),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ONU power shedding",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
